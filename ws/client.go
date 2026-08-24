package ws

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/cli"
	"goshs.de/goshs/v2/logger"
)

// wsReadLimit caps a single inbound websocket message. It is generous enough to
// carry a chat message with a pasted image inlined as a base64 data: URL, while
// still bounding memory per frame. Pasted images larger than this should be sent
// to disk via the chat upload endpoint instead of inlined.
const wsReadLimit = 16 << 20 // 16 MiB

// Packet defines a packet struct
type Packet struct {
	Type    string `json:"type"`
	Content json.RawMessage
}

// SendPacket represents a response package from server to browser
type SendPacket struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

type Conn interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Close(code websocket.StatusCode, reason string) error
	Write(ctx context.Context, tp websocket.MessageType, data []byte) error
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	// conn *websocket.Conn
	conn Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		if err := c.conn.Close(websocket.StatusNormalClosure, ""); err != nil {
			return
		}
	}()

	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			break
		}
		var packet Packet
		if err := json.Unmarshal(data, &packet); err != nil {
			continue
		}

		// Switch over possible socket events
		c.dispatchReadPump(packet)
	}
}

func (c *Client) dispatchReadPump(packet Packet) {
	// Switch here over possible socket events and pull in handlers
	switch packet.Type {
	case "newMessage":
		var in struct {
			Author  string `json:"author"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(packet.Content, &in); err != nil {
			logger.Errorf("Error reading json packet: %+v", err)
			return
		}
		msg, err := c.hub.chat.AddEntry(in.Author, in.Content)
		if err != nil {
			logger.Errorf("Error creating chat message: %+v", err)
			return
		}
		c.broadcastChatMessage(msg)

	case "editMessage":
		var in struct {
			ID      int    `json:"id"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(packet.Content, &in); err != nil {
			logger.Errorf("Error reading json packet: %+v", err)
			return
		}
		msg, err := c.hub.chat.EditEntry(in.ID, in.Content)
		if err != nil {
			logger.Errorf("Error editing chat message with id %d: %+v", in.ID, err)
			return
		}
		c.broadcastChatFull("chatEdit", msg)

	case "react":
		var in struct {
			ID     int    `json:"id"`
			Emoji  string `json:"emoji"`
			Author string `json:"author"`
		}
		if err := json.Unmarshal(packet.Content, &in); err != nil {
			logger.Errorf("Error reading json packet: %+v", err)
			return
		}
		// Guard against oversized/empty "emoji" payloads from a hostile client;
		// the value is stored and relayed to every other client.
		if in.Emoji == "" || len(in.Emoji) > 32 {
			logger.Warnf("Ignoring reaction with invalid emoji (len %d)", len(in.Emoji))
			return
		}
		msg, err := c.hub.chat.React(in.ID, in.Emoji, in.Author)
		if err != nil {
			logger.Errorf("Error reacting to chat message with id %d: %+v", in.ID, err)
			return
		}
		c.broadcastChatFull("chatReaction", msg)

	case "delMessage":
		var id int
		if err := json.Unmarshal(packet.Content, &id); err != nil {
			logger.Errorf("Error reading json packet: %+v", err)
			return
		}
		if err := c.hub.chat.DeleteEntry(id); err != nil {
			logger.Errorf("Error deleting chat message with id %d: %+v", id, err)
			return
		}
		c.broadcastChatDelete(id)

	case "clearChat":
		if err := c.hub.chat.Clear(); err != nil {
			logger.Errorf("Error clearing chat: %+v", err)
			return
		}
		c.broadcastChatClear()

	case "command":
		if c.hub.cliEnabled {
			var command string
			if err := json.Unmarshal(packet.Content, &command); err != nil {
				logger.Errorf("Error reading json packet: %+v", err)
			}
			logger.Debugf("Command was: %+v", command)
			output, err := cli.RunCMD(command)
			if err != nil {
				logger.Errorf("Error running command: %+v", err)
			}
			logger.Debugf("Output: %+v", output)
			c.updateCLI(output)
		}
	case "clearHTTP":
		c.hub.HTTPLog.Clear()
	case "clearDNS":
		c.hub.DNSLog.Clear()
	case "clearSMTP":
		c.hub.SMTPLog.Clear()
	case "clearSMB":
		c.hub.SMBLog.Clear()
	case "clearLDAP":
		c.hub.LDAPLog.Clear()

	default:
		logger.Warnf("The event sent via websocket cannot be handeled: %+v", packet.Type)
	}

}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	for sendPacket := range c.send {
		err := c.conn.Write(context.Background(), websocket.MessageText, sendPacket)
		if err != nil {
			logger.Errorf("Failed to write to ws: %+v", err)
			break
		}
	}
}

// ServeWS will handle the socket connections
func ServeWS(hub *Hub, w http.ResponseWriter, r *http.Request) bool {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{r.Host},
	})
	if err != nil {
		logger.Errorf("Failed to upgrade ws: %+v", err)
		return false
	}
	// Raise the read limit well above the library default of 32 KiB: chat
	// messages can carry a pasted image inlined as a base64 data: URL, which
	// easily exceeds 32 KiB. Without this the Read call errors ("read limited"),
	// the readPump tears the connection down, and the message is silently lost.
	conn.SetReadLimit(wsReadLimit)

	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 1024)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()

	return true
}

// broadcastChatMessage fans a newly created chat message out to every client so
// they can append it live — no page reload.
func (c *Client) broadcastChatMessage(m chat.Message) {
	c.broadcastChatFull("chatMessage", m)
}

// broadcastChatFull marshals a full chat message (id, author, content, time,
// edited, reactions) inlined next to the given event type and broadcasts it.
// Used for chatMessage, chatEdit and chatReaction so every client re-renders
// from the authoritative message state.
func (c *Client) broadcastChatFull(typ string, m chat.Message) {
	evt := struct {
		Type string `json:"type"`
		chat.Message
	}{Type: typ, Message: m}
	data, err := json.Marshal(evt)
	if err != nil {
		logger.Errorf("Unable to marshal %s: %+v", typ, err)
		return
	}
	c.hub.Broadcast <- data
}

// broadcastChatDelete tells every client to remove the message with the given ID.
func (c *Client) broadcastChatDelete(id int) {
	evt := struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}{Type: "chatDelete", ID: id}
	data, err := json.Marshal(evt)
	if err != nil {
		logger.Errorf("Unable to marshal chatDelete: %+v", err)
		return
	}
	c.hub.Broadcast <- data
}

// broadcastChatClear tells every client to empty the chat log.
func (c *Client) broadcastChatClear() {
	data, err := json.Marshal(struct {
		Type string `json:"type"`
	}{Type: "chatClear"})
	if err != nil {
		logger.Errorf("Unable to marshal chatClear: %+v", err)
		return
	}
	c.hub.Broadcast <- data
}

func (c *Client) updateCLI(output string) {
	sendPkg := &SendPacket{
		Type:    "updateCLI",
		Content: output,
	}
	broadcastMessage, err := json.Marshal(sendPkg)
	if err != nil {
		logger.Errorf("Unable to marshal json data in redirect: %+v", err)
	}

	c.hub.Broadcast <- broadcastMessage
}
