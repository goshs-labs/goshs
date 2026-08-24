package ws

import (
	"bytes"
	"encoding/json"
	"sync"

	"goshs.de/goshs/v2/chat"
)

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	Broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client

	// In-process subscribers (e.g. the TUI dashboard) that receive a copy
	// of every broadcast message without being WebSocket clients.
	subscribers map[chan []byte]bool

	// Subscribe / unsubscribe requests for in-process subscribers.
	subscribe   chan chan []byte
	unsubscribe chan chan []byte

	// Mutex
	mu sync.RWMutex

	// Handle chat
	chat *chat.Chat

	// CLI Enabled
	cliEnabled bool

	// Ring BUffers - capped storage survives client reconnect
	HTTPLog *RingBuffer
	DNSLog  *RingBuffer
	SMTPLog *RingBuffer
	SMBLog  *RingBuffer
	LDAPLog *RingBuffer
}

// NewHub will create a new hub
func NewHub(ch *chat.Chat, cliEnabled bool) *Hub {
	return &Hub{
		Broadcast:   make(chan []byte),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		clients:     make(map[*Client]bool),
		subscribers: make(map[chan []byte]bool),
		subscribe:   make(chan chan []byte),
		unsubscribe: make(chan chan []byte),
		chat:        ch,
		cliEnabled:  cliEnabled,
		HTTPLog:     NewRingBuffer(1000),
		DNSLog:      NewRingBuffer(1000),
		SMTPLog:     NewRingBuffer(1000),
		SMBLog:      NewRingBuffer(1000),
		LDAPLog:     NewRingBuffer(1000),
	}
}

// Run runs the hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			// Send existing history to new client
			go h.sendCatchup(client)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case sub := <-h.subscribe:
			h.mu.Lock()
			h.subscribers[sub] = true
			h.mu.Unlock()
			// Replay existing history to the new subscriber
			go h.sendCatchupRaw(sub)

		case sub := <-h.unsubscribe:
			h.mu.Lock()
			if _, ok := h.subscribers[sub]; ok {
				delete(h.subscribers, sub)
				close(sub)
			}
			h.mu.Unlock()

		case message := <-h.Broadcast:
			// Store in the appropriate ring buffer based on the type field
			h.classifyAndStore(message)
			// Fan out to all clients; collect slow/closed clients under the read lock
			var stale []*Client
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					stale = append(stale, client)
				}
			}
			// Fan out to in-process subscribers. A subscriber that cannot keep
			// up simply drops the message — it is a display consumer, so a
			// missed event must never block or disconnect the hub.
			for sub := range h.subscribers {
				select {
				case sub <- message:
				default:
				}
			}
			h.mu.RUnlock()
			// Remove stale clients under a write lock
			if len(stale) > 0 {
				h.mu.Lock()
				for _, client := range stale {
					if _, ok := h.clients[client]; ok {
						delete(h.clients, client)
						close(client.send)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// classifyAndStore peeks at the "type" field of the JSON message
// and stores it in the correct ring buffer.
func (h *Hub) classifyAndStore(msg []byte) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(msg, &peek); err != nil {
		return
	}
	switch peek.Type {
	case "http":
		h.HTTPLog.Add(msg)
	case "dns":
		h.DNSLog.Add(msg)
	case "smtp":
		h.SMTPLog.Add(msg)
	case "smb":
		h.SMBLog.Add(msg)
	case "ldap":
		h.LDAPLog.Add(msg)
	}
}

// buildCatchup serialises up to 200 entries from each ring buffer into a
// single "catchup" message, identical to what a reconnecting browser client
// receives. Returns nil if marshalling fails.
func (h *Hub) buildCatchup() []byte {
	httpEntries := h.HTTPLog.Last(200)
	dnsEntries := h.DNSLog.Last(200)
	smtpEntries := h.SMTPLog.Last(200)
	smbEntries := h.SMBLog.Last(200)
	ldapEntries := h.LDAPLog.Last(200)

	// Marshal each slice of raw JSON messages into a JSON array
	marshal := func(entries [][]byte) json.RawMessage {
		if len(entries) == 0 {
			return json.RawMessage("[]")
		}
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, e := range entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(e)
		}
		buf.WriteByte(']')
		return buf.Bytes()
	}

	payload := map[string]any{
		"type": "catchup",
		"http": marshal(httpEntries),
		"dns":  marshal(dnsEntries),
		"smtp": marshal(smtpEntries),
		"smb":  marshal(smbEntries),
		"ldap": marshal(ldapEntries),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return data
}

// sendCatchup sends the buffered history to a newly connected client.
func (h *Hub) sendCatchup(client *Client) {
	data := h.buildCatchup()
	if data == nil {
		return
	}
	select {
	case client.send <- data:
	default:
	}
}

// sendCatchupRaw sends the buffered history to a newly registered in-process
// subscriber channel.
func (h *Hub) sendCatchupRaw(sub chan []byte) {
	data := h.buildCatchup()
	if data == nil {
		return
	}
	select {
	case sub <- data:
	default:
	}
}

// Subscribe registers an in-process consumer of the broadcast stream and
// returns a channel that first receives a "catchup" message with buffered
// history and then every subsequent broadcast. Use Unsubscribe to release it.
func (h *Hub) Subscribe() chan []byte {
	sub := make(chan []byte, 256)
	h.subscribe <- sub
	return sub
}

// Unsubscribe removes a subscriber previously registered with Subscribe and
// closes its channel.
func (h *Hub) Unsubscribe(sub chan []byte) {
	h.unsubscribe <- sub
}
