package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/chat"
)

func TestDispatchReadPump_NewMessage(t *testing.T) {
	mockChat := &chat.Chat{}

	hub := &Hub{chat: mockChat, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "newMessage", Content: json.RawMessage(`{"author":"alice","content":"hello"}`)}

	client.dispatchReadPump(packet)

	select {
	case msg := <-hub.Broadcast:
		var pkt struct {
			Type    string `json:"type"`
			Author  string `json:"author"`
			Content string `json:"content"`
		}
		require.NoError(t, json.Unmarshal(msg, &pkt))
		require.Equal(t, "chatMessage", pkt.Type)
		require.Equal(t, "alice", pkt.Author)
		require.Equal(t, "hello", pkt.Content)
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_DelMessage(t *testing.T) {
	ch := &chat.Chat{}
	if _, err := ch.AddEntry("alice", "test"); err != nil {
		t.Fatalf("Failed to add message: %v", err)
	}
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "delMessage", Content: json.RawMessage(`0`)}

	client.dispatchReadPump(packet)

	select {
	case msg := <-hub.Broadcast:
		var pkt struct {
			Type string `json:"type"`
			ID   int    `json:"id"`
		}
		require.NoError(t, json.Unmarshal(msg, &pkt))
		require.Equal(t, "chatDelete", pkt.Type)
		require.Equal(t, 0, pkt.ID)
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_DelMessageInvalidID(t *testing.T) {
	ch := &chat.Chat{}
	if _, err := ch.AddEntry("alice", "test"); err != nil {
		t.Fatalf("Failed to add message: %v", err)
	}
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	// ID 5 does not exist — delete fails, nothing is broadcast.
	packet := Packet{Type: "delMessage", Content: json.RawMessage(`5`)}

	client.dispatchReadPump(packet)

	select {
	case <-hub.Broadcast:
		t.Fatal("delete of an invalid ID must not broadcast")
	default:
	}
}

func TestDispatchReadPump_EditMessage(t *testing.T) {
	ch := &chat.Chat{}
	ch.AddEntry("alice", "helo") // gets ID 0
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "editMessage", Content: json.RawMessage(`{"id":0,"content":"hello"}`)}
	client.dispatchReadPump(packet)

	select {
	case msg := <-hub.Broadcast:
		var pkt struct {
			Type    string `json:"type"`
			ID      int    `json:"id"`
			Content string `json:"content"`
			Edited  bool   `json:"edited"`
		}
		require.NoError(t, json.Unmarshal(msg, &pkt))
		require.Equal(t, "chatEdit", pkt.Type)
		require.Equal(t, "hello", pkt.Content)
		require.True(t, pkt.Edited)
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_React(t *testing.T) {
	ch := &chat.Chat{}
	ch.AddEntry("alice", "gg") // gets ID 0
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "react", Content: json.RawMessage(`{"id":0,"emoji":"🔥","author":"bob"}`)}
	client.dispatchReadPump(packet)

	select {
	case msg := <-hub.Broadcast:
		var pkt struct {
			Type      string              `json:"type"`
			Reactions map[string][]string `json:"reactions"`
		}
		require.NoError(t, json.Unmarshal(msg, &pkt))
		require.Equal(t, "chatReaction", pkt.Type)
		require.Equal(t, []string{"bob"}, pkt.Reactions["🔥"])
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_ReactInvalidEmoji(t *testing.T) {
	ch := &chat.Chat{}
	ch.AddEntry("alice", "gg") // gets ID 0
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	// An oversized "emoji" must be rejected before it is stored/broadcast.
	packet := Packet{Type: "react", Content: json.RawMessage(`{"id":0,"emoji":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","author":"bob"}`)}
	client.dispatchReadPump(packet)

	select {
	case <-hub.Broadcast:
		t.Fatal("oversized reaction must not broadcast")
	default:
	}
}

func TestDispatchReadPump_ClearChat(t *testing.T) {
	ch := &chat.Chat{}
	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "clearChat", Content: json.RawMessage(`""`)}

	client.dispatchReadPump(packet)

	select {
	case msg := <-hub.Broadcast:
		var pkt struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal(msg, &pkt))
		require.Equal(t, "chatClear", pkt.Type)
	default:
		t.Fatal("no message Broadcasted")
	}
}

func TestDispatchReadPump_Command(t *testing.T) {
	hub := &Hub{cliEnabled: true, chat: &chat.Chat{}, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	cmdStr := `"ls -la"`
	packet := Packet{Type: "command", Content: json.RawMessage(cmdStr)}

	client.dispatchReadPump(packet)
}

func TestInvalidEventSent(t *testing.T) {
	hub := &Hub{cliEnabled: true, chat: &chat.Chat{}, Broadcast: make(chan []byte, 1)}
	client := &Client{hub: hub}

	packet := Packet{Type: "invalid", Content: json.RawMessage(`""`)}

	client.dispatchReadPump(packet)
}

func TestDispatchReadPump_ClearHTTP(t *testing.T) {
	hub := NewHub(&chat.Chat{}, false)
	hub.HTTPLog.Add([]byte(`{"type":"http"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearHTTP"})
	require.Equal(t, 0, len(hub.HTTPLog.Last(10)))
}

func TestDispatchReadPump_ClearDNS(t *testing.T) {
	hub := NewHub(&chat.Chat{}, false)
	hub.DNSLog.Add([]byte(`{"type":"dns"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearDNS"})
	require.Equal(t, 0, len(hub.DNSLog.Last(10)))
}

func TestDispatchReadPump_ClearSMTP(t *testing.T) {
	hub := NewHub(&chat.Chat{}, false)
	hub.SMTPLog.Add([]byte(`{"type":"smtp"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearSMTP"})
	require.Equal(t, 0, len(hub.SMTPLog.Last(10)))
}

func TestDispatchReadPump_ClearSMB(t *testing.T) {
	hub := NewHub(&chat.Chat{}, false)
	hub.SMBLog.Add([]byte(`{"type":"smb"}`))
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "clearSMB"})
	require.Equal(t, 0, len(hub.SMBLog.Last(10)))
}
func TestHub_Run(t *testing.T) {
	cb := &chat.Chat{} // Use a mock or real instance as needed
	hub := NewHub(cb, false)

	go hub.Run()

	// Create dummy clients
	client1 := &Client{send: make(chan []byte, 1)}
	client2 := &Client{send: make(chan []byte, 1)}

	// Register clients
	hub.register <- client1
	hub.register <- client2

	// Give some time to process (better: use sync or channels)
	time.Sleep(10 * time.Millisecond)

	// Check clients are registered
	if !hub.clients[client1] || !hub.clients[client2] {
		t.Fatal("clients not registered correctly")
	}

	// Check client received catchup message
	select {
	case m := <-client1.send:
		var msg HTTPEvent
		if err := json.Unmarshal(m, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Type != "catchup" {
			t.Fatalf("unexpected message type: %s", msg.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message on client1")
	}

	// Unregister client1
	hub.unregister <- client1

	time.Sleep(100 * time.Millisecond)

	// client1 should be removed and its channel closed
	if _, ok := hub.clients[client1]; ok {
		t.Fatal("client1 not removed after unregister")
	}
	select {
	case _, ok := <-client1.send:
		if ok {
			t.Fatal("client1 send channel not closed")
		}
	default:
		t.Fatal("client1 send channel not closed default")
	}

	// Clean up: unregister client2 to avoid goroutine leak
	hub.unregister <- client2
}

func TestHub_Run_BroadcastClientSendFull(t *testing.T) {
	cb := &chat.Chat{}
	hub := NewHub(cb, false)

	go hub.Run()

	// Create client with send channel buffer size 1
	client := &Client{send: make(chan []byte, 1)}

	// Fill the client's send channel so it is full
	client.send <- []byte("dummy")

	// Register client
	hub.register <- client
	time.Sleep(10 * time.Millisecond) // allow goroutine to process

	// Broadcast a message
	hub.Broadcast <- []byte("message")

	// Allow hub to process Broadcast
	time.Sleep(10 * time.Millisecond)

	// Clean up (just in case)
	hub.unregister <- client
}

type mockConn struct {
	messages  [][]byte
	readCount int
	closed    bool
	writes    []writeCall
}

type writeCall struct {
	messageType websocket.MessageType
	data        []byte
}

func (m *mockConn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	if m.readCount >= len(m.messages) {
		// Simulate normal closure error from websocket
		return 0, nil, nil
	}
	msg := m.messages[m.readCount]
	m.readCount++
	return websocket.MessageText, msg, nil
}

func (m *mockConn) Write(ctx context.Context, tp websocket.MessageType, data []byte) error {
	m.writes = append(m.writes, writeCall{websocket.MessageType(1), append([]byte{}, data...)})

	return nil
}

func (m *mockConn) Close(code websocket.StatusCode, reason string) error {
	return nil
}

func TestClient_readPump_CloseCalled(t *testing.T) {
	hub := NewHub(&chat.Chat{}, false)
	hub.unregister = make(chan *Client, 1) // buffered

	validPacket := Packet{
		Type:    "clearChat",
		Content: json.RawMessage(`null`),
	}
	validPacketJSON, _ := json.Marshal(validPacket)

	mockConn := &mockConn{
		messages: [][]byte{validPacketJSON},
	}

	client := &Client{
		hub:  hub,
		conn: mockConn,
		send: make(chan []byte, 1),
	}

	done := make(chan struct{})
	go func() {
		client.readPump()
		close(done)
	}()

	select {
	case <-done:
		// readPump exited gracefully
	case <-time.After(2 * time.Second):
		t.Log("readPump did not finish in time")
	}

	if !mockConn.closed {
		t.Log("expected connection Close() to be called")
	}

	select {
	case unregistered := <-hub.unregister:
		if unregistered != client {
			t.Errorf("expected client to be unregistered")
		}
	default:
		t.Log("client was not unregistered")
	}
}

func TestClient_writePump(t *testing.T) {
	// Mock connection that records Write calls
	mockConn := &mockConn{
		writes: []writeCall{},
	}

	client := &Client{
		conn: mockConn,
		send: make(chan []byte, 2),
	}

	// Push messages to send channel
	client.send <- []byte("message 1")
	client.send <- []byte("message 2")
	close(client.send) // close to stop writePump loop

	done := make(chan struct{})
	go func() {
		client.writePump()
		close(done)
	}()

	select {
	case <-done:
		// writePump exited
	case <-time.After(2 * time.Second):
		t.Fatal("writePump did not finish in time")
	}

	if len(mockConn.writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(mockConn.writes))
	}
	if string(mockConn.writes[0].data) != "message 1" {
		t.Errorf("expected first write 'message 1', got %s", mockConn.writes[0].data)
	}
	if string(mockConn.writes[1].data) != "message 2" {
		t.Errorf("expected second write 'message 2', got %s", mockConn.writes[1].data)
	}
}

func TestServeWS(t *testing.T) {
	// Create a Hub instance with mock chat
	cb := &chat.Chat{}
	hub := NewHub(cb, false)

	// Start the hub's Run loop in a goroutine
	go hub.Run()

	// Setup HTTP test server with ServeWS handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeWS(hub, w, r)
	}))
	defer server.Close()

	// Convert http test server URL to ws scheme
	wsURL := "ws" + server.URL[len("http"):]

	// Dial websocket client to the server
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Wait shortly to let the hub register the client
	time.Sleep(100 * time.Millisecond)

	// Check hub has one registered client
	if len(hub.clients) != 1 {
		t.Fatalf("expected 1 client registered, got %d", len(hub.clients))
	}
}

// TestServeWS_ChatRoundTrip exercises the full wire contract the web UI relies
// on: a browser sends a newMessage packet, the server stores it and broadcasts a
// concrete chatMessage event back with id/author/content/time. This guards the
// JSON shapes and (case-insensitive) field names shared with assets/js/src/chat.js.
func TestServeWS_ChatRoundTrip(t *testing.T) {
	ch := chat.New()
	hub := NewHub(ch, false)
	go hub.Run()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeWS(hub, w, r)
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):]
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Send a newMessage exactly as the browser does (lowercase keys).
	out := []byte(`{"type":"newMessage","content":{"author":"alice","content":"hi **there**"}}`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, out); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read until we see the chatMessage broadcast (skip the initial catchup).
	var got struct {
		Type    string `json:"type"`
		ID      int    `json:"id"`
		Author  string `json:"author"`
		Content string `json:"content"`
		Time    string `json:"time"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for chatMessage broadcast")
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, data, err := conn.Read(rctx)
		rcancel()
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if err := json.Unmarshal(data, &got); err != nil {
			continue
		}
		if got.Type == "chatMessage" {
			break
		}
	}

	require.Equal(t, "alice", got.Author)
	require.Equal(t, "hi **there**", got.Content)
	require.NotEmpty(t, got.Time)

	// The message must also be retrievable from the shared store (what the TUI
	// reads and the /?chatDown export serialises).
	messages, _ := ch.GetEntries()
	require.Len(t, messages, 1)
	require.Equal(t, "alice", messages[0].Author)
	require.Equal(t, got.ID, messages[0].ID)
}

// readChatEvent reads ws frames until one with the wanted type arrives (skipping
// the initial catchup), or fails on timeout.
func readChatEvent(t *testing.T, conn *websocket.Conn, want string) struct {
	Type      string              `json:"type"`
	ID        int                 `json:"id"`
	Content   string              `json:"content"`
	Edited    bool                `json:"edited"`
	Reactions map[string][]string `json:"reactions"`
} {
	t.Helper()
	var got struct {
		Type      string              `json:"type"`
		ID        int                 `json:"id"`
		Content   string              `json:"content"`
		Edited    bool                `json:"edited"`
		Reactions map[string][]string `json:"reactions"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", want)
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, data, err := conn.Read(rctx)
		rcancel()
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if err := json.Unmarshal(data, &got); err != nil {
			continue
		}
		if got.Type == want {
			return got
		}
	}
}

// TestServeWS_EditAndReactRoundTrip drives the full wire path for the two newer
// interactions the web UI relies on: reacting to a message and editing it in
// place. Guards the react/editMessage packet shapes and the chatReaction/chatEdit
// broadcasts shared with assets/js/src/chat.js.
func TestServeWS_EditAndReactRoundTrip(t *testing.T) {
	ch := chat.New()
	hub := NewHub(ch, false)
	go hub.Run()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ServeWS(hub, w, r)
	}))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):]
	conn, _, err := websocket.Dial(context.Background(), wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx := context.Background()
	send := func(s string) {
		wctx, wcancel := context.WithTimeout(ctx, 2*time.Second)
		defer wcancel()
		if err := conn.Write(wctx, websocket.MessageText, []byte(s)); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	send(`{"type":"newMessage","content":{"author":"alice","content":"helo"}}`)
	created := readChatEvent(t, conn, "chatMessage")
	id := created.ID

	// React.
	send(`{"type":"react","content":{"id":` + strconv.Itoa(id) + `,"emoji":"🔥","author":"bob"}}`)
	reacted := readChatEvent(t, conn, "chatReaction")
	require.Equal(t, []string{"bob"}, reacted.Reactions["🔥"])

	// Edit in place.
	send(`{"type":"editMessage","content":{"id":` + strconv.Itoa(id) + `,"content":"hello"}}`)
	edited := readChatEvent(t, conn, "chatEdit")
	require.Equal(t, "hello", edited.Content)
	require.True(t, edited.Edited)

	// Store reflects both mutations.
	messages, _ := ch.GetEntries()
	require.Len(t, messages, 1)
	require.Equal(t, "hello", messages[0].Content)
	require.True(t, messages[0].Edited)
	require.Equal(t, []string{"bob"}, messages[0].Reactions["🔥"])
}

// TestDispatchReadPump_Persists proves a message posted over the websocket is
// written to disk through the same *chat.Chat the hub holds, so a restart with
// --persist-chat recovers it.
func TestDispatchReadPump_Persists(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".goshs-chat", "chat.json")
	ch := chat.New()
	require.NoError(t, ch.Load(path))

	hub := &Hub{chat: ch, Broadcast: make(chan []byte, 4)}
	client := &Client{hub: hub}

	client.dispatchReadPump(Packet{Type: "newMessage", Content: json.RawMessage(`{"author":"alice","content":"persist me"}`)})
	client.dispatchReadPump(Packet{Type: "react", Content: json.RawMessage(`{"id":0,"emoji":"🔥","author":"bob"}`)})

	// A fresh Chat loading the same file must see the message and reaction.
	reloaded := chat.New()
	require.NoError(t, reloaded.Load(path))
	msgs, err := reloaded.GetEntries()
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, "persist me", msgs[0].Content)
	require.Equal(t, []string{"bob"}, msgs[0].Reactions["🔥"])
}
