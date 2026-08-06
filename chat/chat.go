// Package chat provides an in-memory, shared team chat. It is the evolution of
// the former clipboard: an append-only, newest-at-the-bottom message log that
// the web UI and the TUI both read from and mutate through the websocket hub.
package chat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Chat is the in-memory message log holding all chat messages.
type Chat struct {
	mu       sync.RWMutex
	Messages []Message
	// nextID is a monotonic counter. IDs are never reused, so a client can map
	// a DOM node to a message for the lifetime of the server — deleting a
	// message must not renumber the others.
	nextID int
	// persistPath, when non-empty, is the file the log is written to after every
	// mutation and read from on Load. Empty means the chat is in-memory only.
	persistPath string
}

// persistState is the on-disk shape of a persisted chat log. It carries the
// monotonic ID counter alongside the messages (which already include authors,
// edit flags and the per-emoji reaction authors) so IDs are not reused across a
// restart.
type persistState struct {
	NextID   int       `json:"next_id"`
	Messages []Message `json:"messages"`
}

// Message represents a single chat message.
type Message struct {
	ID      int    `json:"id"`
	Author  string `json:"author"`
	Content string `json:"content"`
	Time    string `json:"time"`
	// Edited is set once a message has been edited in place.
	Edited bool `json:"edited"`
	// Reactions maps an emoji to the list of authors (nicknames) who reacted
	// with it. Omitted from JSON when empty.
	Reactions map[string][]string `json:"reactions,omitempty"`
}

// clone returns a deep copy of the message so callers never share the mutable
// Reactions map with the stored message.
func (m Message) clone() Message {
	c := m
	if m.Reactions != nil {
		c.Reactions = make(map[string][]string, len(m.Reactions))
		for k, v := range m.Reactions {
			c.Reactions[k] = append([]string(nil), v...)
		}
	}
	return c
}

// New will return an instantiated Chat
func New() *Chat {
	return &Chat{}
}

// Load enables persistence at path and pre-stages any previously persisted log.
// The containing directory is created if needed. A missing file is not an error
// (first run); a malformed file is reported but persistence is still enabled so
// the next mutation overwrites it. From here on every mutation is written back
// to path.
func (c *Chat) Load(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.persistPath = path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating chat persistence dir: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing persisted yet
		}
		return fmt.Errorf("reading persisted chat: %w", err)
	}

	var state persistState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parsing persisted chat %q: %w", path, err)
	}
	c.Messages = state.Messages
	c.nextID = state.NextID
	// Defend against a hand-edited or older file whose counter would collide
	// with an existing ID.
	for _, m := range c.Messages {
		if m.ID >= c.nextID {
			c.nextID = m.ID + 1
		}
	}
	return nil
}

// save writes the current log to persistPath atomically (temp file + rename).
// It is a no-op when persistence is disabled. Callers must already hold c.mu.
func (c *Chat) save() {
	if c.persistPath == "" {
		return
	}
	data, err := json.MarshalIndent(persistState{NextID: c.nextID, Messages: c.Messages}, "", "    ")
	if err != nil {
		return
	}
	tmp := c.persistPath + "~"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, c.persistPath)
}

// AddEntry appends a message to the log and returns the created message so the
// caller (the ws hub) can broadcast the concrete object to every client.
func (c *Chat) AddEntry(author, content string) (Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	msg := Message{
		ID:      c.nextID,
		Author:  author,
		Content: content,
		Time:    time.Now().Format("Mon Jan _2 15:04:05 2006"),
	}
	c.nextID++
	c.Messages = append(c.Messages, msg)
	c.save()
	return msg, nil
}

// DeleteEntry removes the message with the given ID. IDs are matched directly
// (not by slice position) and the remaining messages keep their IDs.
func (c *Chat) DeleteEntry(id int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, m := range c.Messages {
		if m.ID == id {
			c.Messages = append(c.Messages[:i], c.Messages[i+1:]...)
			c.save()
			return nil
		}
	}
	return fmt.Errorf("invalid message ID: %d", id)
}

// EditEntry replaces the content of the message with the given ID and flags it
// as edited. Returns the updated message so the caller can broadcast it.
func (c *Chat) EditEntry(id int, content string) (Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.Messages {
		if c.Messages[i].ID == id {
			c.Messages[i].Content = content
			c.Messages[i].Edited = true
			c.save()
			return c.Messages[i].clone(), nil
		}
	}
	return Message{}, fmt.Errorf("invalid message ID: %d", id)
}

// React toggles an emoji reaction by author on the message with the given ID:
// the author's first reaction adds it, a second removes it. Returns the updated
// message so the caller can broadcast it.
func (c *Chat) React(id int, emoji, author string) (Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.Messages {
		if c.Messages[i].ID != id {
			continue
		}
		m := &c.Messages[i]
		if m.Reactions == nil {
			m.Reactions = map[string][]string{}
		}
		authors := m.Reactions[emoji]
		idx := -1
		for j, a := range authors {
			if a == author {
				idx = j
				break
			}
		}
		if idx >= 0 {
			authors = append(authors[:idx], authors[idx+1:]...)
			if len(authors) == 0 {
				delete(m.Reactions, emoji)
			} else {
				m.Reactions[emoji] = authors
			}
		} else {
			m.Reactions[emoji] = append(authors, author)
		}
		if len(m.Reactions) == 0 {
			m.Reactions = nil
		}
		c.save()
		return m.clone(), nil
	}
	return Message{}, fmt.Errorf("invalid message ID: %d", id)
}

// Clear will empty the chat log. The monotonic ID counter is intentionally left
// untouched so IDs are never reused within a server lifetime.
func (c *Chat) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Messages = nil
	c.save()
	return nil
}

// GetEntries returns a deep copy of the messages, oldest first.
func (c *Chat) GetEntries() ([]Message, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Message, len(c.Messages))
	for i := range c.Messages {
		out[i] = c.Messages[i].clone()
	}
	return out, nil
}

// Download returns a json encoded representation of the chat log for export.
func (c *Chat) Download() ([]byte, error) {
	c.mu.RLock()
	messages := make([]Message, len(c.Messages))
	for i := range c.Messages {
		messages[i] = c.Messages[i].clone()
	}
	c.mu.RUnlock()

	return json.MarshalIndent(messages, "", "    ")
}
