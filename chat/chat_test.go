package chat

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

var (
	ch *Chat
)

func TestNew(t *testing.T) {
	ch = New()
	if len(ch.Messages) != 0 {
		t.Error("Error testing New")
	}
}

func TestAddEntry(t *testing.T) {
	msg, err := ch.AddEntry("alice", "This is a test message")
	if err != nil {
		t.Errorf("Error in testing AddEntry: %v", err)
	}
	if msg.Author != "alice" || msg.Content != "This is a test message" {
		t.Errorf("Error in testing AddEntry: returned message has wrong fields: %+v", msg)
	}
	if len(ch.Messages) != 1 {
		t.Errorf("Error in testing AddEntry: want length of 1 got length of %d", len(ch.Messages))
	}
}

func TestMonotonicIDs(t *testing.T) {
	c := New()
	m0, _ := c.AddEntry("a", "first")
	m1, _ := c.AddEntry("b", "second")
	m2, _ := c.AddEntry("c", "third")
	if m0.ID != 0 || m1.ID != 1 || m2.ID != 2 {
		t.Errorf("IDs should be monotonic 0,1,2 - got %d,%d,%d", m0.ID, m1.ID, m2.ID)
	}
	// Deleting the middle message must not renumber the others.
	if err := c.DeleteEntry(m1.ID); err != nil {
		t.Fatal(err)
	}
	res, _ := c.GetEntries()
	if len(res) != 2 || res[0].ID != 0 || res[1].ID != 2 {
		t.Errorf("Delete must keep stable IDs, want [0,2] got %+v", res)
	}
	// A new message continues the monotonic sequence (no reuse of 1).
	m3, _ := c.AddEntry("d", "fourth")
	if m3.ID != 3 {
		t.Errorf("nextID must not reuse deleted IDs, want 3 got %d", m3.ID)
	}
}

func TestDeleteEntryInvalid(t *testing.T) {
	c := New()
	if err := c.DeleteEntry(42); err == nil {
		t.Error("DeleteEntry on unknown ID should return an error")
	}
}

func TestOrderingOldestFirst(t *testing.T) {
	c := New()
	c.AddEntry("a", "one")
	c.AddEntry("b", "two")
	res, _ := c.GetEntries()
	if res[0].Content != "one" || res[1].Content != "two" {
		t.Errorf("messages should be oldest-first, got %+v", res)
	}
}

func TestEditEntry(t *testing.T) {
	c := New()
	m, _ := c.AddEntry("alice", "helo world")
	edited, err := c.EditEntry(m.ID, "hello world")
	if err != nil {
		t.Fatalf("EditEntry error: %v", err)
	}
	if edited.Content != "hello world" || !edited.Edited {
		t.Errorf("edit not applied: %+v", edited)
	}
	res, _ := c.GetEntries()
	if res[0].Content != "hello world" || !res[0].Edited {
		t.Errorf("store not updated after edit: %+v", res[0])
	}
	if _, e := c.EditEntry(999, "x"); e == nil {
		t.Error("editing an unknown ID should error")
	}
}

func TestReactToggle(t *testing.T) {
	c := New()
	m, _ := c.AddEntry("alice", "gg")

	// First reaction from bob adds it.
	r, err := c.React(m.ID, "🔥", "bob")
	if err != nil {
		t.Fatalf("React error: %v", err)
	}
	if got := r.Reactions["🔥"]; len(got) != 1 || got[0] != "bob" {
		t.Fatalf("expected [bob] on 🔥, got %+v", r.Reactions)
	}

	// A different author stacks on the same emoji.
	r, _ = c.React(m.ID, "🔥", "carol")
	if len(r.Reactions["🔥"]) != 2 {
		t.Fatalf("expected 2 authors on 🔥, got %+v", r.Reactions)
	}

	// bob reacting again toggles his reaction off.
	r, _ = c.React(m.ID, "🔥", "bob")
	if got := r.Reactions["🔥"]; len(got) != 1 || got[0] != "carol" {
		t.Fatalf("toggle should remove bob, got %+v", r.Reactions)
	}

	// carol toggling off empties the emoji, and with no reactions left the map
	// is cleared entirely.
	r, _ = c.React(m.ID, "🔥", "carol")
	if r.Reactions != nil {
		t.Fatalf("reactions should be nil when empty, got %+v", r.Reactions)
	}

	if _, err := c.React(999, "🔥", "bob"); err == nil {
		t.Error("reacting on an unknown ID should error")
	}
}

func TestReactionsDeepCopied(t *testing.T) {
	c := New()
	m, _ := c.AddEntry("alice", "hi")
	_, _ = c.React(m.ID, "👍", "bob")

	res, _ := c.GetEntries()
	// Mutating the returned copy must not affect the stored message.
	res[0].Reactions["👍"] = append(res[0].Reactions["👍"], "mallory")

	res2, _ := c.GetEntries()
	if len(res2[0].Reactions["👍"]) != 1 {
		t.Fatalf("GetEntries must deep-copy reactions, store was mutated: %+v", res2[0].Reactions)
	}
}

func TestDownload(t *testing.T) {
	var js json.RawMessage

	resJson, err := ch.Download()
	if err != nil {
		t.Errorf("Download has an error: %+v", err)
	}
	if json.Unmarshal(resJson, &js) != nil {
		t.Error("Download has an error. The returned bytes are not valid json")
	}
}

func TestClear(t *testing.T) {
	c := New()
	c.AddEntry("a", "one")
	c.AddEntry("b", "two")
	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(c.Messages) != 0 {
		t.Errorf("Error clearing chat: want 0 messages got %d", len(c.Messages))
	}
}

func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "chat.json")

	// First run: enable persistence (dir does not exist yet), then mutate.
	c := New()
	if err := c.Load(path); err != nil {
		t.Fatalf("Load on fresh path: %v", err)
	}
	m0, _ := c.AddEntry("alice", "first")
	c.AddEntry("bob", "second")
	if _, err := c.EditEntry(m0.ID, "first (edited)"); err != nil {
		t.Fatalf("EditEntry: %v", err)
	}
	if _, err := c.React(m0.ID, "🔥", "carol"); err != nil {
		t.Fatalf("React: %v", err)
	}

	// Second run: a fresh Chat loading the same file must recover everything,
	// including the edit flag, reaction authors and the monotonic counter.
	c2 := New()
	if err := c2.Load(path); err != nil {
		t.Fatalf("Load persisted: %v", err)
	}
	msgs, _ := c2.GetEntries()
	if len(msgs) != 2 {
		t.Fatalf("want 2 persisted messages, got %d", len(msgs))
	}
	if msgs[0].Content != "first (edited)" || !msgs[0].Edited {
		t.Errorf("edit not persisted: %+v", msgs[0])
	}
	if got := msgs[0].Reactions["🔥"]; len(got) != 1 || got[0] != "carol" {
		t.Errorf("reaction authors not persisted: %+v", msgs[0].Reactions)
	}

	// New messages must not reuse an existing ID after reload.
	m2, _ := c2.AddEntry("dave", "third")
	if m2.ID <= msgs[1].ID {
		t.Errorf("nextID not restored: new id %d must exceed %d", m2.ID, msgs[1].ID)
	}

	// A missing file is not an error and simply starts empty.
	c3 := New()
	if err := c3.Load(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Errorf("Load on missing file should be nil, got %v", err)
	}
}
