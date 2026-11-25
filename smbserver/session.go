package smbserver

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
)

// smbSession tracks an authenticated (or anonymous) SMB2 session.
// mu protects all fields; the same session may be accessed from multiple
// goroutines when a client opens parallel TCP connections (e.g. Win10 + Win11).
type smbSession struct {
	mu sync.RWMutex

	ID         uint64
	Authed     bool
	Username   string
	Domain     string
	Challenge  *NTLMChallenge // active challenge; nil after auth completes
	SigningKey []byte         // 16-byte HMAC-SHA256 signing key; nil if not signing

	// conns holds the TCP connections that completed SESSION_SETUP for this
	// session. Only those may use it: the SessionID in a request header is
	// client-chosen, so trusting it alone let any connection reuse another
	// client's authenticated session (GHSA-grm2-rp49-4ffc / GHSA-pw36-69cp-8hjp).
	conns map[*connState]struct{}
}

// bindLocked marks sess as authenticated on cs. Caller holds sess.mu (write).
func (sess *smbSession) bindLocked(cs *connState) {
	if sess.conns == nil {
		sess.conns = make(map[*connState]struct{})
	}
	sess.conns[cs] = struct{}{}
}

// boundTo reports whether cs completed SESSION_SETUP for sess.
func (sess *smbSession) boundTo(cs *connState) bool {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	_, ok := sess.conns[cs]
	return ok
}

// authedOn reports whether sess is authenticated and was set up on cs.
func (sess *smbSession) authedOn(cs *connState) bool {
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	_, bound := sess.conns[cs]
	return sess.Authed && bound
}

// smbTree tracks a connected SMB2 tree (share).
type smbTree struct {
	ID        uint32
	ShareName string
	RootPath  string // local filesystem path
}

// smbHandle tracks an open file or directory.
type smbHandle struct {
	ID                   uint64 // used as both persistent and volatile handle ID
	Path                 string // absolute local path
	File                 *os.File
	IsDir                bool
	IsPipe               bool
	PipeName             string        // IPC$ pipe name; never a filesystem path (Path stays empty for pipes)
	PipeResp             []byte        // buffered response for next READ
	DirEntries           []os.DirEntry // cached listing for QueryDirectory
	DirIndex             int           // current position in DirEntries
	SearchPattern        string        // active pattern for QueryDirectory
	DeleteOnClose        bool
	AccessMask           uint32
	SyntheticEntriesSent bool
	Modified             bool // true if file was created/overwritten/written — triggers CHANGE_NOTIFY on close
	IsNullSink           bool // true for Alternate Data Stream handles (e.g. Zone.Identifier); writes are silently discarded
}

// pendingNotify tracks a held SMB2 CHANGE_NOTIFY request.
// Watches are stored server-wide (SMBServer.watches) so that a file operation
// on any connection can fire watches registered on any other connection.
type pendingNotify struct {
	msgID  uint64
	treeID uint32
	sessID uint64
	status uint32   // STATUS_NOTIFY_ENUM_DIR on fire, STATUS_CANCELLED on cancel
	conn   net.Conn // TCP connection that registered this watch
}

// connState holds all state for a single TCP connection.
// Sessions are NOT stored here — they live in SMBServer.sessions (server-wide)
// — but a session is only usable on the connections bound to it
// (smbSession.conns).
type connState struct {
	mu sync.Mutex

	conn net.Conn // underlying TCP connection (set once in handleConn)

	clientRequiresSigning bool // true when client NEGOTIATE has SecurityMode bit 0x02 set (e.g. Win11 24H2+)

	trees map[uint32]*smbTree

	handles      sync.Map // uint64 → *smbHandle
	nextHandleID uint64   // atomic counter

	nextTreeID uint32

	pendingSessionID uint64 // transient: session ID being assigned during NTLM Type1/Type2

	// sessIDs are the sessions this connection created or bound; they are
	// released when the connection closes so a session never outlives every
	// connection that authenticated it.
	sessIDs map[uint64]struct{}

	// downgrade ratchet: set when we send a Type 2 challenge, cleared when
	// we receive a Type 3.  If the connection closes with this still set the
	// client dropped the connection after receiving our challenge (likely
	// because we omitted ESS and NtlmMinClientSec requires it).
	challengePending      bool
	challengeClientIP     string
	challengeAttemptLevel NTLMDowngradeLevel

	// deferredNotifies holds CHANGE_NOTIFY responses that fired for THIS
	// connection's own watches. They are sent AFTER the current command
	// response so Explorer sees the correct message ordering.
	deferredNotifies []pendingNotify
}

func newConnState() *connState {
	return &connState{
		trees:        make(map[uint32]*smbTree),
		sessIDs:      make(map[uint64]struct{}),
		nextTreeID:   1,
		nextHandleID: 1,
	}
}

// trackSession records that this connection created or bound session id.
func (c *connState) trackSession(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessIDs[id] = struct{}{}
}

// ownsSession reports whether this connection created or bound session id.
func (c *connState) ownsSession(id uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.sessIDs[id]
	return ok
}

// ── Tree management ────────────────────────────────────────────────────────

func (c *connState) newTreeID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextTreeID
	c.nextTreeID++
	return id
}

func (c *connState) addTree(t *smbTree) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trees[t.ID] = t
}

func (c *connState) getTree(id uint32) *smbTree {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trees[id]
}

func (c *connState) removeTree(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.trees, id)
}

// ── Handle management ──────────────────────────────────────────────────────

func (c *connState) newHandleID() uint64 {
	return atomic.AddUint64(&c.nextHandleID, 1)
}

func (c *connState) addHandle(h *smbHandle) {
	c.handles.Store(h.ID, h)
}

func (c *connState) getHandle(id uint64) *smbHandle {
	v, ok := c.handles.Load(id)
	if !ok {
		return nil
	}
	return v.(*smbHandle)
}

func (c *connState) removeHandle(id uint64) *smbHandle {
	v, ok := c.handles.LoadAndDelete(id)
	if !ok {
		return nil
	}
	return v.(*smbHandle)
}

// closeAllHandles closes every open handle. Called on connection teardown.
func (c *connState) closeAllHandles() {
	c.handles.Range(func(key, val any) bool {
		h := val.(*smbHandle)
		if h.File != nil {
			h.File.Close()
			if h.DeleteOnClose {
				os.Remove(h.Path)
			}
		}
		c.handles.Delete(key)
		return true
	})
}

// handleFileID encodes a handle ID as the 16-byte SMB2 FileId (persistent + volatile).
// We use the same uint64 for both halves.
func handleFileID(id uint64) []byte {
	fid := make([]byte, 16)
	putle64(fid, 0, id) // persistent
	putle64(fid, 8, id) // volatile
	return fid
}

// fileIDFromBuf reads a 16-byte SMB2 FileId from buf at offset off.
// Returns the volatile handle ID (second 8 bytes).
func fileIDFromBuf(buf []byte, off int) uint64 {
	if off+16 > len(buf) {
		return 0
	}
	return le64(buf, off+8) // volatile half is authoritative for our impl
}
