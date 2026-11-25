package smbserver

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-grm2-rp49-4ffc (dup GHSA-pw36-69cp-8hjp): an
// unauthenticated connection must not be able to TREE_CONNECT (or LOGOFF) with
// the SessionID of a session another connection authenticated.

func startAuthSMB(t *testing.T) *SMBServer {
	t.Helper()
	s := &SMBServer{
		IP:         "127.0.0.1",
		Port:       0,
		Root:       t.TempDir(),
		ShareName:  "goshs",
		ServerName: "GOSHS",
		Username:   "admin",
		Password:   "S3cretPass",
	}
	require.NoError(t, s.Bind())
	go s.Start()
	t.Cleanup(func() { s.ln.Close() })
	return s
}

func rawSMBRequest(t *testing.T, c net.Conn, cmd uint16, msgID, sessID uint64, body []byte) []byte {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, []byte{0xFE, 'S', 'M', 'B'})
	putle16(hdr, 4, 64)
	putle16(hdr, 12, cmd)
	putle16(hdr, 14, 31)
	binary.LittleEndian.PutUint64(hdr[24:], msgID)
	binary.LittleEndian.PutUint64(hdr[40:], sessID)
	pkt := append(hdr, body...)
	frame := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(frame, uint32(len(pkt)))
	copy(frame[4:], pkt)
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := c.Write(frame)
	require.NoError(t, err)
	lenBuf := make([]byte, 4)
	_, err = io.ReadFull(c, lenBuf)
	require.NoError(t, err)
	resp := make([]byte, binary.BigEndian.Uint32(lenBuf)&0xFFFFFF)
	_, err = io.ReadFull(c, resp)
	require.NoError(t, err)
	return resp
}

func rawNegotiate(t *testing.T, c net.Conn) {
	body := make([]byte, 36+4)
	putle16(body, 0, 36)
	putle16(body, 2, 2) // DialectCount
	putle16(body, 4, 1) // SecurityMode
	putle16(body, 36, SMB2_DIALECT_202)
	putle16(body, 38, SMB2_DIALECT_210)
	resp := rawSMBRequest(t, c, SMB2_NEGOTIATE, 0, 0, body)
	require.Equal(t, STATUS_SUCCESS, respStatus(resp))
}

func rawTreeConnect(t *testing.T, c net.Conn, msgID, sessID uint64) uint32 {
	path := toUTF16LE(`\\127.0.0.1\goshs`)
	body := make([]byte, 8+len(path))
	putle16(body, 0, 9)
	putle16(body, 4, 64+8)
	putle16(body, 6, uint16(len(path)))
	copy(body[8:], path)
	return respStatus(rawSMBRequest(t, c, SMB2_TREE_CONNECT, msgID, sessID, body))
}

// authedSessionIDs returns the IDs of all authenticated sessions.
func authedSessionIDs(s *SMBServer) []uint64 {
	var ids []uint64
	s.sessions.Range(func(k, v any) bool {
		sess := v.(*smbSession)
		sess.mu.RLock()
		if sess.Authed {
			ids = append(ids, k.(uint64))
		}
		sess.mu.RUnlock()
		return true
	})
	return ids
}

func TestSMBSessionHijack_TreeConnectFromOtherConnectionDenied(t *testing.T) {
	s := startAuthSMB(t)
	addr := s.ln.Addr().String()

	// Victim: a real NTLM login + tree connect.
	vc, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer vc.Close()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "admin", Password: "S3cretPass"}}
	vs, err := d.Dial(vc)
	require.NoError(t, err)
	share, err := vs.Mount("goshs")
	require.NoError(t, err)
	defer share.Umount()

	ids := authedSessionIDs(s)
	require.Len(t, ids, 1)
	victimID := ids[0]
	require.NotEqual(t, uint64(0x100000001), victimID, "session IDs must not be sequential")

	// Attacker: own connection, never sends SESSION_SETUP.
	ac, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer ac.Close()
	rawNegotiate(t, ac)
	require.Equal(t, STATUS_ACCESS_DENIED, rawTreeConnect(t, ac, 1, 0))
	require.Equal(t, STATUS_ACCESS_DENIED, rawTreeConnect(t, ac, 2, victimID), "foreign session must not grant a tree")
	require.Equal(t, STATUS_ACCESS_DENIED, rawTreeConnect(t, ac, 3, 0x100000001))

	// Attacker cannot log the victim off either.
	logoff := make([]byte, 4)
	putle16(logoff, 0, 4)
	require.Equal(t, STATUS_USER_SESSION_DELETED, respStatus(rawSMBRequest(t, ac, SMB2_LOGOFF, 4, victimID, logoff)))
	require.NotNil(t, s.getSession(victimID))

	// The victim's own session keeps working.
	_, err = share.ReadDir(".")
	require.NoError(t, err)
}

func TestSMBSessionHijack_SessionReleasedOnDisconnect(t *testing.T) {
	s := startAuthSMB(t)
	addr := s.ln.Addr().String()

	vc, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "admin", Password: "S3cretPass"}}
	_, err = d.Dial(vc)
	require.NoError(t, err)
	ids := authedSessionIDs(s)
	require.Len(t, ids, 1)
	victimID := ids[0]

	// Victim disconnects without LOGOFF.
	require.NoError(t, vc.Close())
	require.Eventually(t, func() bool { return s.getSession(victimID) == nil }, 5*time.Second, 20*time.Millisecond,
		"session must be dropped when its last connection closes")

	ac, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer ac.Close()
	rawNegotiate(t, ac)
	require.Equal(t, STATUS_ACCESS_DENIED, rawTreeConnect(t, ac, 1, victimID))
}

func TestSMBSession_BindingUnit(t *testing.T) {
	s := &SMBServer{}
	a, b := newConnState(), newConnState()
	sess := s.createSession(a)
	other := s.createSession(a)
	require.NotZero(t, sess.ID)
	require.NotEqual(t, sess.ID, other.ID)

	sess.mu.Lock()
	bindSessionLocked(a, sess)
	sess.mu.Unlock()
	require.True(t, sess.authedOn(a))
	require.False(t, sess.authedOn(b))

	s.releaseConnSessions(a)
	require.Nil(t, s.getSession(sess.ID))
	require.Nil(t, s.getSession(other.ID))
}
