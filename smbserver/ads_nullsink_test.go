package smbserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-4wmw-c376-phcm: an ADS-style (colon) CREATE name
// took a null-sink shortcut that stored the raw path without containment or
// ACL checks, so SET_INFO disposition + CLOSE deleted (and rename moved)
// arbitrary files outside the share.

func dispositionFrame(hID uint64) []byte {
	const bodyLen = 32
	bufOff := 64 + bodyLen
	buf := make([]byte, bufOff+1)
	body := buf[64:]
	body[2] = SMB2_0_INFO_FILE
	body[3] = FileDispositionInformation
	putle32(body, 4, 1)
	putle16(body, 8, uint16(bufOff))
	putle64(body, 16+8, hID)
	buf[bufOff] = 1 // DeletePending
	return buf
}

func closeFrame(hID uint64) []byte {
	buf := make([]byte, 64+24)
	putle64(buf[64:], 16, hID) // FileId volatile half
	return buf
}

// createHandleID returns the volatile FileId from a CREATE response.
func createHandleID(t *testing.T, resp []byte) uint64 {
	t.Helper()
	require.Equal(t, STATUS_SUCCESS, respStatus(resp))
	return le64(resp[64:], 64+8)
}

func TestADSNullSink_OutOfShareDeleteBlocked(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	require.NoError(t, os.Mkdir(root, 0755))
	victim := filepath.Join(base, "app-2026-01-02T03:04:05.log")
	require.NoError(t, os.WriteFile(victim, []byte("KEEP"), 0644))

	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	for _, name := range []string{
		victim,                           // absolute path
		`..\app-2026-01-02T03:04:05.log`, // relative traversal
	} {
		resp := s.handleCreate(cs, h, createFrame(name, FILE_OPEN, 0))
		if respStatus(resp) == STATUS_SUCCESS {
			hID := createHandleID(t, resp)
			_ = s.handleSetInfo(cs, &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}, dispositionFrame(hID))
			_ = s.handleClose(cs, &smb2Hdr{Command: SMB2_CLOSE, TreeID: 1}, closeFrame(hID))
		}
		_, err := os.Stat(victim)
		require.NoError(t, err, "file outside the share must survive (%s)", name)
	}
}

func TestADSNullSink_StoresContainedPath(t *testing.T) {
	root := t.TempDir()
	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	resp := s.handleCreate(cs, h, createFrame(`C:\Windows\System32\drivers\etc\hosts:x`, FILE_OPEN, 0))
	hID := createHandleID(t, resp)
	handle := cs.getHandle(hID)
	require.True(t, handle.IsNullSink)
	rel, err := filepath.Rel(root, handle.Path)
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel) || rel == ".." || len(rel) > 2 && rel[:3] == ".."+string(filepath.Separator), "null-sink path must stay inside the share: %s", handle.Path)

	// Zone.Identifier on a normal in-share file still succeeds.
	require.NoError(t, os.WriteFile(filepath.Join(root, "public.txt"), []byte("x"), 0644))
	resp = s.handleCreate(cs, h, createFrame(`public.txt:Zone.Identifier:$DATA`, FILE_CREATE, 0))
	require.Equal(t, STATUS_SUCCESS, respStatus(resp))
}

func TestADSNullSink_DeleteAndRenameNeverTouchDisk(t *testing.T) {
	root := t.TempDir()
	// A real file whose name contains a colon (legal on Linux) inside the share.
	colon := filepath.Join(root, "a:b")
	require.NoError(t, os.WriteFile(colon, []byte("KEEP"), 0644))
	// Pre-fix the raw name resolved against the CWD; make it hit the file.
	t.Chdir(root)

	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	hID := createHandleID(t, s.handleCreate(cs, h, createFrame(`a:b`, FILE_OPEN, 0)))
	resp := s.handleSetInfo(cs, &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}, renameFrame(hID, "moved.txt"))
	require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp), "rename of a null-sink handle must be denied")
	resp = s.handleSetInfo(cs, &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}, dispositionFrame(hID))
	require.Equal(t, STATUS_SUCCESS, respStatus(resp), "disposition on a null-sink is accepted and discarded")
	_ = s.handleClose(cs, &smb2Hdr{Command: SMB2_CLOSE, TreeID: 1}, closeFrame(hID))

	_, err := os.Stat(colon)
	require.NoError(t, err, "null-sink close must not delete anything")
	_, err = os.Stat(filepath.Join(root, "moved.txt"))
	require.True(t, os.IsNotExist(err))
}

func TestADSNullSink_DeniedByACL(t *testing.T) {
	root := smbACLTree(t)
	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	for _, name := range []string{`secret\file.txt:x`, `secret\.goshs:x`, `.goshs:$DATA`, `blocked.txt:Zone.Identifier`} {
		resp := s.handleCreate(cs, h, createFrame(name, FILE_OPEN, 0))
		require.Equal(t, STATUS_OBJECT_NAME_NOT_FOUND, respStatus(resp), name)
	}
}
