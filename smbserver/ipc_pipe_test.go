package smbserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-p6c9-h3f7-xq9f: the IPC$ CREATE branch stored the
// client-supplied pipe name as the handle's filesystem Path, so SET_INFO
// disposition + CLOSE ran os.Remove on an arbitrary attacker-chosen path.

func TestIPCPipe_OutOfShareDeleteBlocked(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	require.NoError(t, os.Mkdir(root, 0755))
	victim := filepath.Join(base, "victim-data.txt")
	require.NoError(t, os.WriteFile(victim, []byte("KEEP"), 0644))
	// Pre-fix a relative pipe name resolved against the CWD.
	t.Chdir(base)

	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "IPC$", RootPath: ""})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	for _, name := range []string{victim, "victim-data.txt"} {
		hID := createHandleID(t, s.handleCreate(cs, h, createFrame(name, FILE_OPEN, 0)))
		handle := cs.getHandle(hID)
		require.True(t, handle.IsPipe)
		require.Empty(t, handle.Path, "pipe handles must not carry a filesystem path")
		require.Equal(t, name, handle.PipeName)

		resp := s.handleSetInfo(cs, &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}, dispositionFrame(hID))
		require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp), "disposition on a pipe must be denied")
		resp = s.handleSetInfo(cs, &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}, renameFrame(hID, "moved.txt"))
		require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp), "rename of a pipe must be denied")
		_ = s.handleClose(cs, &smb2Hdr{Command: SMB2_CLOSE, TreeID: 1}, closeFrame(hID))

		_, err := os.Stat(victim)
		require.NoError(t, err, "file outside the share must survive (%s)", name)
	}
}

func TestIPCPipe_CloseIgnoresDeleteOnClose(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("KEEP"), 0644))

	s := &SMBServer{Root: t.TempDir()}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "IPC$", RootPath: ""})
	// Even a pipe handle that somehow carries a path and the flag must not delete.
	cs.addHandle(&smbHandle{ID: 7, Path: victim, PipeName: victim, IsPipe: true, DeleteOnClose: true})
	_ = s.handleClose(cs, &smb2Hdr{Command: SMB2_CLOSE, TreeID: 1}, closeFrame(7))

	_, err := os.Stat(victim)
	require.NoError(t, err)
}
