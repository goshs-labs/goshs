package smbserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-q8gg-q2wc-w52g (SMB instance): SMB must honour the
// per-folder .goshs ACL on the webroot it shares.

func smbACLTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	require.NoError(t, os.Mkdir(secret, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(secret, ".goshs"), []byte(`{"auth":"admin:$2a$04$abcdefghijklmnopqrstuu"}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "file.txt"), []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{"block":["blocked.txt"]}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "blocked.txt"), []byte("BLOCKED"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "public.txt"), []byte("public"), 0644))
	return root
}

// createFrame builds a minimal SMB2 CREATE request for name.
func createFrame(name string, disp, options uint32) []byte {
	nameUTF16 := toUTF16LE(name)
	const bodyLen = 56
	nameOff := 64 + bodyLen
	buf := make([]byte, nameOff+len(nameUTF16))
	body := buf[64:]
	putle32(body, 24, 0x80000000) // DesiredAccess: GENERIC_READ
	putle32(body, 36, disp)
	putle32(body, 40, options)
	putle16(body, 44, uint16(nameOff))
	putle16(body, 46, uint16(len(nameUTF16)))
	copy(buf[nameOff:], nameUTF16)
	return buf
}

func TestHandleCreate_DeniedByACL(t *testing.T) {
	root := smbACLTree(t)
	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	h := &smb2Hdr{Command: SMB2_CREATE, TreeID: 1}

	for _, name := range []string{`secret\file.txt`, `secret\.goshs`, `.goshs`, `blocked.txt`, `BLOCKED.TXT`, `secret`} {
		resp := s.handleCreate(cs, h, createFrame(name, FILE_OPEN, 0))
		require.Equal(t, STATUS_OBJECT_NAME_NOT_FOUND, respStatus(resp), name)
	}
	resp := s.handleCreate(cs, h, createFrame(`poison\.goshs`, FILE_CREATE, FILE_DIRECTORY_FILE))
	require.Equal(t, STATUS_OBJECT_NAME_NOT_FOUND, respStatus(resp))
	_, err := os.Stat(filepath.Join(root, "poison"))
	require.True(t, os.IsNotExist(err))

	resp = s.handleCreate(cs, h, createFrame(`public.txt`, FILE_OPEN, 0))
	require.Equal(t, STATUS_SUCCESS, respStatus(resp), "unprotected file must stay accessible")
}

func TestHandleSetInfo_RenameIntoProtectedDirDenied(t *testing.T) {
	root := smbACLTree(t)
	src := filepath.Join(root, "public.txt")
	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: src})

	h := &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}
	resp := s.handleSetInfo(cs, h, renameFrame(hID, `secret\public.txt`))
	require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp))
	_, err := os.Stat(src)
	require.NoError(t, err)
}

func TestHandleQueryDir_FiltersListing(t *testing.T) {
	root := smbACLTree(t)
	s := &SMBServer{Root: root}
	cs := newConnState()
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: root, IsDir: true})

	const bodyLen = 32
	buf := make([]byte, 64+bodyLen)
	body := buf[64:]
	body[2] = 12             // FileNamesInformation
	putle64(body, 8+8, hID)  // FileId volatile half
	putle32(body, 28, 65536) // OutputBufferLength

	resp := s.handleQueryDir(cs, &smb2Hdr{Command: SMB2_QUERY_DIRECTORY}, buf)
	require.Equal(t, STATUS_SUCCESS, respStatus(resp))
	listing := fromUTF16LE(resp[64+8:])
	require.Contains(t, listing, "public.txt")
	for _, hidden := range []string{".goshs", "blocked.txt", "secret"} {
		require.False(t, strings.Contains(listing, hidden), "listing must not reveal %q", hidden)
	}
}

// GHSA-95fx-g5c4-6f8f: FileRenameInformation on a directory must not move a
// block-listed file out of the .goshs scope that hides it.
func TestHandleSetInfo_RenameDirOutOfBlockScopeDenied(t *testing.T) {
	root := smbACLTree(t)
	sub := filepath.Join(root, "pub", "sub")
	require.NoError(t, os.MkdirAll(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pub", ".goshs"), []byte(`{"block":["flag.txt"]}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "flag.txt"), []byte("FLAG"), 0644))
	s := &SMBServer{Root: root}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: root})
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: sub, IsDir: true})

	h := &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}
	resp := s.handleSetInfo(cs, h, renameFrame(hID, `moved`))
	require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp))
	require.FileExists(t, filepath.Join(sub, "flag.txt"))

	resp = s.handleSetInfo(cs, h, renameFrame(hID, `pub\sub2`))
	require.Equal(t, STATUS_SUCCESS, respStatus(resp))
	require.FileExists(t, filepath.Join(root, "pub", "sub2", "flag.txt"))
}
