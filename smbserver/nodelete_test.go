package smbserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// respStatus extracts the NTSTATUS from an SMB2 response (bytes 8..12).
func respStatus(resp []byte) uint32 {
	if len(resp) < 12 {
		return 0xFFFFFFFF
	}
	return le32(resp, 8)
}

// writeFrame builds a minimal SMB2 WRITE request for the given handle ID.
func writeFrame(hID uint64, writeOff int64, data []byte) []byte {
	const bodyLen = 48
	dataOff := 64 + bodyLen
	buf := make([]byte, dataOff+len(data))
	body := buf[64:]
	putle16(body, 2, uint16(dataOff))   // DataOffset (from start of SMB2 header)
	putle32(body, 4, uint32(len(data))) // Length
	putle64(body, 8, uint64(writeOff))  // Offset
	putle64(body, 16+8, hID)            // FileId volatile half (read at body[24])
	copy(buf[dataOff:], data)
	return buf
}

// TestProtectExisting exercises the shared decision helper that gates every SMB
// --no-delete / --upload-only content-destroying sink.
func TestProtectExisting(t *testing.T) {
	const p = "/srv/report.docx"

	t.Run("no flags never protects", func(t *testing.T) {
		s := &SMBServer{}
		require.False(t, s.protectExisting(p))
	})

	t.Run("no-delete protects pre-existing path", func(t *testing.T) {
		s := &SMBServer{NoDelete: true}
		require.True(t, s.protectExisting(p))
	})

	t.Run("upload-only protects pre-existing path", func(t *testing.T) {
		s := &SMBServer{UploadOnly: true}
		require.True(t, s.protectExisting(p))
	})

	t.Run("newly created path stays writable", func(t *testing.T) {
		s := &SMBServer{NoDelete: true}
		s.newlyCreatedPaths.Store(p, struct{}{})
		require.False(t, s.protectExisting(p))
	})
}

// TestHandleWrite_NoDeleteBlocksExistingFile is the regression for
// GHSA-275v-rxgc-4rcj: an SMB2 WRITE at an attacker-chosen offset must not
// modify a pre-existing served file when --no-delete is set.
func TestHandleWrite_NoDeleteBlocksExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.docx")
	original := []byte("ORIGINAL-CONTENTS")
	require.NoError(t, os.WriteFile(path, original, 0644))

	f, err := os.OpenFile(path, os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer f.Close()

	s := &SMBServer{NoDelete: true}
	cs := newConnState()
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: path, File: f})

	h := &smb2Hdr{Command: SMB2_WRITE}
	resp := s.handleWrite(cs, h, writeFrame(hID, 0, []byte("pwned")))

	require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp), "WRITE to a pre-existing file must be denied under --no-delete")
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, got, "file contents must be untouched")
}

// TestHandleWrite_AllowsNewlyCreatedFile confirms the guard does not break
// legitimate uploads: a file created earlier in the session (newlyCreatedPaths)
// is still streamed via WRITE.
func TestHandleWrite_AllowsNewlyCreatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upload.bin")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	require.NoError(t, err)
	defer f.Close()

	s := &SMBServer{NoDelete: true}
	s.newlyCreatedPaths.Store(path, struct{}{}) // as handleCreate would record
	cs := newConnState()
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: path, File: f})

	payload := []byte("fresh upload bytes")
	h := &smb2Hdr{Command: SMB2_WRITE}
	resp := s.handleWrite(cs, h, writeFrame(hID, 0, payload))

	require.Equal(t, STATUS_SUCCESS, respStatus(resp), "WRITE to a session-created file must be allowed")
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// renameFrame builds an SMB2 SET_INFO FileRenameInformation request renaming the
// handle's file to newName (relative to the tree root).
func renameFrame(hID uint64, newName string) []byte {
	nameUTF16 := toUTF16LE(newName)
	infoBuf := make([]byte, 20+len(nameUTF16))
	putle32(infoBuf, 16, uint32(len(nameUTF16)))
	copy(infoBuf[20:], nameUTF16)

	const bodyLen = 32
	bufOff := 64 + bodyLen
	buf := make([]byte, bufOff+len(infoBuf))
	body := buf[64:]
	body[2] = SMB2_0_INFO_FILE
	body[3] = FileRenameInformation
	putle32(body, 4, uint32(len(infoBuf))) // BufferLength
	putle16(body, 8, uint16(bufOff))       // BufferOffset (from start of SMB2 header)
	putle64(body, 16+8, hID)               // FileId volatile half
	copy(buf[bufOff:], infoBuf)
	return buf
}

// TestHandleSetInfo_NoDeleteBlocksRename is the regression for
// GHSA-ppvh-3pc7-mvxw: renaming a pre-existing file (move-as-deletion) must be
// refused under --no-delete, mirroring FTP/SFTP/WebDAV.
func TestHandleSetInfo_NoDeleteBlocksRename(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "keep.txt")
	require.NoError(t, os.WriteFile(src, []byte("KEEP"), 0644))

	s := &SMBServer{NoDelete: true}
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: dir})
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: src}) // pre-existing: not in newlyCreatedPaths

	h := &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}
	resp := s.handleSetInfo(cs, h, renameFrame(hID, "moved.txt"))

	require.Equal(t, STATUS_ACCESS_DENIED, respStatus(resp), "rename of a pre-existing file must be denied under --no-delete")
	_, err := os.Stat(src)
	require.NoError(t, err, "source must still exist at its original path")
	require.True(t, func() bool { _, e := os.Stat(filepath.Join(dir, "moved.txt")); return os.IsNotExist(e) }(), "destination must not be created")
}

// TestHandleSetInfo_NoDeleteBlocksRenameClobber verifies that even a
// session-created source cannot be renamed onto a pre-existing destination,
// which os.Rename would silently clobber.
func TestHandleSetInfo_NoDeleteBlocksRenameClobber(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.txt")
	require.NoError(t, os.WriteFile(src, []byte("NEW"), 0644))
	victim := filepath.Join(dir, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("VICTIM"), 0644))

	s := &SMBServer{NoDelete: true}
	s.newlyCreatedPaths.Store(src, struct{}{}) // source is the operator's own upload
	cs := newConnState()
	cs.addTree(&smbTree{ID: 1, ShareName: "goshs", RootPath: dir})
	hID := cs.newHandleID()
	cs.addHandle(&smbHandle{ID: hID, Path: src})

	h := &smb2Hdr{Command: SMB2_SET_INFO, TreeID: 1}
	resp := s.handleSetInfo(cs, h, renameFrame(hID, "victim.txt"))

	require.Equal(t, STATUS_OBJECT_NAME_COLLISION, respStatus(resp), "rename onto an existing destination must be refused")
	got, err := os.ReadFile(victim)
	require.NoError(t, err)
	require.Equal(t, []byte("VICTIM"), got, "destination contents must be preserved")
}
