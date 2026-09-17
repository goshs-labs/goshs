package sftpserver

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

// These tests are the handler-level reproduction of GHSA-2m7f-jq4x-rcj7: the
// per-folder .goshs ACL was enforced for HTTP/WebDAV but never consulted on the
// SFTP request path, so any SFTP client could read/write/list/rename inside a
// folder that .goshs protects under a different credential or blocks outright.
// A non-empty .goshs "auth" cannot be satisfied over SFTP (no per-folder
// credential is presented), so it must fail closed.

// realistic-looking per-folder auth: "user:bcrypthash". SFTP never validates the
// hash — a non-empty auth is an unsatisfiable requirement and denies outright.
const protectedGoshs = `{"auth":"protuser:$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"}`

// newProtectedRoot builds a webroot with an auth-protected subfolder and an
// unprotected file at the top level, returning the root path.
func newProtectedRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prot := filepath.Join(dir, "protected")
	require.NoError(t, os.Mkdir(prot, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(prot, ".goshs"), []byte(protectedGoshs), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(prot, "secret.txt"), []byte("TOP-SECRET"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "public.txt"), []byte("public"), 0o644))
	return dir
}

func TestSFTP_ACL_ReadProtectedFileDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	_, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/protected/secret.txt"})
	require.ErrorIs(t, err, errACLDenied)
}

func TestSFTP_ACL_WriteIntoProtectedFolderDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	_, err := h.Filewrite(&sftp.Request{Method: "Put", Filepath: "/protected/pwned.txt"})
	require.ErrorIs(t, err, errACLDenied)
	require.NoFileExists(t, filepath.Join(dir, "protected", "pwned.txt"))
}

func TestSFTP_ACL_ListProtectedFolderDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	_, err := h.Filelist(&sftp.Request{Method: "List", Filepath: "/protected"})
	require.ErrorIs(t, err, errACLDenied)
}

func TestSFTP_ACL_StatProtectedFileDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	_, err := h.Filelist(&sftp.Request{Method: "Stat", Filepath: "/protected/secret.txt"})
	require.ErrorIs(t, err, errACLDenied)
}

func TestSFTP_ACL_GoshsFileItselfDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	// The .goshs file holds the bcrypt hashes; it must never be readable.
	_, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/protected/.goshs"})
	require.ErrorIs(t, err, errACLDenied)
}

func TestSFTP_ACL_RemoveProtectedFileDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	err := h.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/protected/secret.txt"})
	require.ErrorIs(t, err, errACLDenied)
	require.FileExists(t, filepath.Join(dir, "protected", "secret.txt"))
}

func TestSFTP_ACL_RenameIntoProtectedFolderDenied(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	// Source is unprotected, destination lands inside the protected folder.
	err := h.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/public.txt", Target: "/protected/public.txt"})
	require.ErrorIs(t, err, errACLDenied)
	require.NoFileExists(t, filepath.Join(dir, "protected", "public.txt"))
}

func TestSFTP_ACL_BlockedFileDenied(t *testing.T) {
	dir := t.TempDir()
	// Block-only .goshs at the root: no auth requirement, just a block entry.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["blocked.txt"]}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("y"), 0o644))
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	_, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/blocked.txt"})
	require.ErrorIs(t, err, errACLDenied)

	// A non-blocked sibling in the same folder is still readable.
	r, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/ok.txt"})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestSFTP_ACL_ListingHidesGoshsBlockedAndProtectedChildren(t *testing.T) {
	dir := newProtectedRoot(t)
	// Add a block-only .goshs at the root that also blocks a file, so the root
	// listing itself is allowed (no auth) but must filter its contents.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["hidden.txt"]}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hidden.txt"), []byte("h"), 0o644))

	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}
	lister, err := h.Filelist(&sftp.Request{Method: "List", Filepath: "/"})
	require.NoError(t, err)

	names := listerNames(t, lister)
	require.Contains(t, names, "public.txt")
	require.NotContains(t, names, ".goshs")     // config file hidden
	require.NotContains(t, names, "hidden.txt") // block-listed
	require.NotContains(t, names, "protected")  // auth-protected subdirectory
}

func TestSFTP_ACL_UnprotectedPathStillWorks(t *testing.T) {
	dir := newProtectedRoot(t)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: testSFTPServer(dir)}

	r, err := h.Fileread(&sftp.Request{Method: "Get", Filepath: "/public.txt"})
	require.NoError(t, err)
	require.NotNil(t, r)
}

// listerNames drains a sftp.ListerAt into the set of entry names it exposes.
func listerNames(t *testing.T, lister sftp.ListerAt) []string {
	t.Helper()
	buf := make([]fs.FileInfo, 128)
	n, _ := lister.ListAt(buf, 0)
	names := make([]string, 0, n)
	for _, fi := range buf[:n] {
		names = append(names, fi.Name())
	}
	return names
}
