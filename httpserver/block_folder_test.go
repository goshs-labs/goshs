package httpserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-5v54-7vcp-2f4h: a "name/" folder entry in a .goshs
// block list was only honoured by the HTTP directory listing. WebDAV, the
// credential-less protocols (via ProtocolACL) and the ?bulk zip compared the
// bare name, never matched, and listed/served the hidden folder.

// blockedFolderTree builds webroot/{public.txt, secret-backups/creds.txt,
// a/secret-backups/creds.txt} with {"block":["secret-backups/"]} in the
// webroot. The nested copy exercises the merged (effective) block list.
func blockedFolderTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "public.txt"), []byte("hi"), 0o644))
	for _, d := range []string{"secret-backups", filepath.Join("a", "secret-backups")} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, d, "creds.txt"), []byte("db password: hunter2"), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{"block":["secret-backups/"]}`), 0o644))
	return root
}

func TestBlockedFolder_BulkZipOfParentSkipsIt(t *testing.T) {
	fs, _ := newTestFileServer(t, blockedFolderTree(t))
	w := httptest.NewRecorder()
	fs.bulkDownload(w, httptest.NewRequest(http.MethodGet, "/?bulk&file=/", nil))
	require.Equal(t, http.StatusOK, w.Code)
	names := zipEntryNames(t, w.Body.Bytes())
	require.Contains(t, names, "public.txt")
	for _, n := range names {
		require.NotContains(t, n, "secret-backups", "blocked folder leaked into the archive")
	}
}

func TestBlockedFolder_BulkZipDirectSelectionRefused(t *testing.T) {
	fs, _ := newTestFileServer(t, blockedFolderTree(t))
	for _, p := range []string{"/secret-backups", "/a/secret-backups"} {
		w := httptest.NewRecorder()
		fs.bulkDownload(w, httptest.NewRequest(http.MethodGet, "/?bulk&file="+p, nil))
		require.Equal(t, http.StatusNotFound, w.Code, p)
	}
}

func TestBlockedFolder_WebdavHidesAndRefuses(t *testing.T) {
	fs, cleanup := newTestFileServer(t, blockedFolderTree(t))
	defer cleanup()
	h := newWebdavTestHandler(fs)

	for _, p := range []string{"/", "/a/"} {
		w := propfind(t, h, p, "")
		require.Equal(t, http.StatusMultiStatus, w.Code, p)
		require.NotContains(t, w.Body.String(), "secret-backups", "PROPFIND %s lists the blocked folder", p)
	}
	for _, p := range []string{"/secret-backups/", "/a/secret-backups/"} {
		w := propfind(t, h, p, "")
		require.Equal(t, http.StatusNotFound, w.Code, "PROPFIND %s", p)
	}
}

func TestBlockedFolder_ProtocolACL(t *testing.T) {
	root := blockedFolderTree(t)
	acl := NewProtocolACL(root)

	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	for _, e := range acl.FilterDirEntries(root, entries) {
		require.NotEqual(t, "secret-backups", e.Name(), "listing shows the blocked folder")
	}
	infos := []os.FileInfo{}
	for _, e := range entries {
		fi, err := e.Info()
		require.NoError(t, err)
		infos = append(infos, fi)
	}
	for _, fi := range acl.FilterListing(root, infos) {
		require.NotEqual(t, "secret-backups", fi.Name())
	}

	require.False(t, acl.Allowed(filepath.Join(root, "secret-backups")), "opening/listing the blocked folder")
	require.False(t, acl.Allowed(filepath.Join(root, "a", "secret-backups")), "nested blocked folder via merged ACL")
	require.True(t, acl.Allowed(filepath.Join(root, "a")))
	require.True(t, acl.Allowed(filepath.Join(root, "public.txt")))
	// A *file* with the folder's name is not matched by the "name/" entry.
	require.NoError(t, os.WriteFile(filepath.Join(root, "a", "secret-backups.txt"), nil, 0o644))
	require.True(t, acl.Allowed(filepath.Join(root, "a", "secret-backups.txt")))
}

// doDir checked only the immediate parent's .goshs, so a folder hidden by an
// ancestor's entry (and thus missing from its parent's listing) could still be
// listed by requesting it directly.
func TestBlockedFolder_HTTPNestedDirectRequest404(t *testing.T) {
	fs, _ := newTestFileServer(t, blockedFolderTree(t))
	for _, p := range []string{"/secret-backups/", "/a/secret-backups/"} {
		w := httptest.NewRecorder()
		fs.handler(w, httptest.NewRequest(http.MethodGet, p+"?json", nil))
		require.Equal(t, http.StatusNotFound, w.Code, p)
		require.False(t, strings.Contains(w.Body.String(), "creds.txt"), p)
	}
	w := httptest.NewRecorder()
	fs.handler(w, httptest.NewRequest(http.MethodGet, "/a/?json", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "secret-backups")
}
