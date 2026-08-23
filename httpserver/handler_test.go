package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/smtpattach"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// newTestFileServer returns a minimal FileServer wired to a running Hub so that
// emitCollabEvent does not block. Call cleanup() in a defer to drain the hub.
func newTestFileServer(t *testing.T, webroot string) (*FileServer, func()) {
	t.Helper()
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()

	wh := webhook.Register(false, "", "discord", []string{})

	fs := &FileServer{
		Webroot:      webroot,
		UploadFolder: webroot,
		CSRFToken:    "test-csrf",
		Hub:          hub,
		Chat:         cb,
		Webhook:      *wh,
		SharedLinks:  map[string]SharedLink{},
		Version:      "test",
		Whitelist:    &Whitelist{},
	}
	return fs, func() {} // hub goroutine is cleaned up by process exit in tests
}

// CreateShareHandler must not dereference a nil os.FileInfo when the target
// path cannot be stat'd (regression for the missing return after http.Error).
func TestCreateShareHandler_StatError_NoPanic(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Pass = "secret" // sharing is only enabled when auth is configured

	r := httptest.NewRequest(http.MethodGet, "/does-not-exist?share", nil)
	w := httptest.NewRecorder()

	require.NotPanics(t, func() { fs.CreateShareHandler(w, r) })
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ─── handleMkdir ─────────────────────────────────────────────────────────────

func TestHandleMkdir_Success(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodPost, "/newdir/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusCreated, w.Code)
	require.DirExists(t, filepath.Join(root, "newdir"))
}

func TestHandleMkdir_ReadOnly(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.ReadOnly = true

	r := httptest.NewRequest(http.MethodPost, "/blocked/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleMkdir_UploadOnly(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.UploadOnly = true

	r := httptest.NewRequest(http.MethodPost, "/blocked/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── CreateShareHandler ───────────────────────────────────────────────────────

func TestCreateShareHandler_NoAuth_Forbidden(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	// Pass and CACert both empty → sharing disabled

	r := httptest.NewRequest(http.MethodGet, "/?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateShareHandler_WithAuth_CreatesToken(t *testing.T) {
	root := t.TempDir()
	// Write a real file to share
	testFile := filepath.Join(root, "hello.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "somepassword"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/hello.txt?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string][]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp["urls"])

	// Token should now be registered in SharedLinks
	require.Len(t, fs.SharedLinks, 1)
}

func TestCreateShareHandler_CustomExpiryAndLimit(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "data.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/data.txt?share&expires=120&limit=3", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, fs.SharedLinks, 1)
	for _, sl := range fs.SharedLinks {
		require.Equal(t, 3, sl.DownloadLimit)
		require.True(t, sl.Expires.After(time.Now()))
	}
}

// ─── ShareHandler ─────────────────────────────────────────────────────────────

func TestShareHandler_InvalidToken_NotFound(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?token=doesnotexist", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_ExpiredToken_NotFound(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "old.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("old content"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["expiredtoken"] = SharedLink{
		FilePath:      "/old.txt",
		IsDir:         false,
		Expires:       time.Now().Add(-1 * time.Hour), // already expired
		DownloadLimit: 1,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=expiredtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_ValidToken_ServesFile(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("top secret"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["validtoken"] = SharedLink{
		FilePath:      "/secret.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 5,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=validtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "top secret", w.Body.String())
}

func TestShareHandler_DownloadLimitExhausted(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "limited.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	// Limit=0 means already exhausted (not -1 which is unlimited)
	fs.SharedLinks["limitedtoken"] = SharedLink{
		FilePath:      "/limited.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 0,
		Downloaded:    0,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=limitedtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_UnlimitedDownloads(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "unlimited.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("unlimited content"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["unlimitedtoken"] = SharedLink{
		FilePath:      "/unlimited.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: -1, // unlimited
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=unlimitedtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "unlimited content", w.Body.String())
}

// ─── DeleteShareHandler ───────────────────────────────────────────────────────

func TestDeleteShareHandler_RemovesToken(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["mytoken"] = SharedLink{
		Expires: time.Now().Add(time.Hour),
	}

	r := httptest.NewRequest(http.MethodDelete, "/?token=mytoken", nil)
	w := httptest.NewRecorder()

	fs.DeleteShareHandler(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
	_, exists := fs.SharedLinks["mytoken"]
	require.False(t, exists)
}

func TestDeleteShareHandler_NonexistentToken_NoError(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/?token=ghost", nil)
	w := httptest.NewRecorder()

	fs.DeleteShareHandler(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
}

// ─── deleteFile .goshs guard ──────────────────────────────────────────────────

func TestDeleteFile_DotGoshsBlocked(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{}`), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/.goshs", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.deleteFile(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	_, err := os.Stat(filepath.Join(root, ".goshs"))
	require.NoError(t, err, ".goshs should not have been deleted")
}

// TestDeleteFile_BlockListedRefused verifies a file block-listed by a .goshs
// ACL cannot be deleted via HTTP DELETE — the read/share/bulk/WebDAV paths all
// treat it as non-existent, so delete must too (regression for
// GHSA-ppmc-5w4w-2669, residual of CVE-2026-40189).
func TestDeleteFile_BlockListedRefused(t *testing.T) {
	root := t.TempDir()
	blockedDir := filepath.Join(root, "blocked")
	require.NoError(t, os.MkdirAll(blockedDir, 0755))
	secret := filepath.Join(blockedDir, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blockedDir, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/blocked/secret.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.deleteFile(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	_, err := os.Stat(secret)
	require.NoError(t, err, "block-listed file must not have been deleted")
}

// TestDeleteFile_NonBlockedStillDeletable confirms the block-list guard does not
// break ordinary deletion of a non-blocked sibling in the same directory.
func TestDeleteFile_NonBlockedStillDeletable(t *testing.T) {
	root := t.TempDir()
	blockedDir := filepath.Join(root, "blocked")
	require.NoError(t, os.MkdirAll(blockedDir, 0755))
	keep := filepath.Join(blockedDir, "public.txt")
	require.NoError(t, os.WriteFile(keep, []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blockedDir, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/blocked/public.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.deleteFile(w, r)

	// deleteFile does not set an explicit status on success (recorder defaults to
	// 200); the meaningful signal is that the non-blocked file is gone.
	require.Equal(t, http.StatusOK, w.Code)
	_, err := os.Stat(keep)
	require.True(t, os.IsNotExist(err), "non-blocked file should have been deleted")
}

// ─── CreateShareHandler edge cases ───────────────────────────────────────────

func TestCreateShareHandler_InvalidExpiresInt(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/f.txt?share&expires=notanint", nil)
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)
	// Bad expires: handler writes 400 via http.Error (no early return in the code)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateShareHandler_InvalidLimitInt(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/f.txt?share&limit=notanint", nil)
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateShareHandler_SSLProtocol(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 8000
	fs.SSL = true

	r := httptest.NewRequest(http.MethodGet, "/f.txt?share", nil)
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string][]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp["urls"])
	require.Contains(t, resp["urls"][0], "https://")
}

func TestCreateShareHandler_Port80(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 80

	r := httptest.NewRequest(http.MethodGet, "/f.txt?share", nil)
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string][]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	// URL for port 80 should NOT include port number
	require.NotContains(t, resp["urls"][0], ":80")
}

// ─── ShareHandler directory download ─────────────────────────────────────────

func TestShareHandler_IsDir_BulkDownload(t *testing.T) {
	root := t.TempDir()
	subDir := filepath.Join(root, "mydir")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "a.txt"), []byte("content"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["dirtoken"] = SharedLink{
		FilePath:      "/mydir",
		IsDir:         true,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 1,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=dirtoken", nil)
	w := httptest.NewRecorder()
	fs.ShareHandler(w, r)

	// bulkDownload sends a zip — either 200 with zip content-type or some response
	require.NotEqual(t, http.StatusNotFound, w.Code)
}

// ─── handleSMTPAttachment ─────────────────────────────────────────────────────

func TestHandleSMTPAttachment_NotFound(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?smtp&id=nonexistent", nil)
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSMTPAttachment_NoID(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?smtp", nil)
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSMTPAttachment_Found(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	id := "test-attach-001"
	smtpattach.Save(id, "report.pdf", "application/pdf", []byte("PDF content"))

	r := httptest.NewRequest(http.MethodGet, "/?smtp&id="+id, nil)
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/pdf", w.Header().Get("Content-Type"))
	require.Equal(t, "PDF content", w.Body.String())
}

// Captured attachments can be large, so the download path supports HTTP Range
// (resumable downloads) via http.ServeContent.
func TestHandleSMTPAttachment_Range(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	id := "test-attach-range"
	smtpattach.Save(id, "dump.bin", "application/octet-stream", []byte("0123456789"))

	r := httptest.NewRequest(http.MethodGet, "/?smtp&id="+id, nil)
	r.Header.Set("Range", "bytes=2-5")
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusPartialContent, w.Code)
	require.Equal(t, "bytes 2-5/10", w.Header().Get("Content-Range"))
	require.Equal(t, "2345", w.Body.String())
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
}
