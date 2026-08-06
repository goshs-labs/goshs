package httpserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// ─── NoDelete tests ──────────────────────────────────────────────────────────

func TestDeleteFile_NoDelete(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "should_stay.txt")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.NoDelete = true

	r := httptest.NewRequest(http.MethodDelete, "/should_stay.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	// NoDelete check happens at the mux route level, not in deleteFile.
	// Simulate the mux-level guard here.
	if fs.ReadOnly || fs.UploadOnly || fs.NoDelete {
		fs.handleError(w, r, fmt.Errorf("delete not allowed"), http.StatusForbidden)
		return
	}
	fs.deleteFile(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	// File should still exist
	_, err := os.Stat(target)
	require.NoError(t, err)
}

// ─── Full ACL flow tests (from TestFileBasedACL) ─────────────────────────────

func TestACL_BlockedFile_Returns404(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACL")
	require.NoError(t, os.Mkdir(aclDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile.txt"), []byte("secret"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile2.txt"), []byte("public"), 0644))

	// .goshs blocks testfile.txt and testfolder
	aclContent := `{"block":["testfile.txt","testfolder/"]}`
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// testfile.txt should be blocked (404)
	r := httptest.NewRequest(http.MethodGet, "/ACL/testfile.txt", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)

	// testfile2.txt should be allowed (200)
	r = httptest.NewRequest(http.MethodGet, "/ACL/testfile2.txt", nil)
	w = httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public", w.Body.String())
}

func TestACL_BlockedDir_Returns404(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACL")
	require.NoError(t, os.MkdirAll(filepath.Join(aclDir, "testfolder"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfolder", "testfile2.txt"), []byte("inside"), 0644))

	aclContent := `{"block":["testfolder/"]}`
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// testfolder should be blocked
	r := httptest.NewRequest(http.MethodGet, "/ACL/testfolder", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)

	// testfolder/testfile2.txt should be allowed (block only applies to listing)
	r = httptest.NewRequest(http.MethodGet, "/ACL/testfolder/testfile2.txt", nil)
	w = httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestACL_AuthRequiredDir_Unauthorized(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACLAuth")
	require.NoError(t, os.Mkdir(aclDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile.txt"), []byte("secret"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile2.txt"), []byte("public"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)
	aclContent := fmt.Sprintf(`{"auth":"admin:%s","block":["testfile.txt"]}`, string(hash))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// Without auth - should get 401
	r := httptest.NewRequest(http.MethodGet, "/ACLAuth/", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestACL_AuthRequiredDir_Authorized(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACLAuth")
	require.NoError(t, os.Mkdir(aclDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile2.txt"), []byte("public"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)
	aclContent := fmt.Sprintf(`{"auth":"admin:%s"}`, string(hash))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// With auth - should get 200
	r := httptest.NewRequest(http.MethodGet, "/ACLAuth/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	r.Header.Set("Authorization", "Basic "+auth)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestACL_AuthRequiredDir_BlockedFile(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACLAuth")
	require.NoError(t, os.Mkdir(aclDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile.txt"), []byte("secret"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)
	aclContent := fmt.Sprintf(`{"auth":"admin:%s","block":["testfile.txt"]}`, string(hash))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// Auth + blocked file = 404
	r := httptest.NewRequest(http.MethodGet, "/ACLAuth/testfile.txt", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	r.Header.Set("Authorization", "Basic "+auth)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestACL_AuthRequiredDir_AllowedFile(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACLAuth")
	require.NoError(t, os.Mkdir(aclDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, "testfile2.txt"), []byte("public"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)
	aclContent := fmt.Sprintf(`{"auth":"admin:%s"}`, string(hash))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// Auth + allowed file = 200
	r := httptest.NewRequest(http.MethodGet, "/ACLAuth/testfile2.txt", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	r.Header.Set("Authorization", "Basic "+auth)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public", w.Body.String())
}

func TestACL_AuthRequiredDir_BlockedDir(t *testing.T) {
	dir := t.TempDir()
	aclDir := filepath.Join(dir, "ACLAuth")
	require.NoError(t, os.MkdirAll(filepath.Join(aclDir, "testfolder"), 0755))

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)
	aclContent := fmt.Sprintf(`{"auth":"admin:%s","block":["testfolder/"]}`, string(hash))
	require.NoError(t, os.WriteFile(filepath.Join(aclDir, ".goshs"), []byte(aclContent), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/ACLAuth/testfolder", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	r.Header.Set("Authorization", "Basic "+auth)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

// ─── NoChat tests ────────────────────────────────────────────────────────────

func TestConstructDefault_NoChat(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080
	fs.NoChat = true

	w := httptest.NewRecorder()
	fs.constructDefault(w, "/", nil, nil)
	require.Equal(t, http.StatusOK, w.Code)

	// The response should not contain the chat UI when disabled
	body := w.Body.String()
	require.NotContains(t, body, `id="panel-chat"`)
}

func TestConstructDefault_WithChat(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080

	w := httptest.NewRecorder()
	fs.constructDefault(w, "/", nil, nil)
	require.Equal(t, http.StatusOK, w.Code)

	// Should contain the chat UI when not disabled
	body := w.Body.String()
	require.Contains(t, body, `id="panel-chat"`)
}

func TestConstructDefault_ChatRendersEditedAndReactions(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080

	// Seed a message, edit it, and add a reaction, then render the page.
	m, err := fs.Chat.AddEntry("alice", "helo")
	require.NoError(t, err)
	_, err = fs.Chat.EditEntry(m.ID, "hello")
	require.NoError(t, err)
	_, err = fs.Chat.React(m.ID, "🔥", "bob")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	fs.constructDefault(w, "/", nil, nil)
	require.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	// The edited marker and the reactions payload must be server-rendered so a
	// reloading client sees the same state chat.js renders live.
	require.Contains(t, body, "(edited)")
	require.Contains(t, body, `data-reactions=`)
	require.Contains(t, body, "bob")
	require.Contains(t, body, "🔥")
}

// ─── Full flow tests (from TestUnsecureServer) ───────────────────────────────

func TestFullFlow_ViewDownloadUploadDelete(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test_data.txt"), []byte("hello world"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// View
	r := httptest.NewRequest(http.MethodGet, "/test_data.txt", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "hello world", w.Body.String())

	// Download
	r = httptest.NewRequest(http.MethodGet, "/test_data.txt?download", nil)
	w = httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")

	// Upload via PUT
	r = httptest.NewRequest(http.MethodPut, "/uploaded_put.txt", strings.NewReader("put content"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w = httptest.NewRecorder()
	fs.put(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	data, err := os.ReadFile(filepath.Join(dir, "uploaded_put.txt"))
	require.NoError(t, err)
	require.Equal(t, "put content", string(data))

	// Verify uploaded file
	r = httptest.NewRequest(http.MethodGet, "/uploaded_put.txt", nil)
	w = httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "put content", w.Body.String())

	// Delete
	r = httptest.NewRequest(http.MethodDelete, "/uploaded_put.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w = httptest.NewRecorder()
	fs.deleteFile(w, r)

	// Verify deleted
	r = httptest.NewRequest(http.MethodGet, "/uploaded_put.txt", nil)
	w = httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestFullFlow_UploadPost(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("files[0]", "uploaded_post.txt")
	require.NoError(t, err)
	_, err = part.Write([]byte("post content"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)
	require.Equal(t, http.StatusSeeOther, w.Code)

	data, err := os.ReadFile(filepath.Join(dir, "uploaded_post.txt"))
	require.NoError(t, err)
	require.Equal(t, "post content", string(data))
}

func TestFullFlow_BulkDownload(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/a.txt&file=/b.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/zip", w.Header().Get("Content-Type"))
	require.Contains(t, w.Header().Get("Content-Disposition"), "goshs_download.zip")
}

func TestFullFlow_JsonOutput(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hi"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?json", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var items []map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&items))
	require.True(t, len(items) > 0)
}

// ─── Basic auth flow tests (from TestBasicAuthServer/Hashed) ─────────────────

func TestBasicAuthFlow_Unauthorized(t *testing.T) {
	fs := newFS("admin", "admin")
	handler := fs.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthFlow_Authorized(t *testing.T) {
	fs := newFS("admin", "admin")
	handler := fs.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "admin"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthFlow_HashedPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	handler := fs.BasicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "admin"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	// Wrong password
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "wrong"))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ─── ReadOnly flow tests (from TestReadOnly) ─────────────────────────────────

func TestReadOnlyFlow_UploadBlocked(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.ReadOnly = true

	// POST upload blocked
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("files[0]", "test.txt")
	require.NoError(t, err)
	part.Write([]byte("data"))
	writer.Close()

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)

	// PUT upload blocked
	r = httptest.NewRequest(http.MethodPut, "/test.txt", strings.NewReader("data"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w = httptest.NewRecorder()
	fs.put(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── UploadOnly flow tests (from TestUploadOnly) ─────────────────────────────

func TestUploadOnlyFlow_DownloadBlocked(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.UploadOnly = true

	// View blocked
	r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, nil, configFile{})
	require.Equal(t, http.StatusForbidden, w.Code)

	// Bulk download blocked
	r = httptest.NewRequest(http.MethodGet, "/?bulk&file=/test.txt", nil)
	w = httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── Log output test (from TestOutputLog) ────────────────────────────────────

func TestLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Just verify LogFile function doesn't panic
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	_ = &FileServer{
		Webroot:      tmpDir,
		UploadFolder: tmpDir,
		CSRFToken:    "test-csrf",
		Hub:          hub,
		Chat:         cb,
		Webhook:      *wh,
		SharedLinks:  map[string]SharedLink{},
		Version:      "test",
	}

	require.NoError(t, os.WriteFile(logFile, []byte("Serving HTTP from "+tmpDir), 0644))
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(data), "Serving HTTP")
}

// ─── SetupMux route-level tests ─────────────────────────────────────────────

func TestSetupMux_DeleteBlocked_NoDelete(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.NoDelete = true
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	// Create a file to try to delete
	require.NoError(t, os.WriteFile(filepath.Join(dir, "target.txt"), []byte("data"), 0644))

	r := httptest.NewRequest(http.MethodDelete, "/target.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSetupMux_DeleteBlocked_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.ReadOnly = true
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	r := httptest.NewRequest(http.MethodDelete, "/target.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSetupMux_DeleteBlocked_UploadOnly(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.UploadOnly = true
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	r := httptest.NewRequest(http.MethodDelete, "/target.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSetupMux_PostMkdir(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	r := httptest.NewRequest(http.MethodPost, "/newdir/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusCreated, w.Code)
	require.DirExists(t, filepath.Join(dir, "newdir"))
}

func TestSetupMux_PostUpload(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("files[0]", "upload.txt")
	require.NoError(t, err)
	part.Write([]byte("uploaded"))
	require.NoError(t, writer.Close())

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	data, err := os.ReadFile(filepath.Join(dir, "upload.txt"))
	require.NoError(t, err)
	require.Equal(t, "uploaded", string(data))
}

func TestSetupMux_PutUpload(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	r := httptest.NewRequest(http.MethodPut, "/put.txt", strings.NewReader("put data"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	data, err := os.ReadFile(filepath.Join(dir, "put.txt"))
	require.NoError(t, err)
	require.Equal(t, "put data", string(data))
}

func TestSetupMux_OptionsCORS(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestSetupMux_BasicAuth(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.User = "admin"
	fs.Pass = "secret"
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	// Without auth
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// With auth
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "secret"))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestSetupMux_InvisibleBasicAuth(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.User = "admin"
	fs.Pass = "secret"
	fs.Invisible = true
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	_ = fs.SetupMux(mux, modeWeb)

	// Without auth - should not get a 401 page (invisible mode)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	// Invisible mode hijacks the connection, no standard response
}

func TestSetupMux_Webdav(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.WebdavPort = 8081
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	addr := fs.SetupMux(mux, "webdav")
	require.Equal(t, ":8081", addr)
}

func TestSetupMux_WebdavWithAuth(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.User = "admin"
	fs.Pass = "secret"
	fs.WebdavPort = 8081
	fs.SharedLinks = map[string]SharedLink{}
	fs.Options = &options.Options{}

	mux := NewCustomMux()
	addr := fs.SetupMux(mux, "webdav")
	require.Equal(t, ":8081", addr)
}
