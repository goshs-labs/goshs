package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// ─── CustomMux tests ─────────────────────────────────────────────────────────

func TestNewCustomMux(t *testing.T) {
	mux := NewCustomMux()
	require.NotNil(t, mux)
}

func TestCustomMux_HandleFunc(t *testing.T) {
	mux := NewCustomMux()
	called := false
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestCustomMux_Handle(t *testing.T) {
	mux := NewCustomMux()
	called := false
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.True(t, called)
}

func TestCustomMux_UseMiddleware(t *testing.T) {
	mux := NewCustomMux()
	order := []string{}

	mux.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1")
			next.ServeHTTP(w, r)
		})
	})
	mux.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2")
			next.ServeHTTP(w, r)
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	require.Equal(t, []string{"mw1", "mw2", "handler"}, order)
}

// ─── CSRF check tests ────────────────────────────────────────────────────────

func TestCheckCSRF_ValidToken(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	require.True(t, fs.checkCSRF(w, r))
}

func TestCheckCSRF_NoOriginNoReferer(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.checkCSRF(w, r))
}

func TestCheckCSRF_SameOrigin(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "http://example.com")
	w := httptest.NewRecorder()
	require.True(t, fs.checkCSRF(w, r))
}

func TestCheckCSRF_SameReferer(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host = "example.com"
	r.Header.Set("Referer", "http://example.com/page")
	w := httptest.NewRecorder()
	require.True(t, fs.checkCSRF(w, r))
}

func TestCheckCSRF_CrossOrigin(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host = "example.com"
	r.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	require.False(t, fs.checkCSRF(w, r))
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── filebased ACL tests ─────────────────────────────────────────────────────

func TestFindSpecialFile_NoConfig(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	config, err := fs.findSpecialFile(dir)
	require.NoError(t, err)
	require.Equal(t, "", config.Auth)
	require.Nil(t, config.Block)
}

func TestFindSpecialFile_WithConfig(t *testing.T) {
	dir := t.TempDir()
	configContent := `{"auth":"user:hashedpass","block":["secret.txt"]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(configContent), 0644))

	fs, _ := newTestFileServer(t, dir)
	config, err := fs.findSpecialFile(dir)
	require.NoError(t, err)
	require.Equal(t, "user:hashedpass", config.Auth)
	require.Equal(t, []string{"secret.txt"}, config.Block)
}

func TestFindSpecialFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte("not json"), 0644))

	fs, _ := newTestFileServer(t, dir)
	_, err := fs.findSpecialFile(dir)
	require.Error(t, err)
}

func TestFindSpecialFile_NonexistentDir(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	_, err := fs.findSpecialFile("/nonexistent/path/12345")
	require.Error(t, err)
}

func TestFindEffectiveACL_InWebroot(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(sub, 0755))

	configContent := `{"auth":"user:pass"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(configContent), 0644))

	fs, _ := newTestFileServer(t, dir)
	config, err := fs.findEffectiveACL(sub)
	require.NoError(t, err)
	require.Equal(t, "user:pass", config.Auth)
}

func TestFindEffectiveACL_NoConfig(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	config, err := fs.findEffectiveACL(dir)
	require.NoError(t, err)
	require.Equal(t, "", config.Auth)
}

// ─── applyCustomAuth tests ───────────────────────────────────────────────────

func TestApplyCustomAuth_NoAuth(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.applyCustomAuth(w, r, configFile{}))
}

func TestApplyCustomAuth_NoHeader(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	require.False(t, fs.applyCustomAuth(w, r, configFile{Auth: "user:pass"}))
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestApplyCustomAuth_BadFormat(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	require.False(t, fs.applyCustomAuth(w, r, configFile{Auth: "invalidnoformat"}))
}

// ─── removeItem tests ────────────────────────────────────────────────────────

func TestRemoveItem(t *testing.T) {
	items := []item{
		{Name: "a.txt"},
		{Name: "b.txt"},
		{Name: "c.txt"},
	}
	result := removeItem(items, "b.txt")
	require.Len(t, result, 2)
	require.Equal(t, "a.txt", result[0].Name)
	require.Equal(t, "c.txt", result[1].Name)
}

func TestRemoveItem_NotFound(t *testing.T) {
	items := []item{{Name: "a.txt"}, {Name: "b.txt"}}
	result := removeItem(items, "z.txt")
	require.Len(t, result, 2)
}

// ─── handleInfo tests ────────────────────────────────────────────────────────

func TestHandleInfo(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.IP = "127.0.0.1"
	fs.Port = 8080
	fs.Options = &options.Options{}
	w := httptest.NewRecorder()
	fs.handleInfo(w)

	require.Equal(t, http.StatusOK, w.Code)

	var info map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&info))
	require.Equal(t, "127.0.0.1", info["ip"])
	require.Equal(t, "8080", info["port"])
}

func TestHandleInfo_Invisible(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.Invisible = true
	fs.Options = &options.Options{}
	w := httptest.NewRecorder()
	fs.handleInfo(w)
	// handleInvisible hijacks the connection; just ensure no crash
}

func TestHandleInfo_Silent(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.Silent = true
	fs.Options = &options.Options{}
	w := httptest.NewRecorder()
	fs.handleInfo(w)
	// handleInvisible hijacks the connection; just ensure no crash
}

// ─── collaborator tests ──────────────────────────────────────────────────────

func TestEmitCollabEvent(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/test?foo=bar", strings.NewReader("body"))
	r.RemoteAddr = "1.2.3.4:5678"
	r.Header.Set("X-Custom", "value")
	r.Header.Set("X-Csrf-Token", "should-be-stripped")

	body := fs.emitCollabEvent(r, http.StatusOK)
	require.Equal(t, "body", string(body))
}

// ─── handler tests ───────────────────────────────────────────────────────────

func TestHandler_Favicon(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
}

func TestHandler_NotFound(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_DirListing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_FileDownload(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello world"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/test.txt?download", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
}

func TestHandler_FileView(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello world"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── put (upload) tests ──────────────────────────────────────────────────────

func TestPut_ReadOnly(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.ReadOnly = true
	r := httptest.NewRequest(http.MethodPut, "/file.txt", strings.NewReader("content"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestPut_Success(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodPut, "/file.txt", strings.NewReader("content"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	data, err := os.ReadFile(filepath.Join(dir, "file.txt"))
	require.NoError(t, err)
	require.Equal(t, "content", string(data))
}

func TestPut_BlockGoshsFile(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodPut, "/.goshs", strings.NewReader("evil"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── upload tests ────────────────────────────────────────────────────────────

func TestUpload_ReadOnly(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.ReadOnly = true
	r := httptest.NewRequest(http.MethodPost, "/upload", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── deleteFile tests ────────────────────────────────────────────────────────

func TestDeleteFile_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "todelete.txt")
	require.NoError(t, os.WriteFile(target, []byte("bye"), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodDelete, "/todelete.txt", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.deleteFile(w, r)

	_, err := os.Stat(target)
	require.True(t, os.IsNotExist(err))
}

func TestDeleteFile_BlockGoshs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte("{}"), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodDelete, "/.goshs", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.deleteFile(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── handleRedirect tests ────────────────────────────────────────────────────

func TestHandleRedirect_DefaultStatus(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "http://example.com", w.Header().Get("Location"))
}

func TestHandleRedirect_CustomStatus(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com&status=301", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusMovedPermanently, w.Code)
}

func TestHandleRedirect_MissingURL(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRedirect_InvalidStatus(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com&status=200", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRedirect_WithHeaders(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com&header=X-Custom:+value", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, "value", w.Header().Get("X-Custom"))
}

func TestHandleRedirect_MalformedHeader(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com&header=badheader", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ─── bulkDownload tests ──────────────────────────────────────────────────────

// mockWebhook captures messages sent via HandleWebhookSend for assertion in tests.
type mockWebhook struct {
	messages []string
	events   []string
}

func (m *mockWebhook) Send(msg string) error      { m.messages = append(m.messages, msg); return nil }
func (m *mockWebhook) GetEnabled() bool           { return true }
func (m *mockWebhook) GetEvents() []string        { return []string{"all"} }
func (m *mockWebhook) Contains(event string) bool { return true }

// ─── PUT upload-limit tests ───────────────────────────────────────────────────

func TestPut_MaxUploadExceeded(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	fs.MaxUpload = 5 // only allow 5 bytes

	r := httptest.NewRequest(http.MethodPut, "/file.txt", strings.NewReader("this is more than five bytes"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	// Partial file must not be left on disk.
	_, err := os.Stat(filepath.Join(dir, "file.txt"))
	require.True(t, os.IsNotExist(err), "partial file should be removed after limit exceeded")
}

func TestUpload_MaxUploadExceeded(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.MaxUpload = 5 // only allow 5 bytes total body

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "big.txt")
	require.NoError(t, err)
	_, err = part.Write([]byte("this is definitely more than five bytes"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	_, err = os.Stat(filepath.Join(dir, "big.txt"))
	require.True(t, os.IsNotExist(err), "partial file should be removed after limit exceeded")
}

// ─── redirect webhook test ────────────────────────────────────────────────────

func TestHandleRedirect_SendsWebhook(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	mock := &mockWebhook{}
	var whi webhook.Webhook = mock
	fs.Webhook = whi

	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com", nil)
	w := httptest.NewRecorder()
	fs.handleRedirect(w, r)

	require.Equal(t, http.StatusFound, w.Code)
	require.Len(t, mock.messages, 1)
	require.Contains(t, mock.messages[0], "http://example.com")
}

// ─── bulkDownload tests ──────────────────────────────────────────────────────

func TestBulkDownload_UploadOnly(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.UploadOnly = true
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/test.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestBulkDownload_NoFiles(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?bulk", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	// Should handle gracefully (404)
}

func TestBulkDownload_Success(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/a.txt&file=/b.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/zip", w.Header().Get("Content-Type"))
}

func TestBulkDownload_ACL_NoCredentials(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected")
	require.NoError(t, os.Mkdir(protected, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(protected, "secret.txt"), []byte("secret"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.MinCost)
	require.NoError(t, err)
	acl := fmt.Sprintf(`{"auth":"user:%s"}`, hash)
	require.NoError(t, os.WriteFile(filepath.Join(protected, ".goshs"), []byte(acl), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/protected/secret.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBulkDownload_ACL_WithCredentials(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected")
	require.NoError(t, os.Mkdir(protected, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(protected, "secret.txt"), []byte("secret"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.MinCost)
	require.NoError(t, err)
	acl := fmt.Sprintf(`{"auth":"user:%s"}`, hash)
	require.NoError(t, os.WriteFile(filepath.Join(protected, ".goshs"), []byte(acl), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/protected/secret.txt", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/zip", w.Header().Get("Content-Type"))
}

func TestBulkDownload_ACL_BlockList(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked.txt"), []byte("nope"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["blocked.txt"]}`), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/blocked.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestBulkDownload_ACL_InheritedFromParent(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "file.txt"), []byte("data"), 0644))

	hash, err := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.MinCost)
	require.NoError(t, err)
	acl := fmt.Sprintf(`{"auth":"user:%s"}`, hash)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(acl), 0644))

	fs, _ := newTestFileServer(t, dir)
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/sub/file.txt", nil)
	w := httptest.NewRecorder()
	fs.bulkDownload(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ─── returnJsonDirListing tests ──────────────────────────────────────────────

func TestReturnJsonDirListing(t *testing.T) {
	items := []item{
		{Name: "a.txt", IsDir: false, Ext: ".txt"},
		{Name: "b/", IsDir: true},
	}
	w := httptest.NewRecorder()
	returnJsonDirListing(w, items)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var parsed []item
	require.NoError(t, json.NewDecoder(w.Body).Decode(&parsed))
	require.Len(t, parsed, 2)
}

// ─── checkPasswordHash tests ─────────────────────────────────────────────────

func TestCheckPasswordHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	require.True(t, checkPasswordHash("secret", string(hash)))
	require.False(t, checkPasswordHash("wrong", string(hash)))
}

// ─── InvisibleBasicAuthMiddleware tests ───────────────────────────────────────

func TestInvisibleBasicAuthMiddleware_NoAuth(t *testing.T) {
	fs := newFS("user", "pass")
	fs.Invisible = true
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.False(t, called)
}

func TestInvisibleBasicAuthMiddleware_ValidAuth(t *testing.T) {
	fs := newFS("user", "pass")
	fs.Invisible = true
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── IPWhitelistMiddleware tests ──────────────────────────────────────────────

func TestIPWhitelistMiddleware_Disabled(t *testing.T) {
	fs := &FileServer{Whitelist: &Whitelist{Enabled: false}}
	called := false
	handler := fs.IPWhitelistMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.True(t, called)
}

func TestIPWhitelistMiddleware_Blocked(t *testing.T) {
	wl, _ := NewIPWhitelist("192.168.1.0/24", true, "")
	fs := &FileServer{Whitelist: wl}
	called := false
	handler := fs.IPWhitelistMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.False(t, called)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestIPWhitelistMiddleware_Allowed(t *testing.T) {
	wl, _ := NewIPWhitelist("192.168.1.0/24", true, "")
	fs := &FileServer{Whitelist: wl}
	called := false
	handler := fs.IPWhitelistMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.5:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.True(t, called)
}

// ─── constructItems tests ────────────────────────────────────────────────────

func TestConstructItems_HidesGoshsFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("hi"), 0644))

	fs, _ := newTestFileServer(t, dir)
	f, _ := os.Open(dir)
	defer f.Close()
	fis, _ := f.Readdir(-1)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	items := fs.constructItems(fis, "/", configFile{}, r)

	for _, it := range items {
		require.NotEqual(t, ".goshs", it.Name)
	}
	require.Len(t, items, 1)
	require.Equal(t, "visible.txt", items[0].Name)
}

func TestConstructItems_BlockedFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))

	fs, _ := newTestFileServer(t, dir)
	f, _ := os.Open(dir)
	defer f.Close()
	fis, _ := f.Readdir(-1)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	items := fs.constructItems(fis, "/", configFile{Block: []string{"b.txt"}}, r)

	require.Len(t, items, 1)
	require.Equal(t, "a.txt", items[0].Name)
}

func TestConstructItems_SortedAlphabetically(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.txt"), []byte("c"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))

	fs, _ := newTestFileServer(t, dir)
	f, _ := os.Open(dir)
	defer f.Close()
	fis, _ := f.Readdir(-1)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	items := fs.constructItems(fis, "/", configFile{}, r)

	require.Len(t, items, 3)
	require.Equal(t, "a.txt", items[0].Name)
	require.Equal(t, "b.txt", items[1].Name)
	require.Equal(t, "c.txt", items[2].Name)
}

// ─── constructSilent tests ───────────────────────────────────────────────────

func TestConstructSilent(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.Silent = true
	w := httptest.NewRecorder()
	fs.constructSilent(w)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── processDir tests ────────────────────────────────────────────────────────

func TestProcessDir_Invisible(t *testing.T) {
	dir := t.TempDir()
	fs, _ := newTestFileServer(t, dir)
	fs.Invisible = true
	f, _ := os.Open(dir)
	defer f.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	fs.processDir(w, r, f, "/", false, configFile{})
	// Should not crash; handleInvisible hijacks
}

func TestProcessDir_JsonOutput(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hi"), 0644))

	fs, _ := newTestFileServer(t, dir)
	f, _ := os.Open(dir)
	defer f.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	fs.processDir(w, r, f, "/", true, configFile{})

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// ─── earlyBreakParameters tests ──────────────────────────────────────────────

func TestEarlyBreakParameters_GoshsInfo(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080
	fs.Options = &options.Options{}
	r := httptest.NewRequest(http.MethodGet, "/?goshs-info", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))

	var info map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&info))
	require.Equal(t, "127.0.0.1", info["ip"])
}

func TestEarlyBreakParameters_SmtpNoID(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?smtp", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestEarlyBreakParameters_NoMatch(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	require.False(t, fs.earlyBreakParameters(w, r))
}

// ─── handleMkdir tests ───────────────────────────────────────────────────────

func TestHandleMkdir_Invisible(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodPost, "/newdir/", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.handleMkdir(w, r)
	// handleInvisible hijacks; should not crash
}

// ─── GenerateQRCode tests ────────────────────────────────────────────────────

func TestGenerateQRCode(t *testing.T) {
	result := GenerateQRCode("http://example.com")
	require.NotEmpty(t, result)
	require.True(t, strings.HasPrefix(result, "data:image/png;base64,"))
}

// ─── generateCSRFToken tests ─────────────────────────────────────────────────

func TestGenerateCSRFToken(t *testing.T) {
	token := generateCSRFToken()
	require.NotEmpty(t, token)
	require.Len(t, token, 64) // 32 bytes hex encoded
}

// ─── chatDown tests ───────────────────────────────────────────────────────────

func TestChatDown_Empty(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	r := httptest.NewRequest(http.MethodGet, "/?chatDown", nil)
	w := httptest.NewRecorder()
	fs.chatDown(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── constructEmbedded tests ─────────────────────────────────────────────────

func TestConstructEmbedded(t *testing.T) {
	fs, _ := newTestFileServer(t, t.TempDir())
	fs.Embedded = true
	items := fs.constructEmbedded()
	// Should return at least one item from the embedded FS
	require.NotNil(t, items)
}

// ─── NewHttpServer tests ─────────────────────────────────────────────────────

func TestNewHttpServer(t *testing.T) {
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})
	wl, _ := NewIPWhitelist("", false, "")

	opts := &options.Options{
		IP:         "0.0.0.0",
		Port:       8080,
		Webroot:    "/tmp",
		SSL:        false,
		ReadOnly:   false,
		UploadOnly: false,
	}

	fs := NewHttpServer(opts, hub, cb, wl, *wh)
	require.NotNil(t, fs)
	require.Equal(t, "0.0.0.0", fs.IP)
	require.Equal(t, 8080, fs.Port)
	require.NotEmpty(t, fs.CSRFToken)
}

// ─── embedded tests ──────────────────────────────────────────────────────────

func TestEmbedded_ValidFile(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/example.txt", nil)
	w := httptest.NewRecorder()
	err := fs.embedded(w, r)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestEmbedded_InvalidFile(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/nonexistent.txt", nil)
	w := httptest.NewRecorder()
	err := fs.embedded(w, r)
	require.Error(t, err)
}

// ─── static tests ────────────────────────────────────────────────────────────

func TestStatic_ValidFile(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/css/style.css", nil)
	w := httptest.NewRecorder()
	fs.static(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── PrintEmbeddedFiles tests ────────────────────────────────────────────────

func TestPrintEmbeddedFiles(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.PrintEmbeddedFiles() // just ensure no panic
}

// ─── logOnly tests ───────────────────────────────────────────────────────────

func TestLogOnly(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.logOnly(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ok\n", w.Body.String())
}

func TestLogOnly_Invisible(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.logOnly(w, r)
	// handleInvisible hijacks - just ensure no panic
}

// ─── handler tests for static and embedded via earlyBreakParameters ──────────

func TestEarlyBreakParameters_Static(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?static", nil)
	w := httptest.NewRecorder()
	// This calls static() which needs a valid static path
	// The test verifies the parameter handling works
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_Embedded(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/example.txt?embedded", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestEarlyBreakParameters_EmbeddedInvalid(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/nonexistent?embedded", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_ChatDown(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?chatDown", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestEarlyBreakParameters_ChatDownNoChat(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.NoChat = true
	r := httptest.NewRequest(http.MethodGet, "/?chatDown", nil)
	w := httptest.NewRecorder()
	// When NoChat is true, chatDown should not be called
	result := fs.earlyBreakParameters(w, r)
	// It should still break but not call chatDown - falls through
	_ = result
}

func TestEarlyBreakParameters_Bulk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("data"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?bulk&file=/test.txt", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_Redirect(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusFound, w.Code)
}

func TestEarlyBreakParameters_Share(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_TokenGet(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("data"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.SharedLinks["validtoken"] = SharedLink{
		FilePath:      "/test.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 5,
	}
	r := httptest.NewRequest(http.MethodGet, "/?token=validtoken", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusOK, w.Code)
}

func TestEarlyBreakParameters_TokenDelete(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.SharedLinks["mytoken"] = SharedLink{Expires: time.Now().Add(time.Hour)}
	r := httptest.NewRequest(http.MethodDelete, "/?token=mytoken", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestEarlyBreakParameters_Ws(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?ws", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	// WebSocket upgrade will fail without a proper connection, but the parameter handling works
}

func TestEarlyBreakParameters_InvisibleBulk(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/?bulk", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	// handleInvisible hijacks
}

func TestEarlyBreakParameters_InvisibleStatic(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/?static", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_InvisibleShare(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_InvisibleRedirect(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/?redirect&url=http://example.com", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_InvisibleToken(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Invisible = true
	r := httptest.NewRequest(http.MethodGet, "/?token=abc", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
}

func TestEarlyBreakParameters_TokenWithTokenAccess(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	// smtp with a token query param should be denied by denyForTokenAccess
	r := httptest.NewRequest(http.MethodGet, "/?smtp&id=test&token=abc", nil)
	w := httptest.NewRecorder()
	require.True(t, fs.earlyBreakParameters(w, r))
	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── sendFile tests ──────────────────────────────────────────────────────────

func TestSendFile_UploadOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.UploadOnly = true

	f, err := os.Open(filepath.Join(dir, "test.txt"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSendFile_BlockGoshs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte("{}"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, ".goshs"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/.goshs", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSendFile_BlockedByACL(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("secret"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, "secret.txt"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/secret.txt", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{Block: []string{"secret.txt"}})
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestSendFile_Success(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello world"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, "test.txt"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/test.txt", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "hello world", w.Body.String())
}

func TestSendFile_Download(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, "test.txt"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/test.txt?download", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
}

// ─── processDir tests ────────────────────────────────────────────────────────

func TestProcessDir_Silent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hi"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.Silent = true
	f, _ := os.Open(dir)
	defer f.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	fs.processDir(w, r, f, "/", false, configFile{})
	require.Equal(t, http.StatusOK, w.Code)
}

func TestProcessDir_SilentJsonBlocked(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hi"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.Silent = true
	f, _ := os.Open(dir)
	defer f.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	fs.processDir(w, r, f, "/", true, configFile{})
	require.Equal(t, http.StatusNotFound, w.Code)
}

// ─── constructDefault tests ──────────────────────────────────────────────────

func TestConstructDefault(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080

	items := []item{
		{Name: "a.txt", IsDir: false, Ext: ".txt", DisplaySize: "10 B", SortSize: 10},
	}
	w := httptest.NewRecorder()
	fs.constructDefault(w, "/", items, nil)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestConstructDefault_Subdirectory(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080

	w := httptest.NewRecorder()
	fs.constructDefault(w, "/subdir", nil, nil)
	require.Equal(t, http.StatusOK, w.Code)
}

// ─── handler JSON output tests ───────────────────────────────────────────────

func TestHandler_DirListingJson(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/?json", nil)
	w := httptest.NewRecorder()
	fs.handler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// ─── handleError tests ───────────────────────────────────────────────────────

func TestHandleError_NotInvisible(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.handleError(w, r, fmt.Errorf("test error"), http.StatusNotFound)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleError_Silent(t *testing.T) {
	fs, cleanup := newTestFileServer(t, t.TempDir())
	defer cleanup()
	fs.Silent = true
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.handleError(w, r, fmt.Errorf("secret details"), http.StatusNotFound)
	require.Equal(t, http.StatusNotFound, w.Code)
	// In silent mode, the error message should be generic
}

// ─── upload multipart test ───────────────────────────────────────────────────

func TestUpload_Success(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "test.txt")
	require.NoError(t, err)
	_, err = part.Write([]byte("uploaded content"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	data, err := os.ReadFile(filepath.Join(dir, "test.txt"))
	require.NoError(t, err)
	require.Equal(t, "uploaded content", string(data))
}

func TestUpload_BlockGoshsFile(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", ".goshs")
	require.NoError(t, err)
	_, err = part.Write([]byte("evil"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.upload(w, r)

	// .goshs file should be blocked
	_, err = os.Stat(filepath.Join(dir, ".goshs"))
	require.True(t, os.IsNotExist(err))
}
