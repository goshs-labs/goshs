package httpserver

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// ─── AddCertAuth ──────────────────────────────────────────────────────────────

func TestAddCertAuth(t *testing.T) {
	// Use the integration test ca.crt
	certPath := filepath.Join("..", "integration", "certs", "ca.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Skip("ca.crt not available")
	}

	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.CACert = certPath

	srv := &http.Server{TLSConfig: &tls.Config{}}
	fs.AddCertAuth(srv)

	require.NotNil(t, srv.TLSConfig.ClientCAs)
	require.Equal(t, tls.RequireAndVerifyClientCert, srv.TLSConfig.ClientAuth)
}

// ─── logStart ─────────────────────────────────────────────────────────────────

func TestLogStart_WebHTTP(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8080
	fs.SSL = false

	// Just verify it doesn't panic
	fs.logStart(modeWeb)
}

func TestLogStart_WebHTTP_AllInterfaces(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "0.0.0.0"
	fs.Port = 8080
	fs.SSL = false

	fs.logStart(modeWeb)
}

func TestLogStart_WebHTTPS_SelfSigned(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8443
	fs.SSL = true
	fs.SelfSigned = true
	fs.Fingerprint256 = "AA:BB"
	fs.Fingerprint1 = "CC:DD"

	fs.logStart(modeWeb)
}

func TestLogStart_WebHTTPS_ProvidedCert(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.Port = 8443
	fs.SSL = true
	fs.SelfSigned = false
	fs.MyKey = "server.key"
	fs.MyCert = "server.crt"
	fs.MyP12 = "server.p12"
	fs.Fingerprint256 = "AA:BB"
	fs.Fingerprint1 = "CC:DD"

	fs.logStart(modeWeb)
}

func TestLogStart_WebdavHTTP(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.WebdavPort = 8081
	fs.SSL = false

	fs.logStart("webdav")
}

func TestLogStart_WebdavHTTPS_SelfSigned(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.WebdavPort = 8444
	fs.SSL = true
	fs.SelfSigned = true
	fs.Fingerprint256 = "AA:BB"
	fs.Fingerprint1 = "CC:DD"

	fs.logStart("webdav")
}

func TestLogStart_WebdavHTTPS_ProvidedCert(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.IP = "127.0.0.1"
	fs.WebdavPort = 8444
	fs.SSL = true
	fs.SelfSigned = false
	fs.MyKey = "server.key"
	fs.MyCert = "server.crt"
	fs.Fingerprint256 = "AA:BB"
	fs.Fingerprint1 = "CC:DD"

	fs.logStart("webdav")
}

func TestLogStart_Default(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	// Default case (neither modeWeb nor "webdav")
	fs.logStart("other")
}

// ─── DeleteShareHandler no token ──────────────────────────────────────────────

func TestDeleteShareHandler_NoToken(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()

	fs.DeleteShareHandler(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// ─── sendFile with ACL auth download ──────────────────────────────────────────

func TestSendFile_ACLAuth_Download(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "download_me.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("download content"), 0644))

	// Create a file server with an in-process hub
	cb := chat.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()
	wh := webhook.Register(false, "", "discord", []string{})

	fs2 := &FileServer{
		Webroot:      dir,
		UploadFolder: dir,
		CSRFToken:    "test-csrf",
		Hub:          hub,
		Chat:         cb,
		Webhook:      *wh,
		SharedLinks:  map[string]SharedLink{},
		Version:      "test",
		Whitelist:    &Whitelist{},
	}

	f, err := os.Open(testFile)
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/download_me.txt?download", nil)
	w := httptest.NewRecorder()

	fs2.sendFile(w, r, f, configFile{})

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
}

func TestSendFile_ACLAuth_Unauthorized(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(dir, "protected.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("secret"), 0644))

	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(testFile)
	require.NoError(t, err)
	defer f.Close()

	acl := configFile{Auth: "admin:$2a$10$invalidhash"}

	r := httptest.NewRequest(http.MethodGet, "/protected.txt", nil)
	w := httptest.NewRecorder()

	fs.sendFile(w, r, f, acl)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// ─── doFile ───────────────────────────────────────────────────────────────────

func TestDoFile(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	testFile := filepath.Join(dir, "regular.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0644))

	f, err := os.Open(testFile)
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/regular.txt", nil)
	w := httptest.NewRecorder()

	fs.doFile(f, w, r)

	require.Equal(t, http.StatusOK, w.Code)
}
