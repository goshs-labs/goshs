package httpserver

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// nextHandler is a trivial next handler that records whether it was called.
func nextHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func basicAuthHeader(user, pass string) string {
	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + creds
}

func newFS(user, pass string) *FileServer {
	return &FileServer{
		User:        user,
		Pass:        pass,
		SharedLinks: map[string]SharedLink{},
		authCache:   make(map[string]time.Time),
	}
}

// After a lockout has elapsed, a valid login must be accepted (and clear the
// failure record) rather than remaining blocked.
func TestVerifyCredentials_ValidLoginAfterLockoutExpiry(t *testing.T) {
	fs := newFS("user", "pass")
	fs.authFailures = map[string]*authFailEntry{
		"192.0.2.1": {count: authMaxFailures, lockedUntil: time.Now().Add(-time.Second)},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	_, ok := fs.verifyCredentials(r)

	require.True(t, ok, "valid login after lockout expiry must succeed")
	require.NotContains(t, fs.authFailures, "192.0.2.1", "successful login clears the failure record")
}

// A single failed attempt after a lockout has elapsed must NOT immediately
// re-lock the client: the counter must have been reset to zero first.
func TestVerifyCredentials_FailureAfterLockoutExpiryDoesNotRelock(t *testing.T) {
	fs := newFS("user", "pass")
	fs.authFailures = map[string]*authFailEntry{
		"192.0.2.1": {count: authMaxFailures, lockedUntil: time.Now().Add(-time.Second)},
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "wrongpass"))
	_, ok := fs.verifyCredentials(r)

	require.False(t, ok)
	entry := fs.authFailures["192.0.2.1"]
	require.NotNil(t, entry)
	require.Equal(t, 1, entry.count, "counter should reset after lockout expiry, then count this failure as the first")
	require.True(t, entry.lockedUntil.IsZero(), "a single post-expiry failure must not re-lock")
}

func TestBasicAuthMiddleware_NoAuthHeader(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_WrongCredentials(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "wrongpass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_CorrectPlainText(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_WrongUser(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("wronguser", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_CorrectBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_WrongBcryptPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "wrongsecret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_ValidToken(t *testing.T) {
	fs := newFS("user", "pass")
	fs.SharedLinks["mytoken"] = SharedLink{}
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/?token=mytoken", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_InvalidToken(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/?token=badtoken", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// Token not in SharedLinks — falls through to auth check, no credentials → 401
	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServerHeaderMiddleware_SetsHeader(t *testing.T) {
	fs := &FileServer{Version: "v2.0.0-test", Invisible: false}
	called := false
	handler := fs.ServerHeaderMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	expected := fmt.Sprintf("goshs/v2.0.0-test (%s; %s)", runtime.GOOS, runtime.Version())
	require.Equal(t, expected, w.Header().Get("Server"))
}

func TestServerHeaderMiddleware_Invisible(t *testing.T) {
	fs := &FileServer{Version: "v2.0.0-test", Invisible: true}
	called := false
	handler := fs.ServerHeaderMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Empty(t, w.Header().Get("Server"), "invisible mode should not set Server header")
}

// ─── InvisibleBasicAuthMiddleware ─────────────────────────────────────────────

func TestInvisibleBasicAuth_NoAuthHeader(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// handleInvisible returns early (Recorder doesn't implement Hijacker) — next NOT called
	require.False(t, called)
}

func TestInvisibleBasicAuth_WrongPlainPassword(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "wrong"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
}

func TestInvisibleBasicAuth_WrongPlainUsername(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("evil", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
}

func TestInvisibleBasicAuth_CorrectPlain(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
}

func TestInvisibleBasicAuth_CorrectPlainCached(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	// First call populates the cache
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	handler.ServeHTTP(httptest.NewRecorder(), r)

	// Second call hits the cache
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)

	require.True(t, called)
}

func TestInvisibleBasicAuth_CorrectBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
}

func TestInvisibleBasicAuth_WrongBcryptPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "wrong"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
}

func TestInvisibleBasicAuth_WrongBcryptUsername(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("baduser", "secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
}

// ─── ConPtyShell.ps1 auth exemption scope (GHSA-6m5c-fv2q-jrj2) ───────────────
//
// The unauthenticated exemption for catcher upgrades must cover ONLY a GET/HEAD
// of /ConPtyShell.ps1 whose sole query parameter is `conpty`. Any other method
// or any extra feature key must fall through to the auth check, or an
// unauthenticated attacker reaches the full authenticated API surface (webroot
// read via ?bulk, ?goshs-info, ?ws, ?catcher-api, PUT/DELETE writes, …).

// The genuine upgrade URL generated by the Web UI / TUI must still be served
// without credentials.
func TestBasicAuthMiddleware_ConPtyExemptGET(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/ConPtyShell.ps1?conpty", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called, "genuine GET /ConPtyShell.ps1?conpty must be exempt")
	require.Equal(t, http.StatusOK, w.Code)
}

// HEAD of the upgrade URL is equally harmless and stays exempt.
func TestBasicAuthMiddleware_ConPtyExemptHEAD(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodHead, "/ConPtyShell.ps1?conpty", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

// A non-GET/HEAD method must NOT ride the exemption: PUT/DELETE/POST on the
// exempt path would otherwise write or delete files unauthenticated.
func TestBasicAuthMiddleware_ConPtyRejectsWriteMethods(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			fs := newFS("user", "pass")
			called := false
			handler := fs.BasicAuthMiddleware(nextHandler(&called))

			r := httptest.NewRequest(method, "/ConPtyShell.ps1?conpty", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			require.False(t, called, method+" must not be exempt")
			require.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// Smuggling any additional feature parameter alongside `conpty` must break the
// exemption, so the request is authenticated like any other.
func TestBasicAuthMiddleware_ConPtyRejectsExtraFeatureKeys(t *testing.T) {
	extras := []string{
		"/ConPtyShell.ps1?conpty&bulk&file=/",
		"/ConPtyShell.ps1?conpty&goshs-info",
		"/ConPtyShell.ps1?conpty&ws",
		"/ConPtyShell.ps1?conpty&catcher-api=list",
		"/ConPtyShell.ps1?conpty&chatDown",
		"/ConPtyShell.ps1?conpty&embedded",
	}
	for _, target := range extras {
		t.Run(target, func(t *testing.T) {
			fs := newFS("user", "pass")
			called := false
			handler := fs.BasicAuthMiddleware(nextHandler(&called))

			r := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			require.False(t, called, "extra feature key must void the exemption: "+target)
			require.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// `conpty` on a different path must not be exempt.
func TestBasicAuthMiddleware_ConPtyRejectsOtherPaths(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/secret.txt?conpty", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// The same scoping must hold for invisible mode, whose exemption block is
// identical. A blocked request calls handleInvisible (a no-op on the recorder),
// so `next` is never reached.
func TestInvisibleBasicAuth_ConPtyExemptGET(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/ConPtyShell.ps1?conpty", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called, "genuine GET /ConPtyShell.ps1?conpty must be exempt in invisible mode")
}

func TestInvisibleBasicAuth_ConPtyRejectsWriteAndExtras(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
	}{
		{"PUT", http.MethodPut, "/ConPtyShell.ps1?conpty"},
		{"DELETE", http.MethodDelete, "/ConPtyShell.ps1?conpty"},
		{"bulk", http.MethodGet, "/ConPtyShell.ps1?conpty&bulk&file=/"},
		{"ws", http.MethodGet, "/ConPtyShell.ps1?conpty&ws"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFS("user", "pass")
			called := false
			handler := fs.InvisibleBasicAuthMiddleware(nextHandler(&called))

			r := httptest.NewRequest(tc.method, tc.target, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			require.False(t, called, "must not be exempt in invisible mode: "+tc.target)
		})
	}
}
