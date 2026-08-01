package httpserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// Regression for GHSA-mqvv-v9g7-4h3j: the single-file ?share redemption path
// passed an empty configFile{} to sendFile, so neither the per-directory block
// list nor the per-directory basic auth was evaluated and a protected file was
// streamed out to anyone holding the token. These tests assert the ACL is now
// enforced on redemption and that a token cannot even be minted for a path the
// caller is not allowed to read.

// shareAuthTree builds a webroot with a block-listed file and an auth-protected
// file, returning the webroot path.
func shareAuthTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Block-list ACL.
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blocked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "secret.txt"), []byte("BLOCKED-CONTENTS"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "ok.txt"), []byte("public"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))

	// Per-directory auth ACL.
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.Mkdir(secret, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "file.txt"), []byte("AUTH-CONTENTS"), 0644))
	hash, err := bcrypt.GenerateFromPassword([]byte("subpass"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(secret, ".goshs"),
		[]byte(fmt.Sprintf(`{"auth":"subuser:%s"}`, hash)), 0644))

	return dir
}

// ─── Redemption enforces the ACL ──────────────────────────────────────────────

// A token minted (or forged) for a block-listed file must 404 on redemption and
// must not leak the file contents.
func TestShareHandler_BlockedFile_RedemptionEnforcesBlock(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.SharedLinks["tok"] = SharedLink{
		FilePath:      "/blocked/secret.txt",
		IsDir:         false,
		Expires:       time.Now().Add(time.Hour),
		DownloadLimit: 5,
	}

	r := httptest.NewRequest(http.MethodGet, "/blocked/secret.txt?token=tok", nil)
	w := httptest.NewRecorder()
	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), "BLOCKED-CONTENTS")
}

// A token for an auth-protected file must 401 on redemption when no credentials
// are supplied, instead of streaming the file unauthenticated.
func TestShareHandler_AuthFile_RedemptionEnforcesAuth(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.SharedLinks["tok"] = SharedLink{
		FilePath:      "/secret/file.txt",
		IsDir:         false,
		Expires:       time.Now().Add(time.Hour),
		DownloadLimit: 5,
	}

	r := httptest.NewRequest(http.MethodGet, "/secret/file.txt?token=tok", nil)
	w := httptest.NewRecorder()
	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.NotContains(t, w.Body.String(), "AUTH-CONTENTS")
}

// A token for an unrestricted file must still be redeemable — the fix must not
// break legitimate single-file shares.
func TestShareHandler_PublicFile_StillServed(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.SharedLinks["tok"] = SharedLink{
		FilePath:      "/blocked/ok.txt",
		IsDir:         false,
		Expires:       time.Now().Add(time.Hour),
		DownloadLimit: 5,
	}

	r := httptest.NewRequest(http.MethodGet, "/blocked/ok.txt?token=tok", nil)
	w := httptest.NewRecorder()
	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public", w.Body.String())
}

// ─── Minting refuses paths the caller cannot read ─────────────────────────────

// Minting a share for a block-listed file must fail and must not store a token.
func TestCreateShareHandler_BlockedFile_NotMinted(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.Pass = "globalpass"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/blocked/secret.txt?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Empty(t, fs.SharedLinks)
}

// Minting a share for an auth-protected file without the sub-credential must fail
// and must not store a token.
func TestCreateShareHandler_AuthFile_NotMinted(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.Pass = "globalpass"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/secret/file.txt?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Empty(t, fs.SharedLinks)
}

// Minting a share for an unrestricted file must still succeed.
func TestCreateShareHandler_PublicFile_StillMinted(t *testing.T) {
	fs, cleanup := newTestFileServer(t, shareAuthTree(t))
	defer cleanup()
	fs.Pass = "globalpass"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/blocked/ok.txt?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, fs.SharedLinks, 1)
}
