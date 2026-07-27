package httpserver

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// blockTree builds a webroot with a "blocked" directory whose .goshs ACL blocks
// "secret.txt". The ACL is block-only (no auth), which is the configuration the
// trailing-slash bypass affects.
func blockTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blocked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "secret.txt"), []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))
	return dir
}

// Regression for the trailing-slash bypass in sendFile: a blocked file must stay
// blocked whether or not the request path carries a trailing slash. Before the
// fix, sendFile derived the guard name from the raw req.URL.Path, so a trailing
// slash produced an empty name that matched neither ".goshs" nor the block list.
func TestSendFile_TrailingSlash_BlockedFile(t *testing.T) {
	fs, cleanup := newTestFileServer(t, blockTree(t))
	defer cleanup()

	cases := []struct {
		name string
		path string
	}{
		{"control-no-slash", "/blocked/secret.txt"},
		{"trailing-slash", "/blocked/secret.txt/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			fs.handler(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.NotContains(t, w.Body.String(), "TOP-SECRET")
		})
	}
}

// The .goshs ACL file itself must never be served, again regardless of a trailing
// slash. Before the fix, /blocked/.goshs/ returned the ACL file (including any
// bcrypt hash) with 200.
func TestSendFile_TrailingSlash_ACLFileNeverServed(t *testing.T) {
	fs, cleanup := newTestFileServer(t, blockTree(t))
	defer cleanup()

	for _, path := range []string{"/blocked/.goshs", "/blocked/.goshs/"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			fs.handler(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			// The ACL file's own JSON must never appear in the response body.
			require.NotContains(t, w.Body.String(), `"block":[`)
		})
	}
}

// multipartUpload builds a multipart/form-data body with a single file part whose
// declared filename is filename, returning the body and its Content-Type header.
func multipartUpload(t *testing.T, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	// Write the Content-Disposition by hand so the raw filename (e.g. "..") is
	// preserved instead of being escaped by CreateFormFile's quoting helper.
	part, err := mw.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="files"; filename="` + filename + `"`},
	})
	require.NoError(t, err)
	_, err = part.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return body, mw.FormDataContentType()
}

// Regression for the residual upload traversal (CVE-2026-35393 follow-up): an
// upload whose filename is ".." must be rejected, not written to the parent of
// the served tree. Before the fix, filepath.Join(targetDir, "..")+"~" landed a
// file outside the webroot.
func TestUpload_DotDotFilename_NoEscape(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	escape := filepath.Join(webroot, "..") + "~"
	// Clean up any stray artifact even if the test fails.
	t.Cleanup(func() { _ = os.Remove(escape) })

	body, ctype := multipartUpload(t, "..", "ESCAPED_WRITE_PROOF")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(escape)
	require.Truef(t, os.IsNotExist(err), "file escaped the webroot at %s", escape)
}

// A normal upload must still succeed after the traversal hardening.
func TestUpload_ValidFilename_Succeeds(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, "good.txt", "hello")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "good.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}
