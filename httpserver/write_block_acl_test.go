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

// Regression tests for GHSA-jghp-446c-v7gp: HTTP PUT and multipart upload must
// not overwrite (or create) a name hidden by the .goshs block list, which every
// other access path (GET, DELETE, share, bulk, WebDAV, FTP/SFTP/SMB/TFTP)
// treats as non-existent.

const blockedOriginal = "ORIGINAL hidden content"

func blockListTree(t *testing.T) (root, secret string) {
	t.Helper()
	root = t.TempDir()
	docs := filepath.Join(root, "docs")
	require.NoError(t, os.MkdirAll(filepath.Join(docs, "hidden"), 0755))
	secret = filepath.Join(docs, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte(blockedOriginal), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(docs, ".goshs"), []byte(`{"block":["secret.txt","hidden/"]}`), 0644))
	return root, secret
}

func TestPut_BlockListedFileNotOverwritten(t *testing.T) {
	root, secret := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	r := httptest.NewRequest(http.MethodPut, "/docs/secret.txt", strings.NewReader("ATTACKER"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	got, err := os.ReadFile(secret)
	require.NoError(t, err)
	require.Equal(t, blockedOriginal, string(got))
}

func TestPut_BlockListedNameNotCreated(t *testing.T) {
	root, secret := blockListTree(t)
	require.NoError(t, os.Remove(secret))
	fs, _ := newTestFileServer(t, root)

	r := httptest.NewRequest(http.MethodPut, "/docs/secret.txt", strings.NewReader("ATTACKER"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	_, err := os.Stat(secret)
	require.True(t, os.IsNotExist(err))
}

func TestPut_BlockListedAliasNotOverwritten(t *testing.T) {
	root, secret := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	// Trailing-dot alias (Windows opens it as the real file).
	r := httptest.NewRequest(http.MethodPut, "/docs/SECRET.txt.", strings.NewReader("ATTACKER"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	got, err := os.ReadFile(secret)
	require.NoError(t, err)
	require.Equal(t, blockedOriginal, string(got))
}

func TestPut_NonBlockedSiblingStillWritable(t *testing.T) {
	root, _ := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	r := httptest.NewRequest(http.MethodPut, "/docs/public.txt", strings.NewReader("hello"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	got, err := os.ReadFile(filepath.Join(root, "docs", "public.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

func TestUpload_BlockListedFileNotOverwritten(t *testing.T) {
	root, secret := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	r := nestedUploadRequest(t, "/docs/upload", map[string]string{
		"secret.txt": "ATTACKER",
		"public.txt": "hello",
	})
	w := httptest.NewRecorder()
	fs.upload(w, r)

	got, err := os.ReadFile(secret)
	require.NoError(t, err)
	require.Equal(t, blockedOriginal, string(got))
	// The non-blocked sibling in the same request is still stored.
	got, err = os.ReadFile(filepath.Join(root, "docs", "public.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

func TestUpload_NestedBlockListedFileNotOverwritten(t *testing.T) {
	root, secret := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	// Folder upload from the webroot whose part lands on the blocked file.
	r := nestedUploadRequest(t, "/upload", map[string]string{"docs/secret.txt": "ATTACKER"})
	w := httptest.NewRecorder()
	fs.upload(w, r)

	got, err := os.ReadFile(secret)
	require.NoError(t, err)
	require.Equal(t, blockedOriginal, string(got))
}

func TestUpload_BlockListedFolderNotReplaced(t *testing.T) {
	root, _ := blockListTree(t)
	fs, _ := newTestFileServer(t, root)

	// A file part named like a "name/"-blocked folder must not be renamed
	// over it (os.Rename onto an empty dir would succeed on some platforms).
	r := nestedUploadRequest(t, "/docs/upload", map[string]string{"hidden": "ATTACKER"})
	w := httptest.NewRecorder()
	fs.upload(w, r)

	info, err := os.Stat(filepath.Join(root, "docs", "hidden"))
	require.NoError(t, err)
	require.True(t, info.IsDir())
}
