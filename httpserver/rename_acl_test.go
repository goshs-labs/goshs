package httpserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-95fx-g5c4-6f8f: a rename checked only the two
// addressed paths, but block entries (and inherited auth) are declared in an
// ancestor .goshs and resolved upwards, so moving the directory that holds a
// block-listed file out of that scope served the file at its new path.

// renameTree builds pub/.goshs {"block":["flag.txt"]} over pub/sub/{flag,open}.txt.
func renameTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sub := filepath.Join(root, "pub", "sub")
	require.NoError(t, os.MkdirAll(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pub", ".goshs"), []byte(`{"block":["flag.txt"]}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "flag.txt"), []byte("BLOCKED-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "open.txt"), []byte("ordinary"), 0644))
	return root
}

func TestRenameACL_WebDAVMoveOutOfBlockScopeDenied(t *testing.T) {
	root := renameTree(t)
	fs, _ := newTestFileServer(t, root)
	h := newWebdavTestHandler(fs)

	w := davReq(t, h, "MOVE", "/pub/sub", "/moved", "")
	require.Equal(t, http.StatusForbidden, w.Code)
	require.FileExists(t, filepath.Join(root, "pub", "sub", "flag.txt"))
	require.NoDirExists(t, filepath.Join(root, "moved"))
}

func TestRenameACL_WebDAVMoveWithinScopeAllowed(t *testing.T) {
	root := renameTree(t)
	fs, _ := newTestFileServer(t, root)
	h := newWebdavTestHandler(fs)

	w := davReq(t, h, "MOVE", "/pub/sub", "/pub/sub2", "")
	require.Equal(t, http.StatusCreated, w.Code)
	require.FileExists(t, filepath.Join(root, "pub", "sub2", "flag.txt"))

	// A destination scope with the same block entry also keeps it hidden.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "other", ".goshs"), []byte(`{"block":["FLAG.TXT"]}`), 0644))
	w = davReq(t, h, "MOVE", "/pub/sub2", "/other/sub", "")
	require.Equal(t, http.StatusCreated, w.Code)
	require.FileExists(t, filepath.Join(root, "other", "sub", "flag.txt"))
}

func TestRenameACL_WebDAVMoveCleanDirAllowed(t *testing.T) {
	root := renameTree(t)
	fs, _ := newTestFileServer(t, root)
	h := newWebdavTestHandler(fs)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain", "x"), 0755))

	w := davReq(t, h, "MOVE", "/plain", "/plain2", "")
	require.Equal(t, http.StatusCreated, w.Code)
	require.DirExists(t, filepath.Join(root, "plain2", "x"))
}

// A directory hidden via the "name/" convention would shed that entry by being
// renamed, even inside its scope.
func TestRenameACL_BlockListedDirNotRenamable(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "secret"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "secret", "x.txt"), []byte("x"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{"block":["secret/"]}`), 0644))
	p := NewProtocolACL(root)
	require.False(t, p.RenameAllowed(filepath.Join(root, "secret"), filepath.Join(root, "public")))
}

// Credential-less protocols: an inner auth .goshs travels with the subtree, so
// moving its unprotected ancestor is fine; an inherited block entry is not.
func TestRenameACL_ProtocolRenameAllowed(t *testing.T) {
	root := deepACLTree(t)
	p := NewProtocolACL(root)
	require.True(t, p.RenameAllowed(filepath.Join(root, "a"), filepath.Join(root, "z")))

	root = renameTree(t)
	p = NewProtocolACL(root)
	require.False(t, p.RenameAllowed(filepath.Join(root, "pub", "sub"), filepath.Join(root, "moved")))
	require.True(t, p.RenameAllowed(filepath.Join(root, "pub", "sub"), filepath.Join(root, "pub", "sub2")))
	require.True(t, p.RenameAllowed(filepath.Join(root, "pub", "sub", "open.txt"), filepath.Join(root, "open.txt")))
}

// Regression tests for GHSA-8v6q-gvgc-m3vq / GHSA-fqxq-xh82-pcgh: the create-side
// .goshs guards compared the exact spelling, while Windows opens ".goshs." and
// ".goshs " as the real ACL file, so an anonymous PUT/upload replaced it.

func TestPut_GoshsAlias_Blocked(t *testing.T) {
	for _, name := range []string{".goshs.", ".goshs ", ".GOSHS..", ".goshs. ."} {
		webroot := t.TempDir()
		fs, cleanup := newTestFileServer(t, webroot)
		r := httptest.NewRequest(http.MethodPut, "/x", bytes.NewBufferString(`{"block":[]}`))
		r.URL.Path = "/" + name
		r.Header.Set("X-CSRF-Token", "test-csrf")
		w := httptest.NewRecorder()
		fs.put(w, r)
		cleanup()
		require.Equal(t, http.StatusForbidden, w.Code, name)
		_, err := os.Stat(filepath.Join(webroot, name))
		require.Truef(t, os.IsNotExist(err), "PUT %q must not create a file", name)
	}
}

func TestUpload_GoshsAlias_Blocked(t *testing.T) {
	for _, name := range []string{".goshs.", ".goshs ", "sub/.goshs./x.txt"} {
		webroot := t.TempDir()
		fs, cleanup := newTestFileServer(t, webroot)
		body, ctype := multipartUpload(t, name, `{"block":[]}`)
		r := httptest.NewRequest(http.MethodPost, "/upload", body)
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("X-CSRF-Token", "test-csrf")
		fs.upload(httptest.NewRecorder(), r)
		cleanup()
		_, err := os.Stat(filepath.Join(webroot, name))
		require.Truef(t, os.IsNotExist(err), "upload of %q must be blocked", name)
	}
}

func TestDelete_GoshsAlias_Blocked(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	require.NoError(t, os.WriteFile(filepath.Join(webroot, ".goshs."), []byte(`{}`), 0644))

	r := deleteReq("/x")
	r.URL.Path = "/.goshs."
	w := httptest.NewRecorder()
	fs.deleteFile(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.FileExists(t, filepath.Join(webroot, ".goshs."))
}

func TestContainsACLName_Aliases(t *testing.T) {
	for _, p := range []string{".goshs", ".GOSHS", ".goshs.", ".goshs ", "a/.goshs./b", "a/.goshs /b"} {
		require.True(t, containsACLName(p), p)
	}
	for _, p := range []string{"goshs", ".goshs-chat", "a/.goshsx/b", ".goshs.bak"} {
		require.False(t, containsACLName(p), p)
	}
	p := NewProtocolACL(t.TempDir())
	require.False(t, p.Allowed(filepath.Join(p.fs.Webroot, "d", ".goshs.", "f")))
}
