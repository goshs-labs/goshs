package ftpserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-q8gg-q2wc-w52g (FTP instance): the FTP view of the
// webroot must honour the per-folder .goshs ACL like SFTP does.

func newACLFs(t *testing.T) (*aclFs, string) {
	t.Helper()
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	require.NoError(t, os.Mkdir(secret, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(secret, ".goshs"), []byte(`{"auth":"admin:$2a$04$abcdefghijklmnopqrstuu"}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(secret, "file.txt"), []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{"block":["blocked.txt"]}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "blocked.txt"), []byte("BLOCKED"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "public.txt"), []byte("public"), 0644))

	srv := &FTPServer{Root: root}
	return srv.withACL(afero.NewBasePathFs(afero.NewOsFs(), root)).(*aclFs), root
}

func TestACLFs_DeniesProtectedReads(t *testing.T) {
	fs, _ := newACLFs(t)
	for _, name := range []string{"/secret/file.txt", "/secret/.goshs", "/.goshs", "/blocked.txt", "/BLOCKED.TXT", "/secret"} {
		_, err := fs.OpenFile(name, os.O_RDONLY, 0)
		require.Error(t, err, name)
		_, err = fs.Stat(name)
		require.Error(t, err, name)
	}
	_, err := fs.ReadDir("/secret")
	require.Error(t, err)

	f, err := fs.OpenFile("/public.txt", os.O_RDONLY, 0)
	require.NoError(t, err, "unprotected file must stay readable")
	f.Close()
}

func TestACLFs_DeniesProtectedWrites(t *testing.T) {
	fs, root := newACLFs(t)
	_, err := fs.Create("/secret/new.txt")
	require.Error(t, err)
	_, err = fs.Create("/secret/.goshs")
	require.Error(t, err)
	require.Error(t, fs.Mkdir("/poison/.goshs", 0755))
	require.Error(t, fs.Remove("/secret/.goshs"))
	require.Error(t, fs.Rename("/public.txt", "/secret/public.txt"))
	require.Error(t, fs.Rename("/secret/file.txt", "/stolen.txt"))

	got, err := os.ReadFile(filepath.Join(root, "secret", ".goshs"))
	require.NoError(t, err)
	require.Contains(t, string(got), "admin:")
}

func TestACLFs_ReadDirFiltersListing(t *testing.T) {
	fs, _ := newACLFs(t)
	infos, err := fs.ReadDir("/")
	require.NoError(t, err)
	var names []string
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	require.Equal(t, []string{"public.txt"}, names)
}

// GHSA-rf62-vgq5-ggq5: RemoveAll of the webroot (an unprotected ancestor of
// secret/) must not destroy the auth-protected subtree.
func TestACLFs_RemoveAllAncestorOfProtectedDenied(t *testing.T) {
	fs, root := newACLFs(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a"), 0755))
	require.NoError(t, os.Rename(filepath.Join(root, "secret"), filepath.Join(root, "a", "secret")))

	require.ErrorIs(t, fs.RemoveAll("/a"), errACLDenied)
	require.FileExists(t, filepath.Join(root, "a", "secret", "file.txt"))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain", "sub"), 0755))
	require.NoError(t, fs.RemoveAll("/plain"))
	require.NoDirExists(t, filepath.Join(root, "plain"))
}

// GHSA-95fx-g5c4-6f8f: RNFR/RNTO of a directory must not move a block-listed
// file out of the .goshs scope that hides it.
func TestACLFs_RenameOutOfBlockScopeDenied(t *testing.T) {
	fs, root := newACLFs(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pub", "sub"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pub", ".goshs"), []byte(`{"block":["flag.txt"]}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pub", "sub", "flag.txt"), []byte("FLAG"), 0644))

	require.ErrorIs(t, fs.Rename("/pub/sub", "/moved"), errACLDenied)
	require.FileExists(t, filepath.Join(root, "pub", "sub", "flag.txt"))

	require.NoError(t, fs.Rename("/pub/sub", "/pub/sub2"))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain"), 0755))
	require.NoError(t, fs.Rename("/plain", "/plain2"))
}
