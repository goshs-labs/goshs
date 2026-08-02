package ftpserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/options"
)

// newBaseFs returns a BasePathFs rooted at a temp dir, matching what AuthUser
// hands to the wrappers, plus the on-disk root so tests can inspect it.
func newBaseFs(t *testing.T) (afero.Fs, string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "existing.txt"), []byte("ORIGINAL"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "secret.txt"), []byte("TOP-SECRET"), 0o644))
	return afero.NewBasePathFs(afero.NewOsFs(), root), root
}

// ─── Option wiring (GHSA-6wwv-mx7w-35jx) ────────────────────────────────────

func TestNewFTPServer_MapsUploadOnly(t *testing.T) {
	opts := &options.Options{UploadOnly: true, NoDelete: true, ReadOnly: false}
	srv := NewFTPServer(opts, nil, nil)
	require.True(t, srv.UploadOnly, "UploadOnly must be copied from opts")
	require.True(t, srv.NoDelete)
	require.False(t, srv.ReadOnly)
}

// ─── uploadOnlyFs: no read-back of files ────────────────────────────────────

func TestUploadOnlyFs_BlocksDownloadOpenFile(t *testing.T) {
	base, _ := newBaseFs(t)
	fs := &uploadOnlyFs{Fs: base}

	// RETR path: driver opens with O_RDONLY.
	_, err := fs.OpenFile("secret.txt", os.O_RDONLY, 0)
	require.Error(t, err, "read-back via OpenFile(O_RDONLY) must be denied in upload-only mode")
}

func TestUploadOnlyFs_BlocksDownloadOpen(t *testing.T) {
	base, _ := newBaseFs(t)
	fs := &uploadOnlyFs{Fs: base}

	_, err := fs.Open("secret.txt")
	require.Error(t, err, "opening a regular file for reading must be denied")
}

func TestUploadOnlyFs_AllowsUpload(t *testing.T) {
	base, root := newBaseFs(t)
	fs := &uploadOnlyFs{Fs: base}

	f, err := fs.OpenFile("new.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err, "STOR (O_WRONLY|O_CREATE|O_TRUNC) must be allowed")
	_, err = f.Write([]byte("UPLOAD"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	got, err := os.ReadFile(filepath.Join(root, "new.txt"))
	require.NoError(t, err)
	require.Equal(t, "UPLOAD", string(got))
}

func TestUploadOnlyFs_AllowsDirectoryListing(t *testing.T) {
	base, _ := newBaseFs(t)
	fs := &uploadOnlyFs{Fs: base}

	dir, err := fs.Open("/")
	require.NoError(t, err, "listing the root directory must stay possible in upload-only mode")
	names, err := dir.Readdirnames(-1)
	require.NoError(t, err)
	require.Contains(t, names, "existing.txt")
	require.NoError(t, dir.Close())
}

// ─── noDeleteFs: existing content is protected ──────────────────────────────

func TestNoDeleteFs_BlocksRemove(t *testing.T) {
	base, _ := newBaseFs(t)
	fs := &noDeleteFs{Fs: base}

	require.Error(t, fs.Remove("existing.txt"))
	require.Error(t, fs.RemoveAll("existing.txt"))
}

func TestNoDeleteFs_BlocksRename(t *testing.T) {
	base, root := newBaseFs(t)
	fs := &noDeleteFs{Fs: base}

	// RNFR/RNTO path: a rename would move the file away from its path.
	require.Error(t, fs.Rename("existing.txt", "renamed.txt"))

	_, err := os.Stat(filepath.Join(root, "existing.txt"))
	require.NoError(t, err, "existing.txt must still be present after a blocked rename")
	_, err = os.Stat(filepath.Join(root, "renamed.txt"))
	require.True(t, os.IsNotExist(err), "renamed.txt must not have been created")
}

func TestNoDeleteFs_BlocksTruncatingOverwrite(t *testing.T) {
	base, root := newBaseFs(t)
	fs := &noDeleteFs{Fs: base}

	// Truncating STOR over an existing file.
	_, err := fs.OpenFile("existing.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.Error(t, err, "truncating overwrite of an existing file must be denied")

	// Create also implies truncation.
	_, err = fs.Create("existing.txt")
	require.Error(t, err, "Create over an existing file must be denied")

	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL", string(got), "original contents must be intact")
}

func TestNoDeleteFs_AllowsNewFileAndAppend(t *testing.T) {
	base, root := newBaseFs(t)
	fs := &noDeleteFs{Fs: base}

	// New file (O_TRUNC but target does not exist) is allowed.
	f, err := fs.OpenFile("brand-new.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Append to an existing file preserves its content, so it is allowed.
	af, err := fs.OpenFile("existing.txt", os.O_WRONLY|os.O_APPEND, 0o644)
	require.NoError(t, err, "append must be allowed since it does not destroy content")
	_, err = af.Write([]byte("-MORE"))
	require.NoError(t, err)
	require.NoError(t, af.Close())

	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL-MORE", string(got))
}

// ─── Combined upload-only + no-delete stacking ──────────────────────────────

func TestUploadOnlyAndNoDelete_Stack(t *testing.T) {
	base, root := newBaseFs(t)
	// Same order as AuthUser: no-delete inner, upload-only outer.
	fs := &uploadOnlyFs{Fs: &noDeleteFs{Fs: base}}

	// Read-back still blocked by upload-only.
	_, err := fs.OpenFile("secret.txt", os.O_RDONLY, 0)
	require.Error(t, err)

	// Truncating overwrite still blocked by the inner no-delete wrapper.
	_, err = fs.OpenFile("existing.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.Error(t, err)

	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL", string(got))
}
