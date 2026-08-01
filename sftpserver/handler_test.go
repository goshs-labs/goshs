package sftpserver

import (
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
)

func testSFTPServer(root string) *SFTPServer {
	wh := webhook.Register(false, "", "discord", []string{})
	return &SFTPServer{
		IP:        "0.0.0.0",
		Port:      2022,
		Root:      root,
		Webhook:   *wh,
		Whitelist: &httpserver.Whitelist{},
	}
}

// ─── ReadOnlyHandler ──────────────────────────────────────────────────────────

func TestReadOnlyHandler_GetHandler(t *testing.T) {
	h := &ReadOnlyHandler{Root: "/tmp", ClientIP: "1.2.3.4", SFTPServer: testSFTPServer("/tmp")}
	handlers := h.GetHandler()
	require.NotNil(t, handlers.FileGet)
	require.NotNil(t, handlers.FilePut)
	require.NotNil(t, handlers.FileCmd)
	require.NotNil(t, handlers.FileList)
}

func TestReadOnlyHandler_Fileread(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	srv := testSFTPServer(dir)
	h := &ReadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Get", Filepath: "/test.txt"}
	reader, err := h.Fileread(r)
	require.NoError(t, err)
	require.NotNil(t, reader)
}

func TestReadOnlyHandler_Filewrite_Blocked(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &ReadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Put", Filepath: "/test.txt"}
	_, err := h.Filewrite(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read-only")
}

func TestReadOnlyHandler_Filelist(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	srv := testSFTPServer(dir)
	h := &ReadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "List", Filepath: "/"}
	lister, err := h.Filelist(r)
	require.NoError(t, err)
	require.NotNil(t, lister)
}

func TestReadOnlyHandler_Filecmd_Blocked(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &ReadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Remove", Filepath: "/test.txt"}
	err := h.Filecmd(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "read-only")
}

// ─── UploadOnlyHandler ────────────────────────────────────────────────────────

func TestUploadOnlyHandler_GetHandler(t *testing.T) {
	h := &UploadOnlyHandler{Root: "/tmp", ClientIP: "1.2.3.4", SFTPServer: testSFTPServer("/tmp")}
	handlers := h.GetHandler()
	require.NotNil(t, handlers.FileGet)
	require.NotNil(t, handlers.FilePut)
}

func TestUploadOnlyHandler_Fileread_Blocked(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &UploadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Get", Filepath: "/test.txt"}
	_, err := h.Fileread(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "upload-only")
}

func TestUploadOnlyHandler_Filewrite(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &UploadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Put", Filepath: "/upload.txt"}
	writer, err := h.Filewrite(r)
	require.NoError(t, err)
	require.NotNil(t, writer)
}

func TestUploadOnlyHandler_Filelist(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	srv := testSFTPServer(dir)
	h := &UploadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "List", Filepath: "/"}
	lister, err := h.Filelist(r)
	require.NoError(t, err)
	require.NotNil(t, lister)
}

func TestUploadOnlyHandler_Filecmd_Blocked(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &UploadOnlyHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Remove", Filepath: "/test.txt"}
	err := h.Filecmd(r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "upload-only")
}

// ─── DefaultHandler ───────────────────────────────────────────────────────────

func TestDefaultHandler_GetHandler(t *testing.T) {
	h := &DefaultHandler{Root: "/tmp", ClientIP: "1.2.3.4", SFTPServer: testSFTPServer("/tmp")}
	handlers := h.GetHandler()
	require.NotNil(t, handlers.FileGet)
	require.NotNil(t, handlers.FilePut)
	require.NotNil(t, handlers.FileCmd)
	require.NotNil(t, handlers.FileList)
}

func TestDefaultHandler_Fileread(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644))
	srv := testSFTPServer(dir)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Get", Filepath: "/test.txt"}
	reader, err := h.Fileread(r)
	require.NoError(t, err)
	require.NotNil(t, reader)
}

func TestDefaultHandler_Filewrite(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "Put", Filepath: "/upload.txt"}
	writer, err := h.Filewrite(r)
	require.NoError(t, err)
	require.NotNil(t, writer)
}

func TestDefaultHandler_Filelist(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	srv := testSFTPServer(dir)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	r := &sftp.Request{Method: "List", Filepath: "/"}
	lister, err := h.Filelist(r)
	require.NoError(t, err)
	require.NotNil(t, lister)
}

func TestDefaultHandler_Filecmd(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: srv}

	// Mkdir
	r := &sftp.Request{Method: "Mkdir", Filepath: "/subdir"}
	require.NoError(t, h.Filecmd(r))
	require.DirExists(t, filepath.Join(dir, "subdir"))

	// Create a file in subdir
	require.NoError(t, os.WriteFile(filepath.Join(dir, "subdir", "f.txt"), []byte("x"), 0644))

	// Rename
	r = &sftp.Request{Method: "Rename", Filepath: "/subdir/f.txt", Target: "/subdir/g.txt"}
	require.NoError(t, h.Filecmd(r))

	// Stat
	r = &sftp.Request{Method: "Stat", Filepath: "/subdir/g.txt"}
	require.NoError(t, h.Filecmd(r))

	// Lstat
	r = &sftp.Request{Method: "Lstat", Filepath: "/subdir/g.txt"}
	require.NoError(t, h.Filecmd(r))

	// Remove
	r = &sftp.Request{Method: "Remove", Filepath: "/subdir/g.txt"}
	require.NoError(t, h.Filecmd(r))

	// Rmdir
	r = &sftp.Request{Method: "Rmdir", Filepath: "/subdir"}
	require.NoError(t, h.Filecmd(r))
}

// ─── DefaultHandler + --no-delete (GHSA-4wh5-87mw-whxf) ───────────────────────

// noDeleteServer is testSFTPServer with the --no-delete flag set.
func noDeleteServer(root string) *SFTPServer {
	srv := testSFTPServer(root)
	srv.NoDelete = true
	return srv
}

// With --no-delete set, Remove/Rmdir/Rename must all be refused and the target
// must survive on disk. Before the fix the SFTP server ignored the flag entirely.
func TestDefaultHandler_NoDelete_BlocksRemove(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep.txt")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0644))
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	err := h.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/keep.txt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no delete")
	require.FileExists(t, target)
}

func TestDefaultHandler_NoDelete_BlocksRmdir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	err := h.Filecmd(&sftp.Request{Method: "Rmdir", Filepath: "/sub"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no delete")
	require.DirExists(t, sub)
}

func TestDefaultHandler_NoDelete_BlocksRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "orig.txt")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0644))
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	err := h.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/orig.txt", Target: "/moved.txt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no delete")
	require.FileExists(t, target)
	require.NoFileExists(t, filepath.Join(dir, "moved.txt"))
}

// Overwriting an existing file truncates it, which is a deletion — refuse it
// under --no-delete while still allowing brand-new uploads.
func TestDefaultHandler_NoDelete_BlocksOverwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "exists.txt")
	require.NoError(t, os.WriteFile(target, []byte("original"), 0644))
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	_, err := h.Filewrite(&sftp.Request{Method: "Put", Filepath: "/exists.txt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no delete")
	// Contents must be untouched.
	data, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, "original", string(data))
}

func TestDefaultHandler_NoDelete_AllowsNewUpload(t *testing.T) {
	dir := t.TempDir()
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	w, err := h.Filewrite(&sftp.Request{Method: "Put", Filepath: "/new.txt"})
	require.NoError(t, err)
	require.NotNil(t, w)
}

func TestDefaultHandler_NoDelete_AllowsMkdir(t *testing.T) {
	dir := t.TempDir()
	h := &DefaultHandler{Root: dir, ClientIP: "1.2.3.4", SFTPServer: noDeleteServer(dir)}

	require.NoError(t, h.Filecmd(&sftp.Request{Method: "Mkdir", Filepath: "/fresh"}))
	require.DirExists(t, filepath.Join(dir, "fresh"))
}

// ─── ListAt ───────────────────────────────────────────────────────────────────

func TestListAt_Basic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))

	infos, err := os.ReadDir(dir)
	require.NoError(t, err)

	fis := make([]fs.FileInfo, len(infos))
	for i, info := range infos {
		fis[i], _ = info.Info()
	}

	l := &simpleListerAt{files: fis}
	p := make([]fs.FileInfo, 10)
	n, err := l.ListAt(p, 0)
	require.Equal(t, 2, n)
	// io.EOF is returned when fewer items than buffer size
	require.Equal(t, io.EOF, err)
}

func TestListAt_Offset(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644))

	infos, err := os.ReadDir(dir)
	require.NoError(t, err)

	fis := make([]fs.FileInfo, len(infos))
	for i, info := range infos {
		fis[i], _ = info.Info()
	}

	l := &simpleListerAt{files: fis}
	p := make([]fs.FileInfo, 10)
	n, err := l.ListAt(p, 1)
	require.Equal(t, 1, n)
	// io.EOF because 1 < len(p)
	require.Equal(t, io.EOF, err)
}

func TestListAt_PastEnd(t *testing.T) {
	l := &simpleListerAt{files: []fs.FileInfo{}}
	p := make([]fs.FileInfo, 10)
	n, err := l.ListAt(p, 0)
	require.Equal(t, 0, n)
	require.Equal(t, io.EOF, err)
}

// ─── isAllowedIP ──────────────────────────────────────────────────────────────

func TestIsAllowedIP_Disabled(t *testing.T) {
	wl := &httpserver.Whitelist{Enabled: false}
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	require.True(t, isAllowedIP(addr, wl))
}

func TestIsAllowedIP_Enabled_Match(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	wl := &httpserver.Whitelist{
		Enabled:  true,
		Networks: []*net.IPNet{network},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 1234}
	require.True(t, isAllowedIP(addr, wl))
}

func TestIsAllowedIP_Enabled_NoMatch(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	wl := &httpserver.Whitelist{
		Enabled:  true,
		Networks: []*net.IPNet{network},
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	require.False(t, isAllowedIP(addr, wl))
}

func TestIsAllowedIP_InvalidAddr(t *testing.T) {
	wl := &httpserver.Whitelist{Enabled: true}
	require.False(t, isAllowedIP(&net.UnixAddr{Name: "invalid", Net: "unix"}, wl))
}

// ─── NewSFTPServer ────────────────────────────────────────────────────────────

func TestNewSFTPServer(t *testing.T) {
	opts := &options.Options{
		IP:             "127.0.0.1",
		FTPPort:        2222,
		FTPKeyFile:     "keys",
		Username:       "user",
		Password:       "pass",
		Webroot:        "/tmp",
		ReadOnly:       true,
		UploadOnly:     false,
		FTPHostKeyFile: "hostkey",
	}
	wh := webhook.Register(false, "", "discord", []string{})
	wl := &httpserver.Whitelist{}

	srv := NewSFTPServer(opts, wl, *wh)
	require.Equal(t, "127.0.0.1", srv.IP)
	require.Equal(t, 2222, srv.Port)
	require.Equal(t, "keys", srv.KeyFile)
	require.Equal(t, "user", srv.Username)
	require.Equal(t, "pass", srv.Password)
	require.Equal(t, "/tmp", srv.Root)
	require.True(t, srv.ReadOnly)
	require.False(t, srv.UploadOnly)
	require.Equal(t, "hostkey", srv.HostKeyFile)
}

// ─── HandleWebhookSend ────────────────────────────────────────────────────────

func TestHandleWebhookSend_Success(t *testing.T) {
	srv := testSFTPServer("/tmp")
	r := &sftp.Request{Method: "Get", Filepath: "/test.txt"}
	// Just verify it doesn't panic with disabled webhook
	srv.HandleWebhookSend("sftp", r, "1.2.3.4", false)
	srv.HandleWebhookSend("sftp", r, "1.2.3.4", true)
}

func TestHandleWebhookSend_Rename(t *testing.T) {
	srv := testSFTPServer("/tmp")
	r := &sftp.Request{Method: "Rename", Filepath: "/old.txt", Target: "/new.txt"}
	srv.HandleWebhookSend("sftp", r, "1.2.3.4", false)
	srv.HandleWebhookSend("sftp", r, "1.2.3.4", true)
}

// ─── loadAuthorizedKeys ───────────────────────────────────────────────────────

func TestLoadAuthorizedKeys_MissingFile(t *testing.T) {
	_, err := loadAuthorizedKeys("/nonexistent/path")
	require.Error(t, err)
}

// ─── rewritePathWindows ───────────────────────────────────────────────────────

func TestRewritePathWindows(t *testing.T) {
	require.Equal(t, "path\\to\\file", rewritePathWindows("/path/to/file"))
	require.Equal(t, "file.txt", rewritePathWindows("file.txt"))
}

// ─── sanitizePath edge cases ─────────────────────────────────────────────────

func TestSanitizePath_ExactRoot(t *testing.T) {
	path, err := sanitizePath("/", "/home/user")
	require.NoError(t, err)
	require.Equal(t, "/home/user", path)
}

func TestSanitizePath_Subpath(t *testing.T) {
	path, err := sanitizePath("/subdir/file.txt", "/home/user")
	require.NoError(t, err)
	require.Equal(t, "/home/user/subdir/file.txt", path)
}

// ─── readFile error paths ────────────────────────────────────────────────────

func TestReadFile_DotDotPathRerootedAndMissing(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	// sanitizePath re-roots this inside dir; os.Open fails because the file doesn't exist
	r := &sftp.Request{Method: "Get", Filepath: "/../../../etc/passwd"}
	_, err := readFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestReadFile_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Get", Filepath: "/missing.txt"}
	_, err := readFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

// ─── listFile error paths ────────────────────────────────────────────────────

func TestListFile_DotDotPathRerootedMissingDir(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	// sanitizePath re-roots inside dir; os.Open fails because the subdir doesn't exist
	r := &sftp.Request{Method: "List", Filepath: "/../../../etc"}
	_, err := listFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestListFile_StatNonexistent(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Stat", Filepath: "/missing_dir"}
	_, err := listFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestListFile_StatExisting(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0644))
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Stat", Filepath: "/f.txt"}
	lister, err := listFile(dir, r, "1.2.3.4", srv)
	require.NoError(t, err)
	require.NotNil(t, lister)
}

func TestListFile_OpenNonexistentDir(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "List", Filepath: "/no_such_dir"}
	_, err := listFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

// ─── writeFile error paths ───────────────────────────────────────────────────

func TestWriteFile_DotDotPathRerootedNoParentDir(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	// sanitizePath re-roots inside dir; os.Create fails — parent "tmp" subdir doesn't exist
	r := &sftp.Request{Method: "Put", Filepath: "/../../../tmp/evil.txt"}
	_, err := writeFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestWriteFile_Success(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Put", Filepath: "/newfile.txt"}
	f, err := writeFile(dir, r, "1.2.3.4", srv)
	require.NoError(t, err)
	require.NotNil(t, f)
	f.Close()
}

// ─── cmdFile error paths ─────────────────────────────────────────────────────

func TestCmdFile_DotDotPathRerootedNoParentDir(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	// sanitizePath re-roots inside dir; os.Mkdir fails — parent "tmp" subdir doesn't exist
	r := &sftp.Request{Method: "Mkdir", Filepath: "/../../../tmp/evil"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestCmdFile_StatNonexistent(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Stat", Filepath: "/nonexistent"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestCmdFile_LstatNonexistent(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Lstat", Filepath: "/nonexistent"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestCmdFile_MkdirAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists")
	require.NoError(t, os.Mkdir(existing, 0755))
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Mkdir", Filepath: "/exists"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestCmdFile_RemoveNonexistent(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Remove", Filepath: "/nonexistent.txt"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}

func TestCmdFile_UnsupportedMethod(t *testing.T) {
	dir := t.TempDir()
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Symlink", Filepath: "/foo"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestCmdFile_RenameTargetTraversalBlocked(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src.txt"), []byte("x"), 0644))
	srv := testSFTPServer(dir)
	r := &sftp.Request{Method: "Rename", Filepath: "/src.txt", Target: "/../../../tmp/dst.txt"}
	err := cmdFile(dir, r, "1.2.3.4", srv)
	require.Error(t, err)
}
