package ftpserver

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	ftplib "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
	"goshs.de/goshs/v2/ca"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
)

type FTPServer struct {
	IP         string
	Port       int
	Root       string
	Username   string
	Password   string
	ReadOnly   bool
	UploadOnly bool
	NoDelete   bool
	Webhook    webhook.Webhook
	Whitelist  *httpserver.Whitelist
	SSL        bool
	SelfSigned bool
	MyCert     string
	MyKey      string

	srv *ftplib.FtpServer // bound by Bind, served by Start
}

func NewFTPServer(opts *options.Options, wl *httpserver.Whitelist, wh webhook.Webhook) *FTPServer {
	return &FTPServer{
		IP:         opts.IP,
		Port:       opts.FTPPort,
		Root:       opts.Webroot,
		Username:   opts.Username,
		Password:   opts.Password,
		ReadOnly:   opts.ReadOnly,
		UploadOnly: opts.UploadOnly,
		NoDelete:   opts.NoDelete,
		Webhook:    wh,
		Whitelist:  wl,
		SSL:        opts.SSL,
		SelfSigned: opts.SelfSigned,
		MyCert:     opts.MyCert,
		MyKey:      opts.MyKey,
	}
}

// Bind acquires the listening socket so a port conflict is reported to the
// caller synchronously. Previously the bind error from ListenAndServe was
// discarded by the launching goroutine, so a port clash silently disabled FTP
// with no message.
func (s *FTPServer) Bind() error {
	driver := &mainDriver{srv: s}
	srv := ftplib.NewFtpServer(driver)
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("FTP: failed to listen on %s:%d: %w", s.IP, s.Port, err)
	}
	s.srv = srv
	return nil
}

func (s *FTPServer) Start() error {
	// Bind lazily if a caller did not already do so via Bind.
	if s.srv == nil {
		if err := s.Bind(); err != nil {
			return err
		}
	}
	logger.Infof("Starting FTP server on %s:%d", s.IP, s.Port)
	return s.srv.Serve()
}

func (s *FTPServer) HandleWebhookSend(action, path, ip string, blocked bool) {
	var message string
	if blocked {
		message = fmt.Sprintf("[FTP] BLOCKED %s - [%s] - \"%s\"", ip, action, path)
	} else {
		message = fmt.Sprintf("[FTP] %s - [%s] - \"%s\"", ip, action, path)
	}
	logger.HandleWebhookSend(message, "ftp", s.Webhook)
}

// mainDriver implements ftplib.MainDriver
type mainDriver struct {
	srv *FTPServer
}

func (d *mainDriver) GetSettings() (*ftplib.Settings, error) {
	return &ftplib.Settings{
		ListenAddr:              net.JoinHostPort(d.srv.IP, strconv.Itoa(d.srv.Port)),
		Banner:                  "goshs FTP server ready",
		ActiveTransferPortNon20: true,
	}, nil
}

func (d *mainDriver) ClientConnected(cc ftplib.ClientContext) (string, error) {
	clientIP := cc.RemoteAddr().String()
	if !isAllowedIP(cc.RemoteAddr(), d.srv.Whitelist) {
		logger.Warnf("[FTP] [WHITELIST] Access denied for %s", clientIP)
		return "", fmt.Errorf("access denied")
	}
	logger.Infof("[FTP] Client connected from %s", clientIP)
	return "goshs FTP server", nil
}

func (d *mainDriver) ClientDisconnected(cc ftplib.ClientContext) {
	logger.Infof("[FTP] Client disconnected: %s", cc.RemoteAddr())
}

func (d *mainDriver) AuthUser(cc ftplib.ClientContext, user, pass string) (ftplib.ClientDriver, error) {
	if d.srv.Username != "" || d.srv.Password != "" {
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(d.srv.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(d.srv.Password)) == 1
		if !userOK || !passOK {
			logger.Warnf("[FTP] Auth failed for user '%s' from %s", user, cc.RemoteAddr())
			d.srv.HandleWebhookSend("AUTH", user, cc.RemoteAddr().String(), true)
			return nil, fmt.Errorf("invalid credentials")
		}
	}
	logger.Infof("[FTP] User '%s' authenticated from %s", user, cc.RemoteAddr())
	d.srv.HandleWebhookSend("AUTH", user, cc.RemoteAddr().String(), false)

	base := afero.NewBasePathFs(afero.NewOsFs(), d.srv.Root)
	if d.srv.ReadOnly {
		return d.srv.withACL(afero.NewReadOnlyFs(base)), nil
	}
	// upload-only and no-delete are independent and may be combined, so stack the
	// wrappers rather than picking one branch. no-delete goes on first so an
	// upload-only STOR that truncates an existing file is still caught by it.
	var fs afero.Fs = base
	if d.srv.NoDelete {
		fs = &noDeleteFs{Fs: fs}
	}
	if d.srv.UploadOnly {
		fs = &uploadOnlyFs{Fs: fs}
	}
	return d.srv.withACL(fs), nil
}

// withACL wraps fs so every operation honours the per-folder .goshs ACL. It is
// the outermost layer so its ReadDir (ftpserverlib's file-list extension) is
// the one used for LIST/NLST/MLSD.
func (s *FTPServer) withACL(fs afero.Fs) afero.Fs {
	return &aclFs{Fs: fs, root: s.Root, acl: httpserver.NewProtocolACL(s.Root)}
}

// GetTLSConfig returns a TLS config for FTPS (explicit TLS / AUTH TLS) when
// goshs is started with -s. Returning an error (when TLS is not configured)
// causes ftpserverlib to respond with StatusActionNotTaken instead of 234,
// preventing the nil-pointer dereference that would occur if we returned
// (nil, nil) and the library called tls.Server(conn, nil).
func (d *mainDriver) GetTLSConfig() (*tls.Config, error) {
	if !d.srv.SSL {
		return nil, fmt.Errorf("TLS not configured")
	}
	if d.srv.SelfSigned {
		cfg, _, _, err := ca.Setup()
		if err != nil {
			return nil, fmt.Errorf("generating self-signed cert for FTP TLS: %w", err)
		}
		return cfg, nil
	}
	if d.srv.MyCert == "" || d.srv.MyKey == "" {
		return nil, fmt.Errorf("TLS cert or key not provided")
	}
	cert, err := tls.LoadX509KeyPair(d.srv.MyCert, d.srv.MyKey)
	if err != nil {
		return nil, fmt.Errorf("loading FTP TLS cert/key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// noDeleteFs wraps afero.Fs and blocks any operation that would destroy an
// existing file's contents. Removing is not the only way to lose a file: a
// rename moves it away from its path, and opening it O_TRUNC (or Create) rewrites
// it from empty, so those are blocked too. This mirrors the WebDAV guard in
// httpserver/webdav_acl.go, which already treats MOVE and overwriting PUT/COPY
// as deletions. Creating new files and appending (which preserve existing
// content) stay allowed.
type noDeleteFs struct {
	afero.Fs
}

func (fs *noDeleteFs) Remove(name string) error {
	return fmt.Errorf("delete not allowed")
}

func (fs *noDeleteFs) RemoveAll(path string) error {
	return fmt.Errorf("delete not allowed")
}

func (fs *noDeleteFs) Rename(oldname, newname string) error {
	return fmt.Errorf("rename not allowed in no-delete mode")
}

func (fs *noDeleteFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	// A truncating write over an existing file destroys its contents. Appends
	// (O_APPEND without O_TRUNC) and writes to new files are fine.
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 && flag&os.O_TRUNC != 0 {
		if exists, _ := afero.Exists(fs.Fs, name); exists {
			return nil, fmt.Errorf("overwrite not allowed in no-delete mode")
		}
	}
	return fs.Fs.OpenFile(name, flag, perm)
}

func (fs *noDeleteFs) Create(name string) (afero.File, error) {
	// Create implies O_TRUNC, so it would wipe an existing file.
	if exists, _ := afero.Exists(fs.Fs, name); exists {
		return nil, fmt.Errorf("overwrite not allowed in no-delete mode")
	}
	return fs.Fs.Create(name)
}

// uploadOnlyFs wraps afero.Fs so clients can write (STOR) and list directories
// but never read a file back (RETR). ftpserverlib downloads a file via
// OpenFile(..., O_RDONLY) and lists a directory via Open, so reads are denied at
// both entry points while directory listing is preserved.
type uploadOnlyFs struct {
	afero.Fs
}

func (fs *uploadOnlyFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	// O_RDONLY is 0, so a read open has neither O_WRONLY nor O_RDWR set.
	if flag&(os.O_WRONLY|os.O_RDWR) == 0 {
		return nil, fmt.Errorf("download not allowed in upload-only mode")
	}
	return fs.Fs.OpenFile(name, flag, perm)
}

func (fs *uploadOnlyFs) Open(name string) (afero.File, error) {
	// Open is used by the driver for directory listing; permit directories but
	// block opening a regular file for reading.
	if info, err := fs.Fs.Stat(name); err == nil && !info.IsDir() {
		return nil, fmt.Errorf("download not allowed in upload-only mode")
	}
	return fs.Fs.Open(name)
}

// aclFs enforces the per-folder .goshs ACL on the FTP view of the webroot
// (GHSA-q8gg-q2wc-w52g). FTP credentials are server-wide, so a folder's own
// basic-auth can never be presented: like SFTP, a .goshs auth requirement is a
// hard deny, block-listed names and the .goshs file itself are hidden, and
// listings are filtered. Names arrive as FTP paths relative to root.
type aclFs struct {
	afero.Fs
	root string
	acl  *httpserver.ProtocolACL
}

var _ ftplib.ClientDriverExtensionFileList = (*aclFs)(nil)

// errACLDenied looks like a missing file so the ACL cannot be used to
// enumerate protected names.
var errACLDenied = os.ErrNotExist

func (fs *aclFs) abs(name string) string {
	return filepath.Join(fs.root, filepath.FromSlash(path.Clean("/"+name)))
}

func (fs *aclFs) check(names ...string) error {
	for _, name := range names {
		if !fs.acl.Allowed(fs.abs(name)) {
			return &os.PathError{Op: "acl", Path: name, Err: errACLDenied}
		}
	}
	return nil
}

func (fs *aclFs) Create(name string) (afero.File, error) {
	if err := fs.check(name); err != nil {
		return nil, err
	}
	return fs.Fs.Create(name)
}

func (fs *aclFs) Mkdir(name string, perm os.FileMode) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.Mkdir(name, perm)
}

func (fs *aclFs) MkdirAll(name string, perm os.FileMode) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.MkdirAll(name, perm)
}

func (fs *aclFs) Open(name string) (afero.File, error) {
	if err := fs.check(name); err != nil {
		return nil, err
	}
	return fs.Fs.Open(name)
}

func (fs *aclFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if err := fs.check(name); err != nil {
		return nil, err
	}
	return fs.Fs.OpenFile(name, flag, perm)
}

func (fs *aclFs) Remove(name string) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.Remove(name)
}

func (fs *aclFs) RemoveAll(name string) error {
	if err := fs.check(name); err != nil {
		return err
	}
	// check only covers name itself; a recursive delete must not destroy a
	// protected subtree below it (GHSA-rf62-vgq5-ggq5).
	if !fs.acl.SubtreeAllowed(fs.abs(name)) {
		return &os.PathError{Op: "acl", Path: name, Err: errACLDenied}
	}
	return fs.Fs.RemoveAll(name)
}

func (fs *aclFs) Rename(oldname, newname string) error {
	if err := fs.check(oldname, newname); err != nil {
		return err
	}
	// check only covers the two paths; a directory must not be moved out of
	// the .goshs scope protecting its contents (GHSA-95fx-g5c4-6f8f).
	if !fs.acl.RenameAllowed(fs.abs(oldname), fs.abs(newname)) {
		return &os.LinkError{Op: "acl", Old: oldname, New: newname, Err: errACLDenied}
	}
	return fs.Fs.Rename(oldname, newname)
}

func (fs *aclFs) Stat(name string) (os.FileInfo, error) {
	if err := fs.check(name); err != nil {
		return nil, err
	}
	return fs.Fs.Stat(name)
}

func (fs *aclFs) Chmod(name string, mode os.FileMode) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.Chmod(name, mode)
}

func (fs *aclFs) Chown(name string, uid, gid int) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.Chown(name, uid, gid)
}

func (fs *aclFs) Chtimes(name string, atime, mtime time.Time) error {
	if err := fs.check(name); err != nil {
		return err
	}
	return fs.Fs.Chtimes(name, atime, mtime)
}

// ReadDir implements ftplib.ClientDriverExtensionFileList so directory
// listings hide the .goshs file, block-listed entries and auth-protected
// subdirectories.
func (fs *aclFs) ReadDir(name string) ([]os.FileInfo, error) {
	if err := fs.check(name); err != nil {
		return nil, err
	}
	infos, err := afero.ReadDir(fs.Fs, name)
	if err != nil {
		return nil, err
	}
	return fs.acl.FilterListing(fs.abs(name), infos), nil
}

func isAllowedIP(addr net.Addr, wl *httpserver.Whitelist) bool {
	if !wl.Enabled {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range wl.Networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
