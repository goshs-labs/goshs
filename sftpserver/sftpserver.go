package sftpserver

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
)

// SFTPServer represents an SFTP server configuration
type SFTPServer struct {
	IP          string
	Port        int
	KeyFile     string
	Username    string
	Password    string
	Root        string
	ReadOnly    bool
	UploadOnly  bool
	NoDelete    bool
	HostKeyFile string
	Webhook     webhook.Webhook
	Whitelist   *httpserver.Whitelist

	ln net.Listener // bound by Bind, served by Start
}

func NewSFTPServer(opts *options.Options, wl *httpserver.Whitelist, webhook webhook.Webhook) *SFTPServer {
	return &SFTPServer{
		IP:          opts.IP,
		Port:        opts.FTPPort,
		KeyFile:     opts.FTPKeyFile,
		Username:    opts.Username,
		Password:    opts.Password,
		Root:        opts.Webroot,
		ReadOnly:    opts.ReadOnly,
		UploadOnly:  opts.UploadOnly,
		NoDelete:    opts.NoDelete,
		HostKeyFile: opts.FTPHostKeyFile,
		Webhook:     webhook,
		Whitelist:   wl,
	}
}

// Bind acquires the listening socket so a port conflict is reported to the
// caller synchronously instead of a serving goroutine swallowing it.
func (s *SFTPServer) Bind() error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.IP, strconv.Itoa(s.Port)))
	if err != nil {
		return fmt.Errorf("SFTP: failed to listen on %s:%d: %w", s.IP, s.Port, err)
	}
	s.ln = ln
	return nil
}

// Start initializes and starts the SFTP server
func (s *SFTPServer) Start() error {
	var err error

	// Define a simple password auth handler
	sshServer := ssh.Server{
		Addr: net.JoinHostPort(s.IP, strconv.Itoa(s.Port)),
		Handler: func(s ssh.Session) {
			// Deny default ssh connections
			_, err = io.WriteString(s, "This server only supports SFTP.\n")
			if err != nil {
				return
			}
			err = s.Exit(1)
			if err != nil {
				return
			}
		},
	}

	if s.HostKeyFile != "" {
		privateBytes, err := os.ReadFile(s.HostKeyFile)
		if err != nil {
			return err
		}

		private, err := gossh.ParsePrivateKey(privateBytes)
		if err != nil {
			return err
		}

		sshServer.HostSigners = []ssh.Signer{private}
	}

	if s.Username != "" || s.Password != "" {
		sshServer.PasswordHandler = func(ctx ssh.Context, password string) bool {
			return subtle.ConstantTimeCompare([]byte(ctx.User()), []byte(s.Username)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(s.Password)) == 1
		}
	}

	// User authorized_keys if provided
	if s.KeyFile != "" {
		authorizedKeysMap, err = loadAuthorizedKeys(s.KeyFile)
		if err != nil {
			return err
		}
		sshServer.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
			return authorizedKeysMap[string(key.Marshal())]
		}
	}

	// Add SFTP Handler
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": func(sess ssh.Session) {
			// Whitelist
			if isAllowedIP(sess.RemoteAddr(), s.Whitelist) {
				var server *sftp.RequestServer
				// Set handler read only or upload only or default
				if s.ReadOnly {
					roHandler := &ReadOnlyHandler{
						Root:       s.Root,
						ClientIP:   sess.RemoteAddr().String(),
						SFTPServer: s,
					}
					server = sftp.NewRequestServer(sess, roHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
				} else if s.UploadOnly {
					uoHandler := &UploadOnlyHandler{
						Root:       s.Root,
						ClientIP:   sess.RemoteAddr().String(),
						SFTPServer: s,
					}
					server = sftp.NewRequestServer(sess, uoHandler.GetHandler(), sftp.WithStartDirectory(s.Root))
				} else {
					dh := &DefaultHandler{
						Root:       s.Root,
						ClientIP:   sess.RemoteAddr().String(),
						SFTPServer: s,
					}
					server = sftp.NewRequestServer(sess, dh.GetHandler(), sftp.WithStartDirectory(s.Root))
				}

				if err := server.Serve(); err == io.EOF {
					server.Close()
				} else if err != nil {
					logger.Errorf("SFTP server error: %+v", err)
				}
			} else {
				logger.Warnf("[WHITELIST] SFTP access denied for IP: %v", sess.RemoteAddr())
			}
		},
	}

	// Bind lazily if a caller did not already do so via Bind.
	if s.ln == nil {
		if err := s.Bind(); err != nil {
			return err
		}
	}

	logger.Infof("Starting SFTP server on port %s:%d", s.IP, s.Port)
	return sshServer.Serve(s.ln)
}

func (s *SFTPServer) HandleWebhookSend(event string, r *sftp.Request, ip string, blocked bool) {
	var message string
	if blocked {
		switch r.Method {
		case "Rename":
			message = fmt.Sprintf("[SFTP] BLOCKED %s - [%s] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
		default:
			message = fmt.Sprintf("[SFTP] BLOCKED %s - [%s] - \"%s\"", ip, r.Method, r.Filepath)
		}
	} else {
		switch r.Method {
		case "Rename":
			message = fmt.Sprintf("[SFTP] %s - [%s] - \"%s to %s\"", ip, r.Method, r.Filepath, r.Target)
		default:
			message = fmt.Sprintf("[SFTP] %s - [%s] - \"%s\"", ip, r.Method, r.Filepath)
		}
	}

	logger.HandleWebhookSend(message, "ftp", s.Webhook)
}
