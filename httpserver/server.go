package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"golang.org/x/net/webdav"
	"goshs.de/goshs/v2/ca"
	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/config"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/tunnel"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
	"software.sslmate.com/src/go-pkcs12"
)

// Shutdown gracefully stops the HTTP server, waiting up to ctx's deadline for
// in-flight requests to complete.
func (fs *FileServer) Shutdown(ctx context.Context) error {
	if fs.httpServer == nil {
		return nil
	}
	return fs.httpServer.Shutdown(ctx)
}

// logServeResult treats http.ErrServerClosed as a clean exit (graceful
// shutdown) and panics on any other error.
func logServeResult(err error) {
	if errors.Is(err, http.ErrServerClosed) {
		return
	}
	logger.Panic(err)
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("goshs: failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func NewHttpServer(opts *options.Options, hub *ws.Hub, ch *chat.Chat, wl *Whitelist, wh webhook.Webhook) *FileServer {
	fs := &FileServer{
		IP:                opts.IP,
		Port:              opts.Port,
		CLI:               opts.CLI,
		Webroot:           opts.Webroot,
		Chat:              ch,
		Hub:               hub,
		UploadFolder:      opts.UploadFolder,
		SSL:               opts.SSL,
		SelfSigned:        opts.SelfSigned,
		LetsEncrypt:       opts.LetsEncrypt,
		MyCert:            opts.MyCert,
		MyKey:             opts.MyKey,
		MyP12:             opts.MyP12,
		P12NoPass:         opts.P12NoPass,
		User:              opts.Username,
		Pass:              opts.Password,
		CACert:            opts.CertAuth,
		DropUser:          opts.DropUser,
		UploadOnly:        opts.UploadOnly,
		ReadOnly:          opts.ReadOnly,
		NoChat:            opts.NoChat,
		PersistChat:       opts.PersistChat,
		PersistChatImages: opts.PersistChatImages,
		NoDelete:          opts.NoDelete,
		Silent:            opts.Silent,
		Invisible:         opts.Invisible,
		Embedded:          opts.Embedded,
		Verbose:           opts.Verbose,
		Tunnel:            opts.Tunnel,
		Version:           goshsversion.GoshsVersion,
		MaxUpload:         opts.MaxUploadSize,
		Options:           opts,
		CSRFToken:         generateCSRFToken(),
		authCache:         make(map[string]time.Time),
		authFailures:      make(map[string]*authFailEntry),
	}

	fs.Hub = hub
	fs.Chat = ch
	fs.Webhook = wh
	fs.Whitelist = wl
	fs.CatcherMgr = catcher.NewManager(hub)

	// Fix the self-destruct deadline once at startup so the web UI can render a
	// live countdown that keeps decreasing across page reloads, rather than
	// resetting on every render.
	if opts.TTL > 0 {
		fs.TTLDeadline = time.Now().Add(opts.TTL)
	}

	return fs
}

func (fs *FileServer) SetupMux(mux *CustomMux, what string) string {
	var addr string
	switch what {
	case modeWeb:
		// Check Basic Auth and use middleware
		if (fs.User != "" || fs.Pass != "") && what == modeWeb {
			if !fs.SSL {
				logger.Warnf("You are using basic auth without SSL. Your credentials will be transferred in cleartext. Consider using -s, too.")
			}
			logger.Infof("Using basic auth with user '%s' and password '%s'", fs.User, fs.Pass)
			if fs.Invisible {
				// Use invisible basic auth middleware
				mux.Use(fs.InvisibleBasicAuthMiddleware)
			} else {
				// Use middleware
				mux.Use(fs.BasicAuthMiddleware)
			}
		}

		// IP Whitelist Middleware
		mux.Use(fs.IPWhitelistMiddleware)

		// Add custom server header middleware
		mux.Use(fs.ServerHeaderMiddleware)

		// Define routes
		mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
			if action, ok := r.URL.Query()["catcher-api"]; ok {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.handleCatcherAPI(w, r, action[0])
				return
			}
			if _, ok := r.URL.Query()["chatUpload"]; ok {
				if denyForTokenAccess(w, r) {
					return
				}
				if !fs.NoChat && !fs.Invisible {
					fs.chatUpload(w, r)
				} else {
					fs.handleError(w, r, fmt.Errorf("chat is disabled"), http.StatusNotFound)
				}
				runtime.GC()
				return
			}
			if strings.HasSuffix(r.URL.Path, "/upload") {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.upload(w, r)
				runtime.GC()
			} else if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
				if denyForTokenAccess(w, r) {
					return
				}
				if !fs.checkCSRF(w, r) {
					return
				}
				fs.handleMkdir(w, r)
			} else {
				fs.logOnly(w, r)
			}
		})
		mux.HandleFunc("PUT /", func(w http.ResponseWriter, r *http.Request) {
			if denyForTokenAccess(w, r) {
				return
			}
			fs.put(w, r)
		})
		mux.HandleFunc("DELETE /", func(w http.ResponseWriter, r *http.Request) {
			if action, ok := r.URL.Query()["catcher-api"]; ok {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.handleCatcherAPI(w, r, action[0])
				return
			}
			if _, ok := r.URL.Query()["token"]; ok {
				if !fs.checkCSRF(w, r) {
					return
				}
				fs.DeleteShareHandler(w, r)
				return
			}
			if denyForTokenAccess(w, r) {
				return
			}
			if !fs.checkCSRF(w, r) {
				return
			}
			if fs.ReadOnly || fs.UploadOnly || fs.NoDelete {
				fs.handleError(w, r, fmt.Errorf("delete not allowed"), http.StatusForbidden)
				return
			}
			fs.deleteFile(w, r)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				// Handle CORS preflight
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.WriteHeader(http.StatusOK)
				fs.logOnly(w, r)
			} else {
				fs.handler(w, r)
			}
		})

		addr = net.JoinHostPort(fs.IP, strconv.Itoa(fs.Port))
	case "webdav":
		// IP Whitelist Middleware
		mux.Use(fs.IPWhitelistMiddleware)

		// Add custom server header middleware
		mux.Use(fs.ServerHeaderMiddleware)

		wdHandler := &webdav.Handler{
			FileSystem: fs.newWebdavFileSystem(),
			LockSystem: webdav.NewMemLS(),
			Logger: func(r *http.Request, e error) {
				if e != nil && r.Method != "PROPFIND" {
					logger.HandleWebhookSend(fmt.Sprintf("[WEBDAV] ERROR: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto), "webdav", fs.Webhook)
					logger.Errorf("WEBDAV: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
					return
				} else if r.Method != "PROPFIND" {
					logger.HandleWebhookSend(fmt.Sprintf("[WEBDAV]: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto), "webdav", fs.Webhook)
					logger.Infof("WEBDAV:  %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
				}
			},
		}

		// Enforce mode flags and the .goshs ACL on WebDAV verbs.
		wdGuard := fs.webdavGuard(wdHandler)

		// Check Basic Auth and use middleware
		if fs.User != "" || fs.Pass != "" {
			authHandler := fs.BasicAuthMiddleware(wdGuard)
			mux.Handle("/", authHandler)
		} else {
			mux.Handle("/", wdGuard)
		}
		addr = net.JoinHostPort(fs.IP, strconv.Itoa(fs.WebdavPort))
	default:
	}

	return addr
}

func (fs *FileServer) StartListener(server *http.Server, what string, listener net.Listener) {
	var err error
	// Check if ssl
	if fs.SSL {
		// Check if selfsigned
		if fs.SelfSigned {
			serverTLSConf, fingerprint256, fingerprint1, err := ca.Setup()
			if err != nil {
				logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}
			server.TLSConfig = serverTLSConf

			// If client-cert auth add it to TLS Config of server
			if fs.CACert != "" {
				fs.AddCertAuth(server)
			}

			fs.Fingerprint256 = strings.TrimRight(fingerprint256, " ")
			fs.Fingerprint1 = strings.TrimRight(fingerprint1, " ")
			fs.logStart(what)

			// Drop privs if needed
			fs.dropPrivs()

			// Webhook message
			logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

			logServeResult(server.ServeTLS(listener, "", ""))
		} else {
			if fs.MyCert == "" || fs.MyKey == "" {
				if fs.MyP12 == "" {
					logger.Fatal("You need to provide either server.key and server.crt or server.p12 if -s and not -ss")
				}
			}

			var cert tls.Certificate
			var fingerprint256, fingerprint1 string

			if fs.MyP12 != "" {
				p12, err := os.ReadFile(fs.MyP12)
				if err != nil {
					logger.Fatalf("Error reading pkcs12 file: %+v", err)
				}

				var password []byte
				if fs.P12NoPass {
					password = []byte("")
				} else {
					fmt.Printf("Enter password for %+v: ", fs.MyP12)
					password, err = gopass.GetPasswdMasked()
					if err != nil {
						logger.Fatalf("error reading password from stdin: %+v", err)
					}
				}
				privKey, certificate, err := pkcs12.Decode(p12, string(password))
				if err != nil {
					logger.Fatalf("error parsing the p12 file: %+v", err)
				}

				cert = tls.Certificate{
					Certificate: [][]byte{certificate.Raw},
					PrivateKey:  privKey,
					Leaf:        certificate,
				}

				fingerprint256, fingerprint1 = ca.Sum(certificate.Raw)
			} else {
				fingerprint256, fingerprint1, err = ca.ParseAndSum(fs.MyCert)
				if err != nil {
					logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
				}

				cert, err = tls.LoadX509KeyPair(fs.MyCert, fs.MyKey)
				if err != nil {
					logger.Fatalf("Failed to load provided key or certificate: %+v\n", err)
				}
			}

			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			// If client-cert auth add it to TLS Config of server
			if fs.CACert != "" {
				fs.AddCertAuth(server)
			}

			fs.Fingerprint256 = fingerprint256
			fs.Fingerprint1 = fingerprint1
			fs.logStart(what)

			// Drop privs if needed
			fs.dropPrivs()

			// Webhook message
			logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

			logServeResult(server.ServeTLS(listener, "", ""))
		}
	} else {
		fs.logStart(what)

		// Drop privs if needed
		fs.dropPrivs()

		// Webhook message
		logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

		logServeResult(server.Serve(listener))
	}
}

// Bind sets up routing and binds the TCP listener, returning any error (most
// commonly "address already in use") instead of exiting. Callers can invoke it
// synchronously before Start so a bind failure surfaces on the main goroutine —
// this matters under --tui, where a Fatalf from the serving goroutine would exit
// the process behind Bubble Tea's back, leaving no message and a corrupted
// terminal. Start binds lazily if Bind was not called first.
func (fs *FileServer) Bind(what string) error {
	mux := NewCustomMux()
	addr := fs.SetupMux(mux, what)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error binding to listener '%s': %w", addr, err)
	}
	fs.mux = mux
	fs.listener = listener
	return nil
}

// Start will start the file server
func (fs *FileServer) Start(what string) {
	// Bind lazily if a caller did not already do so via Bind.
	if fs.listener == nil {
		if err := fs.Bind(what); err != nil {
			logger.Fatalf("%+v", err)
		}
	}
	mux := fs.mux
	listener := fs.listener
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Errorf("error closing tcp listener: %+v", err)
		}
	}()

	// construct server
	server := &http.Server{
		Handler:           http.AllowQuerySemicolons(mux),
		ReadHeaderTimeout: 10 * time.Second, // Mitigate Slow Loris Attack
		ErrorLog:          log.New(io.Discard, "", 0),
		// Against good practice no timeouts here, otherwise big files would be terminated when downloaded
	}
	fs.httpServer = server

	// Print silent banner
	if fs.Silent {
		logger.Info("Serving in silent mode - no dir listing available at HTTP Listener")
	}

	// Print all embedded files as info to the console
	fs.PrintEmbeddedFiles()

	// Start tunnel if enabled
	if fs.Tunnel {
		configDir, err := config.Dir()
		if err != nil {
			logger.Errorf("tunnel: cannot resolve config directory: %+v", err)
		} else {
			knownHostsFile := filepath.Join(configDir, "known_hosts")
			t, err := tunnel.Start(fs.IP, fs.Port, knownHostsFile)
			if err != nil {
				var mismatch *tunnel.HostKeyMismatchError
				if errors.As(err, &mismatch) {
					logger.Fatalf("tunnel: %v", mismatch)
				}
				logger.Errorf("error starting tunnel: %+v", err)
			} else {
				defer t.Close()
				logger.Infof("Public tunnel URL: %s", t.PublicURL)
				fs.TunnelURL = t.PublicURL
			}
		}
	}

	// Create SharedLinks map
	fs.SharedLinks = make(map[string]SharedLink)

	// Go routine to cleanup SharedLinks when expired
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			fs.sharedLinksMu.Lock()
			for token, link := range fs.SharedLinks {
				if link.Expires.Before(now) {
					delete(fs.SharedLinks, token)
					logger.Debugf("Expired shared link removed: %s", token)
				}
			}
			fs.sharedLinksMu.Unlock()
		}
	}()

	// Start listener
	fs.StartListener(server, what, listener)
}
