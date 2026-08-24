package server

import (
	"context"
	"path/filepath"

	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/dnsserver"
	"goshs.de/goshs/v2/ftpserver"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/ldapserver"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/sftpserver"
	"goshs.de/goshs/v2/smbserver"
	"goshs.de/goshs/v2/smtpserver"
	"goshs.de/goshs/v2/tftpserver"
	"goshs.de/goshs/v2/utils"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

// Servers bundles the shared runtime handles a caller needs after StartAll:
// the graceful-shutdown function plus the live event hub and reverse-shell
// catcher manager that drive the optional TUI dashboard.
type Servers struct {
	Shutdown func(context.Context)
	Hub      *ws.Hub
	Catcher  *catcher.Manager
	// TunnelURL returns the live public tunnel URL, or "" until the tunnel has
	// connected (or when --tunnel is unset). It is a getter rather than a value
	// because the URL is assigned asynchronously once the tunnel comes up.
	TunnelURL func() string
	// Chat is the shared team chat so the TUI can read and mutate the same
	// message log the web UI uses.
	Chat *chat.Chat
}

func StartAll(opts *options.Options) (*Servers, error) {
	// Init chat and hub
	ch := chat.New()
	// With --persist-chat the log is written to (and pre-staged from) a hidden
	// directory inside the served webroot so it survives a restart.
	if opts.PersistChat && !opts.NoChat {
		persistPath := filepath.Join(opts.Webroot, ".goshs-chat", "chat.json")
		if err := ch.Load(persistPath); err != nil {
			logger.Warnf("could not load persisted chat from %s: %v", persistPath, err)
		}
	}
	hub := ws.NewHub(ch, opts.CLI)
	go hub.Run()

	// Whitelist and Webhook
	wl, wh := registerWhitelistWebhook(opts)

	// http — bind synchronously so a port conflict is reported to the caller
	// (and, under --tui, before the dashboard takes over the terminal) instead
	// of the serving goroutine calling Fatalf behind its back.
	httpSrv := httpserver.NewHttpServer(opts, hub, ch, wl, *wh)
	if err := httpSrv.Bind("web"); err != nil {
		return nil, err
	}
	go httpSrv.Start("web")

	// webdav
	var webdavSrv *httpserver.FileServer
	if opts.WebDav {
		webdavSrv = httpserver.NewHttpServer(opts, hub, ch, wl, *wh)
		webdavSrv.WebdavPort = opts.WebDavPort
		if err := webdavSrv.Bind("webdav"); err != nil {
			return nil, err
		}
		go webdavSrv.Start("webdav")
	}

	// Every listening protocol below is bound synchronously via its Bind method
	// before its serving goroutine starts, so a port conflict (or any bind
	// error) surfaces here — and, under --tui, before the dashboard takes over
	// the terminal — instead of a goroutine calling Fatalf or silently dropping
	// the error.
	if opts.DNS {
		dnsSrv := dnsserver.NewDNSServer(opts, hub, wh)
		if err := dnsSrv.Bind(); err != nil {
			return nil, err
		}
		go dnsSrv.Start()
	}

	if opts.SMTP {
		smtpServer := smtpserver.NewSMTP(opts, hub, wh)
		if err := smtpServer.Bind(); err != nil {
			return nil, err
		}
		go smtpServer.Start()
	}

	if opts.SMB {
		smbServer := smbserver.NewSMBServer(opts, hub, wh)
		if err := smbServer.Bind(); err != nil {
			return nil, err
		}
		go smbServer.Start()
	}

	if opts.LDAP {
		ldapSrv := ldapserver.NewLDAPServer(opts, hub, wh)
		if err := ldapSrv.Bind(); err != nil {
			return nil, err
		}
		go ldapSrv.Start()
	}

	if opts.FTP {
		if opts.FTPSFTPMode {
			sftpSrv := sftpserver.NewSFTPServer(opts, wl, *wh)
			if err := sftpSrv.Bind(); err != nil {
				return nil, err
			}
			go func() { _ = sftpSrv.Start() }()
		} else {
			ftpSrv := ftpserver.NewFTPServer(opts, wl, *wh)
			if err := ftpSrv.Bind(); err != nil {
				return nil, err
			}
			go func() { _ = ftpSrv.Start() }()
		}
	}

	if opts.TFTP {
		tftpSrv := tftpserver.NewTFTPServer(opts, wl, *wh)
		if err := tftpSrv.Bind(); err != nil {
			return nil, err
		}
		go func() { _ = tftpSrv.Start() }()
	}

	// Zeroconf mDNS
	if opts.MDNS {
		err := utils.RegisterZeroconfMDNS(opts.SSL, opts.Port, opts.WebDav, opts.WebDavPort, opts.SMTP, opts.SMTPPort, opts.DNS, opts.DNSPort, opts.SMB, opts.SMBPort, opts.LDAP, opts.LDAPPort, opts.FTP, opts.FTPSFTPMode, opts.FTPPort, opts.TFTP, opts.TFTPPort)
		if err != nil {
			logger.Warnf("error registering zeroconf mDNS: %+v", err)
		}
	}

	shutdown := func(ctx context.Context) {
		if err := httpSrv.Shutdown(ctx); err != nil {
			logger.Errorf("error shutting down HTTP server: %+v", err)
		}
		if webdavSrv != nil {
			if err := webdavSrv.Shutdown(ctx); err != nil {
				logger.Errorf("error shutting down WebDAV server: %+v", err)
			}
		}
	}

	return &Servers{
		Shutdown:  shutdown,
		Hub:       hub,
		Catcher:   httpSrv.CatcherMgr,
		TunnelURL: func() string { return httpSrv.TunnelURL },
		Chat:      ch,
	}, nil
}

func registerWhitelistWebhook(opts *options.Options) (wl *httpserver.Whitelist, wh *webhook.Webhook) {
	// Parse IP whitelist
	enabled := false
	if opts.Whitelist != "" {
		logger.Infof("Whitelist activated: %+v", opts.Whitelist)
		enabled = true
	}

	// Register Whitelist
	wl, err := httpserver.NewIPWhitelist(opts.Whitelist, enabled, opts.TrustedProxies)
	if err != nil {
		logger.Warnf("Error parsing IP whitelist: %+v", err)
	}

	// Register webhook
	webh := webhook.Register(opts.WebhookEnabled, opts.WebhookURL, opts.WebhookProvider, opts.WebhookEventsParsed)

	return wl, webh
}
