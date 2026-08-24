package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
)

// Dir returns the path to ~/.config/goshs and creates it if it does not exist.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "goshs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating config directory %s: %w", dir, err)
	}
	return dir, nil
}

type Config struct {
	Interface           string   `json:"interface"`
	Port                int      `json:"port"`
	Directory           string   `json:"directory"`
	UploadFolder        string   `json:"upload_folder"`
	SSL                 bool     `json:"ssl"`
	SelfSigned          bool     `json:"self_signed"`
	PrivateKey          string   `json:"private_key"`
	Certificate         string   `json:"certificate"`
	P12                 string   `json:"p12"`
	P12NoPass           bool     `json:"p12_no_pass"`
	LetsEncrypt         bool     `json:"letsencrypt"`
	LetsEncryptDomain   string   `json:"letsencrypt_domain"`
	LetsEncryptEmail    string   `json:"letsencrypt_email"`
	LetsEncryptHTTPPort string   `json:"letsencrypt_http_port"`
	LetsEncryptTLSPort  string   `json:"letsencrypt_tls_port"`
	AuthUsername        string   `json:"auth_username"`
	AuthPassword        string   `json:"auth_password"`
	CertificateAuth     string   `json:"certificate_auth"`
	Webdav              bool     `json:"webdav"`
	WebdavPort          int      `json:"webdav_port"`
	UploadOnly          bool     `json:"upload_only"`
	ReadOnly            bool     `json:"read_only"`
	NoChat              bool     `json:"no_chat"`
	PersistChat         bool     `json:"persist_chat"`
	PersistChatImages   bool     `json:"persist_chat_images"`
	NoDelete            bool     `json:"no_delete"`
	Verbose             bool     `json:"verbose"`
	Silent              bool     `json:"silent"`
	Invisible           bool     `json:"invisible"`
	RunningUser         string   `json:"running_user"`
	CLI                 bool     `json:"cli"`
	Embedded            bool     `json:"embedded"`
	Output              string   `json:"output"`
	WebhookEnabled      bool     `json:"webhook_enabled"`
	WebhookURL          string   `json:"webhook_url"`
	WebhookProvider     string   `json:"webhook_provider"`
	WebhookEvents       []string `json:"webhook_events"`
	Whitelist           string   `json:"whitelist"`
	TrustedProxies      string   `json:"trusted_proxies"`
	Tunnel              bool     `json:"tunnel"`
	DNSServer           bool     `json:"dns_server"`
	DNSPort             int      `json:"dns_port"`
	DNSIP               string   `json:"dns_ip"`
	SMTPServer          bool     `json:"smtp_server"`
	SMTPPort            int      `json:"smtp_port"`
	SMTPDomain          string   `json:"smtp_domain"`
	SMBServer           bool     `json:"smb_server"`
	SMBPort             int      `json:"smb_port"`
	SMBDomain           string   `json:"smb_domain"`
	SMBShare            string   `json:"smb_share"`
	SMBWordlist         string   `json:"smb_wordlist"`
	MaxUploadSize       int64    `json:"max_upload_size"`
	Catcher             bool     `json:"catcher"`
	LDAP                bool     `json:"ldap"`
	LDAPPort            int      `json:"ldap_port"`
	LDAPJNDIEnabled     bool     `json:"ldap_jndi"`
	LDAPJNDIBase        string   `json:"ldap_jndi_base"`
	LDAPWordlist        string   `json:"ldap_wordlist"`
	FTP                 bool     `json:"ftp"`
	FTPPort             int      `json:"ftp_port"`
	FTPSFTPMode         bool     `json:"ftp_sftp_mode"`
	FTPKeyFile          string   `json:"ftp_keyfile"`
	FTPHostKeyFile      string   `json:"ftp_host_keyfile"`
	TFTP                bool     `json:"tftp"`
	TFTPPort            int      `json:"tftp_port"`
	TTL                 int      `json:"ttl"`
	TUI                 bool     `json:"tui"`
	Template            bool     `json:"template"`
	TemplateVars        []string `json:"template_vars"`
}

func LoadConfig(opts *options.Options) (*options.Options, error) {
	var cfg Config

	absPath, err := filepath.Abs(opts.ConfigFile)
	if err != nil {
		logger.Fatalf("Failed to get absolute path of config file: %+v", err)
		return opts, err
	}
	logger.Infof("Using config file %s", absPath)
	opts.ConfigPath = absPath

	cfile, err := os.ReadFile(absPath)
	if err != nil {
		return opts, err
	}

	if err = json.Unmarshal(cfile, &cfg); err != nil {
		return opts, err
	}

	// Set the config values
	opts.IP = cfg.Interface
	opts.Port = cfg.Port
	opts.Webroot = cfg.Directory
	opts.UploadFolder = cfg.UploadFolder
	opts.SSL = cfg.SSL
	opts.SelfSigned = cfg.SelfSigned
	opts.MyKey = cfg.PrivateKey
	opts.MyCert = cfg.Certificate
	opts.MyP12 = cfg.P12
	opts.P12NoPass = cfg.P12NoPass
	opts.LetsEncrypt = cfg.LetsEncrypt
	opts.LEDomains = cfg.LetsEncryptDomain
	opts.LEEmail = cfg.LetsEncryptEmail
	opts.LEHTTPPort = cfg.LetsEncryptHTTPPort
	opts.LETLSPort = cfg.LetsEncryptTLSPort
	opts.BasicAuth = cfg.AuthUsername + ":" + cfg.AuthPassword
	opts.CertAuth = cfg.CertificateAuth
	opts.WebDav = cfg.Webdav
	opts.WebDavPort = cfg.WebdavPort
	opts.UploadOnly = cfg.UploadOnly
	opts.ReadOnly = cfg.ReadOnly
	opts.NoChat = cfg.NoChat
	opts.PersistChat = cfg.PersistChat
	opts.PersistChatImages = cfg.PersistChatImages
	opts.NoDelete = cfg.NoDelete
	opts.Verbose = cfg.Verbose
	opts.Silent = cfg.Silent
	opts.DropUser = cfg.RunningUser
	opts.CLI = cfg.CLI
	opts.Embedded = cfg.Embedded
	opts.Output = cfg.Output
	opts.WebhookEnabled = cfg.WebhookEnabled
	opts.WebhookURL = cfg.WebhookURL
	opts.WebhookProvider = cfg.WebhookProvider
	opts.WebhookEventsParsed = cfg.WebhookEvents
	opts.Whitelist = cfg.Whitelist
	opts.TrustedProxies = cfg.TrustedProxies
	opts.Invisible = cfg.Invisible
	opts.Tunnel = cfg.Tunnel
	opts.DNS = cfg.DNSServer
	opts.DNSPort = cfg.DNSPort
	opts.DNSIP = cfg.DNSIP
	opts.SMTP = cfg.SMTPServer
	opts.SMTPPort = cfg.SMTPPort
	opts.SMTPDomain = cfg.SMTPDomain
	opts.SMB = cfg.SMBServer
	opts.SMBPort = cfg.SMBPort
	opts.SMBDomain = cfg.SMBDomain
	opts.SMBShare = cfg.SMBShare
	opts.SMBWordlist = cfg.SMBWordlist
	opts.MaxUploadSize = cfg.MaxUploadSize
	opts.Catcher = cfg.Catcher
	opts.LDAP = cfg.LDAP
	opts.LDAPPort = cfg.LDAPPort
	opts.LDAPJNDIEnabled = cfg.LDAPJNDIEnabled
	opts.LDAPJNDIBase = cfg.LDAPJNDIBase
	opts.LDAPWordlist = cfg.LDAPWordlist
	opts.FTP = cfg.FTP
	opts.FTPPort = cfg.FTPPort
	opts.FTPSFTPMode = cfg.FTPSFTPMode
	opts.FTPKeyFile = cfg.FTPKeyFile
	opts.FTPHostKeyFile = cfg.FTPHostKeyFile
	opts.TFTP = cfg.TFTP
	opts.TFTPPort = cfg.TFTPPort
	opts.TTL = time.Duration(cfg.TTL) * time.Second
	opts.TUI = cfg.TUI
	opts.Template = cfg.Template
	opts.TemplateVars = cfg.TemplateVars

	// Default upload folder to webroot if not set in config
	if opts.UploadFolder == "" {
		opts.UploadFolder = opts.Webroot
	}

	return opts, nil
}

func PrintExample() (string, error) {
	defaultConfig := Config{
		Interface:           "0.0.0.0",
		Port:                8000,
		Directory:           ".",
		UploadFolder:        ".",
		SSL:                 false,
		SelfSigned:          false,
		PrivateKey:          "",
		Certificate:         "",
		P12:                 "",
		P12NoPass:           false,
		LetsEncrypt:         false,
		LetsEncryptDomain:   "",
		LetsEncryptEmail:    "",
		LetsEncryptHTTPPort: "80",
		LetsEncryptTLSPort:  "443",
		AuthUsername:        "",
		AuthPassword:        "",
		CertificateAuth:     "",
		Webdav:              false,
		WebdavPort:          8001,
		UploadOnly:          false,
		ReadOnly:            false,
		NoChat:              false,
		PersistChat:         false,
		PersistChatImages:   false,
		NoDelete:            false,
		Verbose:             false,
		Silent:              false,
		Invisible:           false,
		RunningUser:         "",
		CLI:                 false,
		Embedded:            false,
		Output:              "",
		WebhookEnabled:      false,
		WebhookURL:          "",
		WebhookProvider:     "discord",
		WebhookEvents:       []string{"all"},
		Whitelist:           "",
		TrustedProxies:      "",
		Tunnel:              false,
		DNSServer:           false,
		DNSPort:             8053,
		DNSIP:               "127.0.0.1",
		SMTPServer:          false,
		SMTPPort:            2525,
		SMTPDomain:          "",
		SMBServer:           false,
		SMBPort:             445,
		SMBDomain:           "",
		SMBShare:            "",
		SMBWordlist:         "",
		MaxUploadSize:       0,
		Catcher:             false,
		LDAP:                false,
		LDAPPort:            389,
		LDAPJNDIEnabled:     false,
		LDAPJNDIBase:        "",
		LDAPWordlist:        "",
		FTP:                 false,
		FTPPort:             2121,
		FTPSFTPMode:         false,
		FTPKeyFile:          "",
		FTPHostKeyFile:      "",
		TFTP:                false,
		TFTPPort:            69,
		TTL:                 0,
		TUI:                 false,
		Template:            false,
		TemplateVars:        []string{},
	}

	b, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
