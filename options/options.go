package options

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"goshs.de/goshs/v2/completion"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/update"
	"goshs.de/goshs/v2/utils"
)

type Options struct {
	IP                  string            // "0.0.0.0"
	Port                int               // 8000
	Webroot             string            // "."
	SSL                 bool              // false
	SelfSigned          bool              // false
	MyKey               string            // ""
	MyCert              string            // ""
	MyP12               string            // ""
	P12NoPass           bool              // false
	CLI                 bool              // false
	UploadFolder        string            // ""
	LetsEncrypt         bool              // false
	BasicAuth           string            // ""
	Username            string            // "" will be constructed from BasicAuth
	Password            string            // "" will be constructed from BasicAuth
	CertAuth            string            // ""
	WebDav              bool              // false
	WebDavPort          int               // 8001
	UploadOnly          bool              // false
	ReadOnly            bool              // false
	NoChat              bool              // false
	PersistChat         bool              // false
	PersistChatImages   bool              // false
	NoDelete            bool              // false
	Verbose             bool              // false
	Silent              bool              // false
	DropUser            string            // ""
	LEEmail             string            // ""
	LEDomains           string            // ""
	LEHTTPPort          string            //"80"
	LETLSPort           string            // "443"
	Embedded            bool              // false
	Output              string            // ""
	ConfigFile          string            // ""
	ConfigPath          string            // "" Will be constructed from ConfigFile
	WebhookEnabled      bool              // false
	WebhookURL          string            // ""
	WebhookEvents       string            // "all"
	WebhookProvider     string            // "Discord"
	WebhookEventsParsed []string          // []string{}
	Whitelist           string            // ""
	TrustedProxies      string            // ""
	MDNS                bool              // false
	Invisible           bool              // false
	Tunnel              bool              // false
	DNS                 bool              // false
	DNSPort             int               // 8053
	DNSIP               string            // "127.0.0.1"
	SMTP                bool              // false
	SMTPPort            int               // 2525
	SMTPDomain          string            // ""
	SMB                 bool              // false
	SMBPort             int               // 445
	SMBDomain           string            // ""
	SMBShare            string            // ""
	SMBWordlist         string            // ""
	MaxUploadSize       int64             // 0 = unlimited
	Catcher             bool              // false
	LDAP                bool              // false
	LDAPPort            int               // 389
	LDAPJNDIEnabled     bool              // false — when true, use search baseDN as class name
	LDAPJNDIBase        string            // "" auto-constructs from IP/port
	LDAPWordlist        string            // "" optional wordlist path for NTLM hash cracking
	FTP                 bool              // false
	FTPPort             int               // 2121
	FTPSFTPMode         bool              // false
	FTPKeyFile          string            // ""
	FTPHostKeyFile      string            // ""
	TFTP                bool              // false
	TFTPPort            int               // 69
	TTL                 time.Duration     // 0 = disabled, otherwise self-destruct after this duration
	TUI                 bool              // false — run the interactive terminal dashboard
	Template            bool              // false — enable ?tpl payload templating
	TemplateVars        []string          // raw KEY=VALUE entries from --tpl-var / config
	TemplateVarsParsed  map[string]string // parsed in sanity.FurtherProcessing
}

// stringSliceFlag collects a repeatable string flag (e.g. --tpl-var KEY=VALUE).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func Parse() (*Options, bool) {
	wd, _ := os.Getwd()
	opts := &Options{}

	flag.StringVar(&opts.ConfigFile, "C", "", "config")
	flag.StringVar(&opts.IP, "i", "0.0.0.0", "ip")
	flag.StringVar(&opts.IP, "ip", "0.0.0.0", "ip")
	flag.IntVar(&opts.Port, "p", 8000, "port")
	flag.IntVar(&opts.Port, "port", 8000, "port")
	flag.StringVar(&opts.Webroot, "d", wd, "web root")
	flag.StringVar(&opts.Webroot, "dir", wd, "web root")
	flag.BoolVar(&opts.SSL, "s", false, "tls")
	flag.BoolVar(&opts.SSL, "ssl", false, "tls")
	flag.BoolVar(&opts.SelfSigned, "ss", false, "self-signed")
	flag.BoolVar(&opts.SelfSigned, "self-signed", false, "self-signed")
	flag.StringVar(&opts.MyKey, "sk", "", "server key")
	flag.StringVar(&opts.MyKey, "server-key", "", "server key")
	flag.StringVar(&opts.MyCert, "sc", "", "server cert")
	flag.StringVar(&opts.MyCert, "server-cert", "", "server cert")
	flag.StringVar(&opts.MyP12, "p12", "", "server p12")
	flag.StringVar(&opts.MyP12, "pkcs12", "", "server p12")
	flag.BoolVar(&opts.P12NoPass, "p12np", false, "p12 no pass")
	flag.BoolVar(&opts.P12NoPass, "p12-no-pass", false, "p12 no pass")
	flag.StringVar(&opts.BasicAuth, "b", "", "basic auth")
	flag.StringVar(&opts.BasicAuth, "basic-auth", "", "basic auth")
	flag.StringVar(&opts.CertAuth, "ca", "", "cert auth")
	flag.StringVar(&opts.CertAuth, "cert-auth", "", "cert auth")
	flag.BoolVar(&opts.WebDav, "w", false, "enable webdav")
	flag.BoolVar(&opts.WebDav, "webdav", false, "enable webdav")
	flag.IntVar(&opts.WebDavPort, "wp", 8001, "webdav port")
	flag.IntVar(&opts.WebDavPort, "webdav-port", 8001, "webdav port")
	flag.BoolVar(&opts.UploadOnly, "uo", false, "upload only")
	flag.BoolVar(&opts.UploadOnly, "upload-only", false, "upload only")
	flag.BoolVar(&opts.ReadOnly, "ro", false, "read only")
	flag.BoolVar(&opts.ReadOnly, "read-only", false, "read only")
	flag.BoolVar(&opts.NoChat, "nc", false, "")
	flag.BoolVar(&opts.NoChat, "no-chat", false, "")
	flag.BoolVar(&opts.PersistChat, "pc", false, "")
	flag.BoolVar(&opts.PersistChat, "persist-chat", false, "")
	flag.BoolVar(&opts.PersistChatImages, "pci", false, "")
	flag.BoolVar(&opts.PersistChatImages, "persist-chat-images", false, "")
	flag.BoolVar(&opts.NoDelete, "nd", false, "")
	flag.BoolVar(&opts.NoDelete, "no-delete", false, "")
	flag.BoolVar(&opts.Verbose, "V", false, "verbose")
	flag.BoolVar(&opts.Verbose, "verbose", false, "verbose")
	flag.BoolVar(&opts.Silent, "si", false, "silent")
	flag.BoolVar(&opts.Silent, "silent", false, "silent")
	flag.StringVar(&opts.DropUser, "u", "", "user")
	flag.StringVar(&opts.DropUser, "user", "", "user")
	flag.BoolVar(&opts.CLI, "c", false, "cli")
	flag.BoolVar(&opts.CLI, "cli", false, "cli")
	flag.BoolVar(&opts.LetsEncrypt, "sl", false, "letsencrypt")
	flag.BoolVar(&opts.LetsEncrypt, "lets-encrypt", false, "letsencrypt")
	flag.StringVar(&opts.LEDomains, "sld", "", "")
	flag.StringVar(&opts.LEDomains, "le-domains", "", "")
	flag.StringVar(&opts.LEEmail, "sle", "", "")
	flag.StringVar(&opts.LEEmail, "le-email", "", "")
	flag.StringVar(&opts.LEHTTPPort, "slh", "80", "")
	flag.StringVar(&opts.LEHTTPPort, "le-http", "80", "")
	flag.StringVar(&opts.LETLSPort, "slt", "443", "")
	flag.StringVar(&opts.LETLSPort, "le-tls", "443", "")
	flag.BoolVar(&opts.Embedded, "e", false, "")
	flag.BoolVar(&opts.Embedded, "embedded", false, "")
	flag.StringVar(&opts.Output, "o", "", "")
	flag.StringVar(&opts.Output, "output", "", "")
	flag.BoolVar(&opts.WebhookEnabled, "W", false, "")
	flag.BoolVar(&opts.WebhookEnabled, "webhook", false, "")
	flag.StringVar(&opts.WebhookURL, "Wu", "", "")
	flag.StringVar(&opts.WebhookURL, "webhook-url", "", "")
	flag.StringVar(&opts.WebhookEvents, "We", "all", "")
	flag.StringVar(&opts.WebhookEvents, "webhook-events", "all", "")
	flag.StringVar(&opts.WebhookProvider, "Wp", "Discord", "")
	flag.StringVar(&opts.WebhookProvider, "webhook-provider", "Discord", "")
	flag.StringVar(&opts.Whitelist, "ipw", "", "")
	flag.StringVar(&opts.Whitelist, "ip-whitelist", "", "")
	flag.StringVar(&opts.TrustedProxies, "tpw", "", "")
	flag.StringVar(&opts.TrustedProxies, "trusted-proxy-whitelist", "", "")
	flag.StringVar(&opts.UploadFolder, "uf", "", "")
	flag.StringVar(&opts.UploadFolder, "upload-folder", "", "")
	flag.BoolVar(&opts.MDNS, "m", false, "Enable zeroconf mDNS registration")
	flag.BoolVar(&opts.MDNS, "mdns", false, "Enable zeroconf mDNS registration")
	flag.BoolVar(&opts.Invisible, "I", false, "Enable invisible mode")
	flag.BoolVar(&opts.Invisible, "invisible", false, "Enable invisible mode")
	flag.BoolVar(&opts.Tunnel, "t", false, "Enable tunnel")
	flag.BoolVar(&opts.Tunnel, "tunnel", false, "Enable tunnel")
	flag.BoolVar(&opts.DNS, "dns", false, "Enable DNS server")
	flag.BoolVar(&opts.DNS, "dns-server", false, "Enable DNS server")
	flag.IntVar(&opts.DNSPort, "dns-port", 8053, "DNS server port")
	flag.StringVar(&opts.DNSIP, "dns-ip", "127.0.0.1", "DNS server Reply IP")
	flag.BoolVar(&opts.SMTP, "smtp", false, "Enable SMTP server")
	flag.BoolVar(&opts.SMTP, "smtp-server", false, "Enable SMTP server")
	flag.IntVar(&opts.SMTPPort, "smtp-port", 2525, "SMTP server port")
	flag.StringVar(&opts.SMTPDomain, "smtp-domain", "", "SMTP server domain")
	flag.BoolVar(&opts.SMB, "smb", false, "Enable SMB server")
	flag.BoolVar(&opts.SMB, "smb-server", false, "Enable SMB server")
	flag.IntVar(&opts.SMBPort, "smb-port", 445, "SMB server port")
	flag.StringVar(&opts.SMBDomain, "smb-domain", "GOSHS", "SMB server domain")
	flag.StringVar(&opts.SMBShare, "smb-share", "goshs", "SMB server share")
	flag.StringVar(&opts.SMBWordlist, "smb-wordlist", "", "Wordlist file for SMB hash cracking")
	flag.Int64Var(&opts.MaxUploadSize, "mu", 0, "Maximum upload size in bytes (0 = unlimited)")
	flag.Int64Var(&opts.MaxUploadSize, "max-upload", 0, "Maximum upload size in bytes (0 = unlimited)")
	flag.BoolVar(&opts.Catcher, "catcher", false, "Enable reverse shell catcher")
	flag.BoolVar(&opts.Catcher, "rc", false, "Enable reverse shell catcher")
	flag.BoolVar(&opts.LDAP, "ldap", false, "Enable LDAP server")
	flag.BoolVar(&opts.LDAP, "ldap-server", false, "Enable LDAP server")
	flag.IntVar(&opts.LDAPPort, "ldap-port", 389, "LDAP server port")
	flag.BoolVar(&opts.LDAPJNDIEnabled, "ldap-jndi", false, "Enable dynamic JNDI mode (baseDN becomes the class name)")
	flag.StringVar(&opts.LDAPJNDIBase, "ldap-jndi-base", "", "JNDI codeBase URL override (default: auto from HTTP server)")
	flag.StringVar(&opts.LDAPWordlist, "ldap-wordlist", "", "Wordlist file for LDAP NTLM hash cracking")
	flag.BoolVar(&opts.FTP, "ftp", false, "Enable FTP server")
	flag.IntVar(&opts.FTPPort, "ftp-port", 2121, "FTP server port")
	flag.BoolVar(&opts.FTPSFTPMode, "ftp-sftp", false, "Use SFTP instead of plain FTP")
	flag.StringVar(&opts.FTPKeyFile, "fkf", "", "")
	flag.StringVar(&opts.FTPKeyFile, "ftp-keyfile", "", "")
	flag.StringVar(&opts.FTPHostKeyFile, "fhk", "", "")
	flag.StringVar(&opts.FTPHostKeyFile, "ftp-host-keyfile", "", "")
	flag.BoolVar(&opts.TFTP, "tftp", false, "Enable TFTP server")
	flag.BoolVar(&opts.TFTP, "tftp-server", false, "Enable TFTP server")
	flag.IntVar(&opts.TFTPPort, "tftp-port", 69, "TFTP server port")
	flag.DurationVar(&opts.TTL, "ttl", 0, "Self-destruct: shut down automatically after this duration (e.g. 30m, 2h); 0 disables")
	flag.BoolVar(&opts.TUI, "tui", false, "Run the interactive terminal dashboard")
	flag.BoolVar(&opts.Template, "template", false, "Enable ?tpl payload templating in served files")
	var tplVars stringSliceFlag
	flag.Var(&tplVars, "tpl-var", "Template variable KEY=VALUE (repeatable), e.g. LPORT=4444")

	// One-shot flags
	upd := flag.Bool("update", false, "update")
	printConfig := flag.Bool("P", false, "print config")
	printConfigLong := flag.Bool("print-config", false, "print config")
	hash := flag.Bool("H", false, "hash")
	hashLong := flag.Bool("hash", false, "hash")
	version := flag.Bool("v", false, "goshs version")
	comp := flag.String("completion", "", "shell for completion (bash, fish, zsh)")

	flag.Usage = usage()

	flag.Parse()

	// Collect repeatable template variables.
	opts.TemplateVars = []string(tplVars)

	// Check and execute one-shot functions and execute -> early exit
	oneShotFunctions(upd, hash, hashLong, version, comp)

	// Check for print config flag
	if *printConfig || *printConfigLong {
		return opts, true
	}

	opts.WebhookEventsParsed = strings.Split(opts.WebhookEvents, ",")
	for i, event := range opts.WebhookEventsParsed {
		opts.WebhookEventsParsed[i] = strings.TrimSpace(strings.ToLower(event))
	}

	if opts.UploadFolder == "" {
		opts.UploadFolder = opts.Webroot
	}

	opts.IP = resolveInterface(opts.IP)

	return opts, false
}

func usage() func() {
	return func() {
		fmt.Printf(`
goshs %s
Usage: %s [options]

Web server options:
  -i,  --ip             IP or Interface to listen on              (default: 0.0.0.0)
  -p,  --port           The port to listen on                     (default: 8000)
  -d,  --dir            The web root directory                    (default: current working path)
  -w,  --webdav         Also serve using webdav protocol          (default: false)
  -wp, --webdav-port    The port to listen on for webdav          (default: 8001)
  -ro, --read-only      Read only mode, no upload possible        (default: false)
  -uo, --upload-only    Upload only mode, no download possible    (default: false)
  -uf, --upload-folder  Specify a different upload folder         (default: current working path)
  -mu, --max-upload     Maximum upload size in bytes, 0=unlimited (default: 0)
  -nc, --no-chat        Disable the team chat                     (default: false)
  -pc, --persist-chat   Persist chat to disk (.goshs-chat/)       (default: false)
  -pci,--persist-chat-images  Write pasted chat images to disk   (default: false)
  -nd, --no-delete      Disable the delete option                 (default: false)
  -si, --silent         Running without dir listing               (default: false)
  -I,  --invisible      Invisible mode                            (default: false)
  -c,  --cli            Enable cli (only with auth and tls)       (default: false)
  --catcher, -rc        Enable reverse shell catcher              (default: false)
  -e,  --embedded       Show embedded files in UI                 (default: false)
  -o,  --output         Write output to logfile                   (default: false)
  -t,  --tunnel         Enable tunnel                             (default: false)

TLS options:
  -s,     --ssl           Use TLS
  -ss,    --self-signed   Use a self-signed certificate
  -sk,    --server-key    Path to server key
  -sc,    --server-cert   Path to server certificate
  -p12,   --pkcs12        Path to server p12
  -p12np, --p12-no-pass   Server p12 has empty password
  -sl,    --lets-encrypt  Use Let's Encrypt as certification service
  -sld,   --le-domains    Domain(s) to request from Let's Encrypt	   (comma separated list)
  -sle,   --le-email      Email to use with Let's Encrypt
  -slh,   --le-http       Port to use for Let's Encrypt HTTP Challenge	   (default: 80)
  -slt,   --le-tls        Port to use for Let's Encrypt TLS ALPN Challenge (default: 443)

FTP/SFTP server options:
  -ftp                          Activate FTP server capabilities          (default: false)
  -ftp-port                     The port FTP/SFTP listens on              (default: 2121)
  -ftp-sftp                     Switch to SFTP instead of plain FTP       (default: false)
  -fkf, --ftp-keyfile           Authorized_keys file for SFTP pubkey auth
  -fhk, --ftp-host-keyfile      SSH host key file for SFTP identification

TFTP server options:
  -tftp, --tftp-server          Activate TFTP server capabilities         (default: false)
  -tftp-port                    The port TFTP listens on                  (default: 69)

SMB server options:
  -smb                        Activate SMB server capabilities         (default: false)
  -smb-port,   --smb-port     The port SMB listens on                  (default: 445)
  -smb-domain, --smb-domain   The domain to use for SMB authentication (default: WORKGROUP)
  -smb-share,  --smb-share    The share to use for SMB authentication  (default: goshs)
  -smb-wordlist               Wordlist file for quick hash cracking    (default: none)

LDAP server options:
  -ldap, --ldap-server         Activate LDAP credential capture server (default: false)
  -ldap-port                   The port LDAP listens on                 (default: 389)
  -ldap-jndi                   Enable dynamic JNDI mode — baseDN in the search becomes the
                               factory class name, fetched from the goshs HTTP server
  -ldap-jndi-base              Override codeBase URL for JNDI payloads  (default: auto)
  -ldap-wordlist               Wordlist file for quick LDAP NTLM hash cracking
  Use -s -ss or -s -sc/-sk to enable LDAPS (TLS) on default port 636

Authentication options:
  -b,  --basic-auth     Use basic authentication (user:pass - user can be empty)
  -ca, --cert-auth      Use certificate based authentication - provide ca certificate
  -H,  --hash           Hash a password for file based ACLs

Connection restriction:
  -ipw, --ip-whitelist             Comma separated list of IPs to whitelist
  -tpw, --trusted-proxy-whitelist  Comma separated list of trusted proxies

Collaboration options:
  -dns, --dns-server           Enable DNS server                   (default: false)
  -dns-port, --dns-port        DNS server port                     (default: 8053)
  -dns-ip, --dns-ip            DNS server Reply IP                 (default: 127.0.0.1)
  -smtp, --smtp-server         Enable SMTP server                  (default: false)
  -smtp-port, --smtp-port      SMTP server port                    (default: 2525)
  -smtp-domain, --smtp-domain  SMTP server domain                  (default: open relay)

Webhook options:
  -W,  --webhook            Enable webhook support                      (default: false)
  -Wu, --webhook-url        URL to send webhook requests to
  -We, --webhook-events     Comma separated list of events to notify
                            [all, upload, delete, download, view, webdav,
                            ftp, smb, dns, smtp, redirect, verbose]	    (default: all)
  -Wp, --webhook-provider   Webhook provider
                            [Discord, Mattermost, Slack]                (default: Discord)

Payload templating:
      --template      Render {{.VAR}} placeholders in files requested with ?tpl (default: false)
      --tpl-var       Template variable KEY=VALUE (repeatable), e.g. LPORT=4444
                      LHOST defaults to -i when a single IP is bound; on 0.0.0.0 pass --tpl-var LHOST=

Misc options:
  -C  --config        Provide config file path                (default: false)
  -P  --print-config  Print sample config to STDOUT           (default: false)
  -u  --user          Drop privs to user (unix only)          (default: current user)
      --update        Update goshs to most recent version
  -m  --mdns          Enable zeroconf mDNS registration       (default: false)
      --tui           Run the interactive terminal dashboard  (default: false)
      --ttl           Self-destruct after a duration, e.g. 30m, 2h (default: disabled)
  -V  --verbose       Activate verbose log output             (default: false)
  -v                  Print the current goshs version

      --completion    Install shell tab completion (bash|fish|zsh)

Usage examples:
  Start with default values:    	./goshs
  Start with config file:    	        ./goshs -C /path/to/config.yaml
  Start with wevdav support:    	./goshs -w
  Start with different port:    	./goshs -p 8080
  Start with self-signed cert:  	./goshs -s -ss
  Start with let's encrypt:		./goshs -s -sl -sle your@mail.com -sld your.domain.com,your.seconddomain.com
  Start with custom cert:       	./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        	./goshs -b 'secret-user:$up3r$3cur3'
  Start with basic auth bcrypt hash:   	./goshs -b 'secret-user:$2a$14$ydRJ//Ob4SctB/D7o.rvU.LmPs/vwXkeXCbtpCqzgOJDSShLgiY52'
  Start with basic auth empty user:	./goshs -b ':$up3r$3cur3'
  Start with cli enabled:           	./goshs -b 'secret-user:$up3r$3cur3' -s -ss -c
  Start with payload templating:    	./goshs -i 10.10.14.7 --template --tpl-var LPORT=4444

`, goshsversion.GoshsVersion, os.Args[0])
	}
}

func oneShotFunctions(upd, hash, hashLong, version *bool, comp *string) {
	// Check for update flag
	if *upd {
		err := update.UpdateTool(goshsversion.GoshsVersion)
		if err != nil {
			logger.Fatalf("Failed to update tool: %+v", err)
		}
		os.Exit(0)
	}

	// Check for hash flag
	if *hash || *hashLong {
		fmt.Printf("Enter password: ")
		password, err := gopass.GetPasswdMasked()
		if err != nil {
			logger.Fatalf("error reading password from stdin: %+v", err)
		}
		utils.GenerateHashedPassword(password)
		os.Exit(0)
	}

	// Check for version flag
	if *version {
		logger.PrintBanner(goshsversion.GoshsVersion)
		os.Exit(0)
	}

	// Check for completion flag
	if *comp != "" {
		if err := completion.Install(*comp); err != nil {
			logger.Fatalf("completion install failed: %+v", err)
		}
		os.Exit(0)
	}
}

func resolveInterface(ip string) string {
	// If it parses as an IP address (v4 or v6), use it directly.
	if net.ParseIP(ip) != nil {
		return ip
	}
	// Otherwise treat it as an interface name and resolve to its IPv4 address.
	addr, err := utils.GetInterfaceIpv4Addr(ip)
	if err != nil {
		logger.Fatal(err)
		os.Exit(-1)
	}
	if addr == "" {
		logger.Fatal("IP address cannot be found for provided interface")
		os.Exit(-1)
	}
	return addr
}
