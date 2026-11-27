package sanity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goshs.de/goshs/v2/ca"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/update"
	"goshs.de/goshs/v2/utils"
)

func Sanitize(opts *options.Options) (*options.Options, error) {
	var err error
	wd, _ := os.Getwd()

	// Abspath for webroot
	// Trim trailing / for linux/mac and \ for windows
	opts.Webroot = strings.TrimSuffix(opts.Webroot, "/")
	opts.Webroot = strings.TrimSuffix(opts.Webroot, "\\")
	if !filepath.IsAbs(opts.Webroot) {
		opts.Webroot, err = filepath.Abs(filepath.Join(wd, opts.Webroot))
		if err != nil {
			return opts, fmt.Errorf("Webroot cannot be constructed: %w", err)
		}
	}

	return opts, nil
}

func Check(opts *options.Options) (*options.Options, error) {
	if opts.ConfigFile != "" {
		if opts.Webroot == filepath.Dir(opts.ConfigPath) {
			logger.Warn("You are hosting your config file in the webroot of goshs. This is not recommended.")
			// Check if the process user can write the config file
			file, err := os.OpenFile(opts.ConfigPath, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return opts, err
			}
			defer file.Close()
			return opts, fmt.Errorf("%s", "The config file is accessible via goshs and is writeable by the user running goshs. This is a security issue. Read the docs at https://goshs.de/en/usage/config/index.html")
		}

		if _, pass, _ := strings.Cut(opts.BasicAuth, ":"); !utils.IsBcryptHash(pass) {
			logger.Warn("The password in the config file is not hashed. This is not recommended. Use goshs -H to hash the password.")
		}
	}
	// Sanity check for invisible mode
	if opts.Invisible {
		opts.WebDav = false
		opts.MDNS = false
		opts.Silent = false
		opts.DNS = false
		opts.SMTP = false
		opts.LDAP = false
		opts.FTP = false
		opts.TFTP = false
		logger.Warn("Invisible mode activated, disabling FTP/SFTP, TFTP, WebDAV, silent mode, DNS, SMTP, LDAP and mDNS support")
	}

	// Sanity checks for running without the HTTP server (--no-http)
	if opts.NoHTTP {
		if opts.Tunnel {
			return opts, fmt.Errorf("--tunnel exposes the HTTP server and cannot be combined with --no-http")
		}
		if !opts.WebDav && !opts.FTP && !opts.TFTP && !opts.SMB && !opts.LDAP && !opts.DNS && !opts.SMTP && !opts.TUI {
			return opts, fmt.Errorf("--no-http leaves nothing to serve: enable at least one other server (e.g. -w, -ftp, -tftp, -smb, -ldap, -dns, -smtp) or --tui")
		}
		if opts.CLI || opts.Silent {
			logger.Warn("--no-http is set: the web-only options -c/--cli and -si/--silent have no effect")
		}
		if opts.LDAP && opts.LDAPJNDIEnabled && opts.LDAPJNDIBase == "" {
			logger.Warn("--ldap-jndi derives its codeBase from the HTTP server, which --no-http disables; set --ldap-jndi-base to an external URL")
		}
	}

	// Sanity check for upload only vs read only
	if opts.UploadOnly && opts.ReadOnly {
		logger.Fatal("You can only select either 'upload only' or 'read only', not both.")
	}

	// Sanity check if cli mode is combined with auth and tls
	if opts.CLI && (!opts.SSL || opts.BasicAuth == "") {
		if opts.CLI && (!opts.SSL || opts.CertAuth == "") {
			logger.Fatal("With cli mode you need to enable basic/cert auth and tls for security reasons.")
		}
	}

	// Sanity check if catcher mode is combined with auth and tls
	if opts.Catcher && (!opts.SSL || opts.BasicAuth == "") {
		if opts.Catcher && (!opts.SSL || opts.CertAuth == "") {
			logger.Fatal("With catcher mode you need to enable basic/cert auth and tls for security reasons.")
		}
	}

	// Sanity check if CA mode enabled you will also need TLS enabled in some way
	if opts.CertAuth != "" && !opts.SSL {
		logger.Fatal("To use certificate based authentication with a CA cert you will need tls in any mode (-ss, -sk/-sc, -p12, -sl)")
	}

	// Sanity check for self-destruct timer
	if opts.TTL < 0 {
		logger.Fatal("The self-destruct timer (--ttl) cannot be negative.")
	}

	// Payload templating needs a source for {{.LHOST}}: either a single bound IP
	// (-i) or an explicit --tpl-var LHOST=. Warn (not fatal) so templates that do
	// not reference LHOST still work.
	if opts.Template {
		hasLHOST := false
		for _, kv := range opts.TemplateVars {
			if strings.HasPrefix(kv, "LHOST=") {
				hasLHOST = true
				break
			}
		}
		if !hasLHOST && (opts.IP == "" || opts.IP == "0.0.0.0") {
			logger.Warn("--template is enabled but no LHOST source: bind a single IP with -i or pass --tpl-var LHOST=...; {{.LHOST}} templates will error until set.")
		}
	}

	// Sanity check either user:pass or keyfile when using sftp mode
	if opts.FTP && opts.FTPSFTPMode && (opts.BasicAuth == "" && opts.FTPKeyFile == "") {
		logger.Fatal("When using SFTP you need to either specify an authorized keyfile using -fkf or username and password using -b")
	}

	// Sanity check: empty username is not valid for SFTP password auth
	if opts.FTP && opts.FTPSFTPMode && strings.HasPrefix(opts.BasicAuth, ":") {
		logger.Fatal("When using SFTP with password authentication, the username cannot be empty. Please provide a non-empty username with -b 'user:pass'.")
	}

	// Sanity check: empty password is not valid for SFTP password auth either.
	// SFTP auth is mandatory, and an empty -b password (e.g. -b "$U:$UNSET")
	// would accept the username with no password (GHSA-hhv7-wp66-4vfv).
	if opts.FTP && opts.FTPSFTPMode && opts.BasicAuth != "" && strings.HasSuffix(opts.BasicAuth, ":") {
		logger.Fatal("When using SFTP with password authentication, the password cannot be empty. Please provide a non-empty password with -b 'user:pass', or use an authorized keyfile (-fkf).")
	}

	if yes, out := update.CheckForUpdates(goshsversion.GoshsVersion); yes {
		logger.Warnf("There is a newer Version (%s) of goshs available. Run --update to update goshs.", out)
	} else {
		if out != "" {
			logger.Warnf("Failed to check for updates: %+v", out)
		} else {
			logger.Infof("You are running the newest version (%s) of goshs", goshsversion.GoshsVersion)
		}
	}

	return opts, nil
}

func FurtherProcessing(opts *options.Options) (*options.Options, error) {
	// Parse repeatable --tpl-var KEY=VALUE entries (from CLI or config) into a map.
	// Runs here so both the CLI flags and config-file values are merged in first.
	opts.TemplateVarsParsed = make(map[string]string)
	for _, kv := range opts.TemplateVars {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			logger.Warnf("ignoring malformed --tpl-var %q (expected KEY=VALUE)", kv)
			continue
		}
		opts.TemplateVarsParsed[key] = val
	}

	// check for basic auth
	if opts.BasicAuth != "" {
		auth := strings.SplitN(opts.BasicAuth, ":", 2)
		if len(auth) < 2 {
			fmt.Println("Wrong basic auth format. Please provide user:password separated by a colon")
			os.Exit(-1)
		}
		opts.Username = auth[0]
		opts.Password = auth[1]
		// NTLM (SMB) is computed from the plaintext password. With the bcrypt
		// form of -b the hash string itself would become the SMB password
		// (GHSA-qjjr-pc25-pj69), so refuse the combination.
		if opts.SMB && utils.IsBcryptHash(opts.Password) {
			return opts, fmt.Errorf("-smb needs the plaintext password in -b: SMB (NTLM) cannot verify a bcrypt hash")
		}
	}

	// If Let's Encrypt is in play we need to fetch the key and cert, write them to disc and set their path in MyKey and MyCert
	if opts.LetsEncrypt {
		ca.GetLECertificateAndKey(opts.LEEmail, strings.Split(opts.LEDomains, ","), opts.LEHTTPPort, opts.LETLSPort)
		opts.MyCert = "cert"
		opts.MyKey = "key"
	}

	// If a logpath/-file is provided via -o/--output set the multiwriter to output both
	if opts.Output != "" {
		if !filepath.IsAbs(opts.Output) {
			// If the provided path is not an abspath then merge with CWD
			wd, _ := os.Getwd()
			opts.Output = filepath.Join(wd, opts.Output)
		}

		logFile, err := os.OpenFile(opts.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.Panicf("Cannot open file to write output logfile: %s - %+v", opts.Output, err)
		}

		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger.LogFile(multiWriter)
	}

	return opts, nil
}
