package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/options"
)

func writeTempConfig(t *testing.T, cfg Config) string {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "goshs-cfg-*.json")
	require.NoError(t, err)
	_, err = f.Write(b)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLoadConfig_BasicFields(t *testing.T) {
	cfg := Config{
		Interface:  "127.0.0.1",
		Port:       9090,
		Directory:  "/tmp/testroot",
		SSL:        true,
		SelfSigned: true,
	}

	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", result.IP)
	require.Equal(t, 9090, result.Port)
	require.Equal(t, "/tmp/testroot", result.Webroot)
	require.True(t, result.SSL)
	require.True(t, result.SelfSigned)
}

func TestLoadConfig_BasicAuth(t *testing.T) {
	cfg := Config{
		AuthUsername: "alice",
		AuthPassword: "s3cret",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "alice:s3cret", result.BasicAuth)
}

func TestLoadConfig_UploadFolderDefaultsToWebroot(t *testing.T) {
	cfg := Config{
		Directory:    "/srv/web",
		UploadFolder: "",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "/srv/web", result.UploadFolder, "upload folder should default to webroot when not set")
}

func TestLoadConfig_ExplicitUploadFolder(t *testing.T) {
	cfg := Config{
		Directory:    "/srv/web",
		UploadFolder: "/srv/uploads",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.Equal(t, "/srv/uploads", result.UploadFolder)
}

func TestLoadConfig_WebhookFields(t *testing.T) {
	cfg := Config{
		WebhookEnabled:  true,
		WebhookURL:      "https://hooks.example.com/abc",
		WebhookProvider: "slack",
		WebhookEvents:   []string{"upload", "download"},
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.WebhookEnabled)
	require.Equal(t, "https://hooks.example.com/abc", result.WebhookURL)
	require.Equal(t, "slack", result.WebhookProvider)
	require.Equal(t, []string{"upload", "download"}, result.WebhookEventsParsed)
}

func TestLoadConfig_ConfigPathIsAbsolute(t *testing.T) {
	cfg := Config{}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(result.ConfigPath))
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	opts := &options.Options{ConfigFile: "/nonexistent/path/config.json"}
	_, err := LoadConfig(opts)
	require.Error(t, err)
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.json")
	require.NoError(t, err)
	_, err = f.WriteString("{not valid json")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	opts := &options.Options{ConfigFile: f.Name()}
	_, err = LoadConfig(opts)
	require.Error(t, err)
}

func TestPrintExample_ValidJSON(t *testing.T) {
	out, err := PrintExample()
	require.NoError(t, err)
	require.NotEmpty(t, out)

	// Must be valid JSON
	var cfg Config
	err = json.Unmarshal([]byte(out), &cfg)
	require.NoError(t, err)
}

func TestPrintExample_DefaultValues(t *testing.T) {
	out, err := PrintExample()
	require.NoError(t, err)

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(out), &cfg))
	require.Equal(t, "0.0.0.0", cfg.Interface)
	require.Equal(t, 8000, cfg.Port)
	require.Equal(t, ".", cfg.Directory)
	require.Equal(t, "discord", cfg.WebhookProvider)
}

func TestLoadConfig_SMBFields(t *testing.T) {
	cfg := Config{
		SMBServer:   true,
		SMBPort:     8445,
		SMBDomain:   "WORKGROUP",
		SMBShare:    "myshare",
		SMBWordlist: "/tmp/wordlist.txt",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.SMB)
	require.Equal(t, 8445, result.SMBPort)
	require.Equal(t, "WORKGROUP", result.SMBDomain)
	require.Equal(t, "myshare", result.SMBShare)
	require.Equal(t, "/tmp/wordlist.txt", result.SMBWordlist)
}

func TestLoadConfig_SMTPFields(t *testing.T) {
	cfg := Config{
		SMTPServer: true,
		SMTPPort:   2525,
		SMTPDomain: "mail.example.com",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.SMTP)
	require.Equal(t, 2525, result.SMTPPort)
	require.Equal(t, "mail.example.com", result.SMTPDomain)
}

func TestLoadConfig_DNSFields(t *testing.T) {
	cfg := Config{
		DNSServer: true,
		DNSPort:   8053,
		DNSIP:     "10.0.0.1",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.DNS)
	require.Equal(t, 8053, result.DNSPort)
	require.Equal(t, "10.0.0.1", result.DNSIP)
}

func TestLoadConfig_FTPSFTPFields(t *testing.T) {
	cfg := Config{
		FTP:            true,
		FTPPort:        2022,
		FTPSFTPMode:    true,
		FTPKeyFile:     "/etc/goshs/authorized_keys",
		FTPHostKeyFile: "/etc/goshs/host_key",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.FTP)
	require.Equal(t, 2022, result.FTPPort)
	require.True(t, result.FTPSFTPMode)
	require.Equal(t, "/etc/goshs/authorized_keys", result.FTPKeyFile)
	require.Equal(t, "/etc/goshs/host_key", result.FTPHostKeyFile)
}

func TestLoadConfig_TLSFields(t *testing.T) {
	cfg := Config{
		SSL:         true,
		PrivateKey:  "/etc/goshs/server.key",
		Certificate: "/etc/goshs/server.crt",
		P12:         "/etc/goshs/server.p12",
		P12NoPass:   true,
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.SSL)
	require.Equal(t, "/etc/goshs/server.key", result.MyKey)
	require.Equal(t, "/etc/goshs/server.crt", result.MyCert)
	require.Equal(t, "/etc/goshs/server.p12", result.MyP12)
	require.True(t, result.P12NoPass)
}

func TestLoadConfig_BooleanFlags(t *testing.T) {
	cfg := Config{
		ReadOnly:   true,
		UploadOnly: false,
		NoDelete:   true,
		NoChat:     true,
		Invisible:  true,
		Silent:     true,
		Verbose:    true,
		Tunnel:     true,
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.ReadOnly)
	require.False(t, result.UploadOnly)
	require.True(t, result.NoDelete)
	require.True(t, result.NoChat)
	require.True(t, result.Invisible)
	require.True(t, result.Silent)
	require.True(t, result.Verbose)
	require.True(t, result.Tunnel)
}

func TestLoadConfig_LetsEncryptFields(t *testing.T) {
	cfg := Config{
		LetsEncrypt:         true,
		LetsEncryptDomain:   "example.com",
		LetsEncryptEmail:    "admin@example.com",
		LetsEncryptHTTPPort: "80",
		LetsEncryptTLSPort:  "443",
	}
	path := writeTempConfig(t, cfg)
	opts := &options.Options{ConfigFile: path}
	result, err := LoadConfig(opts)
	require.NoError(t, err)
	require.True(t, result.LetsEncrypt)
	require.Equal(t, "example.com", result.LEDomains)
	require.Equal(t, "admin@example.com", result.LEEmail)
	require.Equal(t, "80", result.LEHTTPPort)
	require.Equal(t, "443", result.LETLSPort)
}
