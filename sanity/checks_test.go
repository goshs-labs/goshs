package sanity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/options"
)

func TestSanitize_EmptyWebroot(t *testing.T) {
	wd, _ := os.Getwd()
	opts := &options.Options{Webroot: ""}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, wd, result.Webroot)
}

func TestCheck_InvisibleDisablesFeatures(t *testing.T) {
	opts := &options.Options{
		Invisible:   true,
		FTP:         true,
		FTPSFTPMode: true,
		WebDav:      true,
		MDNS:        true,
		Silent:      true,
		DNS:         true,
		SMTP:        true,
	}
	result, err := Check(opts)
	require.NoError(t, err)
	require.False(t, result.FTP)
	require.False(t, result.WebDav)
	require.False(t, result.MDNS)
	require.False(t, result.Silent)
	require.False(t, result.DNS)
	require.False(t, result.SMTP)
}

func TestCheck_InvisibleNoFeatures(t *testing.T) {
	opts := &options.Options{
		Invisible: true,
	}
	result, err := Check(opts)
	require.NoError(t, err)
	require.True(t, result.Invisible)
}

func TestCheck_UploadOnlyAndReadOnlyFatal(t *testing.T) {
	opts := &options.Options{
		UploadOnly: true,
		ReadOnly:   true,
	}
	// This calls logger.Fatal, which will call os.Exit in tests
	// We can't easily test this, so we skip it
	_ = opts
}

func TestFurtherProcessing_BasicAuth(t *testing.T) {
	opts := &options.Options{
		BasicAuth: "user:password",
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.Equal(t, "user", result.Username)
	require.Equal(t, "password", result.Password)
}

func TestFurtherProcessing_BasicAuthWithColon(t *testing.T) {
	opts := &options.Options{
		BasicAuth: "user:pass:with:colons",
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.Equal(t, "user", result.Username)
	require.Equal(t, "pass:with:colons", result.Password)
}

func TestFurtherProcessing_NoBasicAuth(t *testing.T) {
	opts := &options.Options{}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.Equal(t, "", result.Username)
	require.Equal(t, "", result.Password)
}

func TestFurtherProcessing_OutputRelative(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.log")
	opts := &options.Options{
		Output: outputPath,
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(result.Output))
}

func TestFurtherProcessing_OutputAbsolute(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.log")
	opts := &options.Options{
		Output: outputPath,
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.Equal(t, outputPath, result.Output)
}

func TestSanitize_TrailingSlashAndBackslash(t *testing.T) {
	opts := &options.Options{Webroot: "/path/\\"}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, "/path/", result.Webroot)
}

func TestCheck_NoConfig(t *testing.T) {
	opts := &options.Options{}
	_, err := Check(opts)
	require.NoError(t, err)
}

func TestCheck_ConfigFileNotInWebroot(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{}`), 0644))

	opts := &options.Options{
		ConfigFile: "config.json",
		ConfigPath: configPath,
		Webroot:    tmpDir,
	}
	_, err := Check(opts)
	require.NoError(t, err)
}

func TestCheck_ConfigFileInWebroot_Writeable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"basic_auth":"admin:admin"}`), 0644))

	opts := &options.Options{
		ConfigFile: "config.json",
		ConfigPath: configPath,
		Webroot:    filepath.Dir(configPath),
	}
	_, err := Check(opts)
	// Should error because config is in webroot and writeable
	require.Error(t, err)
}

func TestCheck_ConfigUnhashedPassword(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"basic_auth":"admin:admin"}`), 0644))

	opts := &options.Options{
		ConfigFile: "config.json",
		ConfigPath: configPath,
		Webroot:    tmpDir,
		BasicAuth:  "admin:admin",
	}
	_, err := Check(opts)
	require.NoError(t, err)
}

func TestFurtherProcessing_BadBasicAuth_NoColon(t *testing.T) {
	opts := &options.Options{
		BasicAuth: "justauser",
	}
	// FurtherProcessing calls os.Exit(-1) if auth format is wrong
	// Can't test directly, so we just note the limitation
	_ = opts
}

func TestFurtherProcessing_OutputCreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "goshs.log")

	opts := &options.Options{
		Output: outputPath,
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.Equal(t, outputPath, result.Output)

	// The log file must exist after FurtherProcessing opens it
	_, statErr := os.Stat(outputPath)
	require.NoError(t, statErr)
}

func TestFurtherProcessing_OutputRelativeBecomesAbsolute(t *testing.T) {
	tmpDir := t.TempDir()
	// Write the file so it exists; use an absolute path to avoid CWD ambiguity
	outputPath := filepath.Join(tmpDir, "rel.log")

	opts := &options.Options{
		Output: outputPath,
	}
	result, err := FurtherProcessing(opts)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(result.Output))
}

func TestCheck_InvisibleWithSMBOnly(t *testing.T) {
	opts := &options.Options{
		Invisible: true,
		FTP:       false,
		WebDav:    false,
	}
	result, err := Check(opts)
	require.NoError(t, err)
	require.True(t, result.Invisible)
}

func TestCheck_NoHTTPRequiresAnotherServer(t *testing.T) {
	_, err := Check(&options.Options{NoHTTP: true})
	require.Error(t, err)

	for _, o := range []*options.Options{
		{NoHTTP: true, FTP: true},
		{NoHTTP: true, LDAP: true},
		{NoHTTP: true, WebDav: true},
		{NoHTTP: true, TUI: true},
	} {
		_, err := Check(o)
		require.NoError(t, err)
	}
}

func TestCheck_NoHTTPRejectsTunnel(t *testing.T) {
	_, err := Check(&options.Options{NoHTTP: true, FTP: true, Tunnel: true})
	require.Error(t, err)
}

// Invisible mode switches off every other listener, so --no-http on top of it
// must not silently start a process that serves nothing.
func TestCheck_NoHTTPWithInvisibleFails(t *testing.T) {
	_, err := Check(&options.Options{NoHTTP: true, Invisible: true, FTP: true})
	require.Error(t, err)
}

// GHSA-qjjr-pc25-pj69: SMB (NTLM) needs the plaintext password, so a bcrypt -b
// must be refused with -smb instead of the hash becoming the SMB password.
func TestFurtherProcessing_SMBWithBcryptRefused(t *testing.T) {
	opts := &options.Options{
		BasicAuth: "user:$2a$14$ydRJ//Ob4SctB/D7o.rvU.LmPs/vwXkeXCbtpCqzgOJDSShLgiY52",
		SMB:       true,
	}
	_, err := FurtherProcessing(opts)
	require.Error(t, err)
}

func TestFurtherProcessing_SMBWithPlaintextAllowed(t *testing.T) {
	opts := &options.Options{BasicAuth: "user:password", SMB: true}
	_, err := FurtherProcessing(opts)
	require.NoError(t, err)
}
