package sftpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
)

var sftpserver *SFTPServer = &SFTPServer{
	IP:          "0.0.0.0",
	Port:        2022,
	KeyFile:     "authorized_keys",
	Username:    "test",
	Password:    "test",
	Root:        os.Getenv("PWD"),
	ReadOnly:    false,
	UploadOnly:  false,
	HostKeyFile: "goshs_host_key_rsa",
	Webhook: &webhook.DiscordWebhook{
		Enabled: false,
	},
}

func TestStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})

	go func() {
		err := sftpserver.Start()
		require.NoError(t, err)
	}()
	// Wait for context timeout or server error
	<-ctx.Done()
	// Timeout reached, stop the server gracefully
	close(done)
}

func TestErrors(t *testing.T) {
	server := &SFTPServer{
		IP:          "0.0.0.0",
		Port:        2022,
		KeyFile:     "authorized_keys.foo",
		Username:    "",
		Password:    "",
		Root:        os.Getenv("PWD"),
		ReadOnly:    false,
		UploadOnly:  false,
		HostKeyFile: "",
		Webhook: &webhook.DiscordWebhook{
			Enabled: false,
		},
	}
	err := server.Start()
	require.Error(t, err)

	server = &SFTPServer{
		IP:          "0.0.0.0",
		Port:        2022,
		KeyFile:     "",
		Username:    "",
		Password:    "",
		Root:        os.Getenv("PWD"),
		ReadOnly:    false,
		UploadOnly:  false,
		HostKeyFile: "foo",
		Webhook: &webhook.DiscordWebhook{
			Enabled: false,
		},
	}
	err = server.Start()
	require.Error(t, err)
}

func TestSanitizePath(t *testing.T) {
	root := "/home/user"

	// After the security fix, traversal sequences are safely contained within
	// root rather than rejected — the client path is treated as relative to root.
	path := "/home/user/../test"
	result, err := sanitizePath(path, root)
	require.NoError(t, err)
	require.Contains(t, result, root)

	// Legitimate sub-paths resolve without error.
	path = "/home/user/foo/bar/baz"
	result, err = sanitizePath(path, root)
	require.NoError(t, err)
	require.Contains(t, result, root)

	// Absolute escape attempts (e.g. /etc/passwd) are also contained.
	path = "/etc/passwd"
	result, err = sanitizePath(path, root)
	require.NoError(t, err)
	require.Contains(t, result, root)
}

func TestReadFile(t *testing.T) {
	root := os.Getenv("PWD")
	// After the security fix, SFTP paths are client-relative (relative to root).
	req := &sftp.Request{
		Method:   "Readfile",
		Filepath: "/authorized_keys",
	}
	file, err := readFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	require.Equal(t, file.Name(), filepath.Join(root, "authorized_keys"))
}

func TestListFile(t *testing.T) {
	root := os.Getenv("PWD")
	req := &sftp.Request{
		Method:   "Stat",
		Filepath: "/authorized_keys",
	}
	files, err := listFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	file := files.files[0]
	require.Equal(t, filepath.Join(root, file.Name()), filepath.Join(root, "authorized_keys"))

	req = &sftp.Request{
		Method:   "Listfiles",
		Filepath: "/",
	}

	files, err = listFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	require.Greater(t, len(files.files), 4)
}

func TestWriteFile(t *testing.T) {
	root := os.Getenv("PWD")
	req := &sftp.Request{
		Method:   "Writefile",
		Filepath: "/test.txt",
	}
	file, err := writeFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)
	_, err = file.Write([]byte("test content"))
	require.NoError(t, err)
}

// NewSFTPServer must propagate the --no-delete flag from the options onto the
// server struct; otherwise the enforcement in cmdFile/writeFile never engages
// (GHSA-4wh5-87mw-whxf).
func TestNewSFTPServer_MapsNoDelete(t *testing.T) {
	wh := webhook.Register(false, "", "discord", []string{})
	opts := &options.Options{NoDelete: true}
	srv := NewSFTPServer(opts, &httpserver.Whitelist{}, *wh)
	require.True(t, srv.NoDelete)
}

func TestCmd(t *testing.T) {
	root := os.Getenv("PWD")

	req := &sftp.Request{
		Method:   "Stat",
		Filepath: "/authorized_keys",
	}

	err := cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Lstat",
		Filepath: "/authorized_keys",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Mkdir",
		Filepath: "/testdir",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rename",
		Filepath: "/test.txt",
		Target:   "/testdir/test.txt",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Setstat",
		Filepath: "/testdir/test.txt",
		Attrs:    []byte(`{"mode": 0644}`), // Invalid
	}
	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	// TODO: Add test for Setstat with valid attributes

	req = &sftp.Request{
		Method:   "Remove",
		Filepath: "/testdir/test.txt",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "Rmdir",
		Filepath: "/testdir",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.NoError(t, err)

	req = &sftp.Request{
		Method:   "INVALID",
		Filepath: "/",
	}

	err = cmdFile(root, req, "127.0.0.1", sftpserver)
	require.Error(t, err)
}
