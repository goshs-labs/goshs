package ftpserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/webhook"
)

// ─── GHSA-qwpj-g46h-59wx: REST + STOR in-place overwrite ────────────────────

// ftpserverlib opens a resumed STOR (REST <n> + STOR) O_WRONLY|O_CREATE without
// O_TRUNC and then seeks, overwriting the file in place. That is as
// destructive as a truncate, so it must be refused for an existing file.
func TestNoDeleteFs_BlocksPositionedOverwrite(t *testing.T) {
	base, root := newBaseFs(t)
	fs := &noDeleteFs{Fs: base}

	for _, flag := range []int{
		os.O_WRONLY | os.O_CREATE, // REST n + STOR
		os.O_WRONLY,
		os.O_RDWR,
		os.O_WRONLY | os.O_APPEND | os.O_TRUNC,
	} {
		_, err := fs.OpenFile("existing.txt", flag, 0o644)
		require.Error(t, err, "flag %#x over an existing file must be denied", flag)
	}

	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL", string(got))
}

// ─── GHSA-c3p2-6762-cf9j: --upload-only must not destroy existing files ─────

func TestClientFs_UploadOnlyProtectsExisting(t *testing.T) {
	_, root := newBaseFs(t)
	require.NoError(t, os.Mkdir(filepath.Join(root, "d2"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "d2", "x"), []byte("x"), 0o644))
	fs := (&FTPServer{Root: root, UploadOnly: true}).clientFs()

	_, err := fs.OpenFile("/existing.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.Error(t, err, "STOR over an existing file")
	_, err = fs.OpenFile("/existing.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	require.Error(t, err, "REST + STOR over an existing file")
	require.Error(t, fs.Rename("/existing.txt", "/moved.txt"), "RNFR/RNTO")
	require.Error(t, fs.Remove("/secret.txt"), "DELE")
	require.Error(t, fs.RemoveAll("/d2"), "SITE RMDIR")

	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL", string(got))
	require.FileExists(t, filepath.Join(root, "secret.txt"))
	require.FileExists(t, filepath.Join(root, "d2", "x"))

	// Dropping a new file still works, and reads stay refused.
	f, err := fs.OpenFile("/dropped.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	_, err = f.Write([]byte("new"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = fs.OpenFile("/dropped.txt", os.O_RDONLY, 0)
	require.Error(t, err)
}

// ─── End to end against a real ftpserverlib instance ─────────────────────────

type ftpTestClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func (c *ftpTestClient) reply() (int, string) {
	c.t.Helper()
	var code int
	var msg strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		require.NoError(c.t, err)
		msg.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' {
			code, err = strconv.Atoi(line[:3])
			require.NoError(c.t, err)
			return code, msg.String()
		}
	}
}

func (c *ftpTestClient) cmd(format string, args ...any) (int, string) {
	c.t.Helper()
	_, err := fmt.Fprintf(c.conn, format+"\r\n", args...)
	require.NoError(c.t, err)
	return c.reply()
}

var pasvRe = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

// stor uploads data to name, optionally preceded by REST rest, and returns the
// final reply code of the transfer (or of the STOR if it was refused).
func (c *ftpTestClient) stor(name string, data []byte, rest int) int {
	c.t.Helper()
	code, msg := c.cmd("PASV")
	require.Equal(c.t, 227, code, msg)
	m := pasvRe.FindStringSubmatch(msg)
	require.NotNil(c.t, m, msg)
	p1, _ := strconv.Atoi(m[5])
	p2, _ := strconv.Atoi(m[6])
	dc, err := net.DialTimeout("tcp", fmt.Sprintf("%s.%s.%s.%s:%d", m[1], m[2], m[3], m[4], p1*256+p2), 5*time.Second)
	require.NoError(c.t, err)
	defer dc.Close()
	if rest > 0 {
		code, msg = c.cmd("REST %d", rest)
		require.Equal(c.t, 350, code, msg)
	}
	code, _ = c.cmd("STOR %s", name)
	if code >= 400 {
		return code
	}
	_, err = dc.Write(data)
	require.NoError(c.t, err)
	require.NoError(c.t, dc.Close())
	code, _ = c.reply()
	return code
}

func startTestFTP(t *testing.T, root string, noDelete, uploadOnly bool) *ftpTestClient {
	t.Helper()
	srv := &FTPServer{
		IP:         "127.0.0.1",
		Port:       0,
		Root:       root,
		NoDelete:   noDelete,
		UploadOnly: uploadOnly,
		Webhook:    *webhook.Register(false, "", "discord", []string{}),
		Whitelist:  &httpserver.Whitelist{},
	}
	require.NoError(t, srv.Bind())
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.srv.Stop() })

	conn, err := net.DialTimeout("tcp", srv.srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	c := &ftpTestClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	code, _ := c.reply()
	require.Equal(t, 220, code)
	code, _ = c.cmd("USER anonymous")
	require.Equal(t, 331, code)
	code, _ = c.cmd("PASS x")
	require.Equal(t, 230, code)
	code, _ = c.cmd("TYPE I")
	require.Equal(t, 200, code)
	return c
}

func TestFTP_E2E_RestStorRefusedUnderModeFlags(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		noDelete, uploadOnly bool
	}{
		{"no-delete", true, false},
		{"upload-only", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			keep := filepath.Join(root, "keep.txt")
			require.NoError(t, os.WriteFile(keep, []byte("ORIGINAL-IMPORTANT-CONTENT\n"), 0o644))
			c := startTestFTP(t, root, tc.noDelete, tc.uploadOnly)

			require.GreaterOrEqual(t, c.stor("keep.txt", []byte("x"), 0), 400, "plain STOR over existing")
			require.GreaterOrEqual(t, c.stor("keep.txt", []byte(strings.Repeat("#", 4096)), 1), 400, "REST 1 + STOR over existing")
			code, _ := c.cmd("DELE keep.txt")
			require.GreaterOrEqual(t, code, 400, "DELE")

			got, err := os.ReadFile(keep)
			require.NoError(t, err)
			require.Equal(t, "ORIGINAL-IMPORTANT-CONTENT\n", string(got))

			// A fresh upload still succeeds.
			require.Equal(t, 226, c.stor("new.txt", []byte("hello"), 0))
			f, err := os.Open(filepath.Join(root, "new.txt"))
			require.NoError(t, err)
			b, _ := io.ReadAll(f)
			_ = f.Close()
			require.Equal(t, "hello", string(b))
		})
	}
}

// ─── GHSA-rqv7-6c67-mgjf: SITE CHMOD / MFMT under --no-delete / --upload-only ─

func TestClientFs_ModeFlagsBlockMetadataChanges(t *testing.T) {
	for name, srv := range map[string]FTPServer{
		"no-delete":   {NoDelete: true},
		"upload-only": {UploadOnly: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, root := newBaseFs(t)
			srv.Root = root
			fs := srv.clientFs()
			for _, p := range []string{"/existing.txt", "/"} {
				require.Error(t, fs.Chmod(p, 0), "SITE CHMOD 000 %s", p)
				require.Error(t, fs.Chtimes(p, time.Unix(0, 0), time.Unix(0, 0)), "MFMT %s", p)
				require.Error(t, fs.Chown(p, 0, 0), "chown %s", p)
			}
			fi, err := os.Stat(filepath.Join(root, "existing.txt"))
			require.NoError(t, err)
			require.NotEqual(t, os.FileMode(0), fi.Mode().Perm())
			fi, err = os.Stat(root)
			require.NoError(t, err)
			require.NotEqual(t, os.FileMode(0), fi.Mode().Perm())
		})
	}
}
