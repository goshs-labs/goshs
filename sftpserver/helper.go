package sftpserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/logger"
)

var authorizedKeysMap map[string]bool

// loadAuthorizedKeys loads authorized keys from a file and returns a map of keys
func loadAuthorizedKeys(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keys := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		key, _, _, _, err := gossh.ParseAuthorizedKey(line)
		if err != nil {
			log.Printf("Skipping invalid key: %v", err)
			continue
		}
		keys[string(key.Marshal())] = true
	}
	return keys, scanner.Err()
}

// Sanitize client path to restrict to sftpRoot
func sanitizePath(clientPath string, sftpRoot string) (string, error) {
	if runtime.GOOS == "windows" {
		clientPath = rewritePathWindows(clientPath)
		sftpRoot = rewritePathWindows(sftpRoot)
	}
	clean := filepath.Clean("/" + strings.TrimLeft(clientPath, "/"))
	clean = strings.TrimPrefix(clean, sftpRoot)
	abs := filepath.Join(sftpRoot, clean)
	rootClean := filepath.Clean(sftpRoot)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return "", errors.New("access denied: outside of webroot")
	}
	return abs, nil
}

// simpleListerAt is a simple implementation of sftp.ListerAt
type simpleListerAt struct {
	files []fs.FileInfo
}

// ListAt implements the sftp.ListerAt interface
func (l *simpleListerAt) ListAt(p []fs.FileInfo, off int64) (int, error) {
	if int(off) >= len(l.files) {
		return 0, io.EOF
	}

	n := copy(p, l.files[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readFile opens a file for reading
func readFile(root string, r *sftp.Request, ip string, sftpServer *SFTPServer) (*os.File, error) {
	if runtime.GOOS == "windows" {
		r.Filepath = rewritePathWindows(r.Filepath)
		root = rewritePathWindows(root)
	}
	fullPath, err := sanitizePath(r.Filepath, root)
	if err != nil {
		logger.LogSFTPRequestBlocked(r, ip, err)
		sftpServer.HandleWebhookSend("sftp", r, ip, true)
		return nil, err
	}
	sftpServer.HandleWebhookSend("sftp", r, ip, false)
	logger.LogSFTPRequest(r, ip)
	return os.Open(fullPath)
}

// listFile lists files in a directory
func listFile(root string, r *sftp.Request, ip string, sftpServer *SFTPServer) (*simpleListerAt, error) {
	if runtime.GOOS == "windows" {
		r.Filepath = rewritePathWindows(r.Filepath)
	}
	fullPath, err := sanitizePath(r.Filepath, root)
	if err != nil {
		logger.LogSFTPRequestBlocked(r, ip, err)
		sftpServer.HandleWebhookSend("sftp", r, ip, true)
		return nil, err
	}
	switch r.Method {
	case "Stat":
		info, err := os.Stat(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return nil, err
		}
		logger.LogSFTPRequest(r, ip)
		sftpServer.HandleWebhookSend("sftp", r, ip, false)
		return &simpleListerAt{files: []fs.FileInfo{info}}, nil
	default:
		f, err := os.Open(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return nil, err
		}
		defer f.Close()

		infos, err := f.Readdir(0)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return nil, err
		}

		return &simpleListerAt{files: infos}, nil
	}
}

// writeFile opens a file for writing
func writeFile(root string, r *sftp.Request, ip string, sftpServer *SFTPServer) (*os.File, error) {
	if runtime.GOOS == "windows" {
		r.Filepath = rewritePathWindows(r.Filepath)
	}
	fullPath, err := sanitizePath(r.Filepath, root)
	if err != nil {
		logger.LogSFTPRequestBlocked(r, ip, err)
		sftpServer.HandleWebhookSend("sftp", r, ip, true)
		return nil, err
	}
	// Enforce --no-delete: overwriting an existing file with os.Create truncates
	// it, which destroys its previous contents — a deletion. Block it while still
	// allowing creation of new files (GHSA-4wh5-87mw-whxf). Mirrors the HTTP
	// upload handler's no-delete overwrite guard in updown.go.
	if sftpServer.NoDelete {
		if info, statErr := os.Stat(fullPath); statErr == nil && !info.IsDir() {
			nErr := errors.New("overwriting existing files not allowed due to 'no delete' option")
			logger.LogSFTPRequestBlocked(r, ip, nErr)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return nil, nErr
		}
	}
	logger.LogSFTPRequest(r, ip)
	sftpServer.HandleWebhookSend("sftp", r, ip, false)
	return os.Create(fullPath)
}

// cmdFile executes file commands like Stat, Lstat, Setstat, Rename, Rmdir, Mkdir, and Remove
func cmdFile(root string, r *sftp.Request, ip string, sftpServer *SFTPServer) error {
	if runtime.GOOS == "windows" {
		r.Target = rewritePathWindows(r.Target)
		r.Filepath = rewritePathWindows(r.Filepath)
	}
	fullPath, err := sanitizePath(r.Filepath, root)
	if err != nil {
		logger.LogSFTPRequestBlocked(r, ip, err)
		sftpServer.HandleWebhookSend("sftp", r, ip, true)
		return err
	}

	// Enforce --no-delete: Remove, Rmdir and Rename all destroy or move existing
	// content, so block them when the flag is set (GHSA-4wh5-87mw-whxf). Mirrors
	// the FTP noDeleteFs wrapper and the HTTP no-delete guards.
	if sftpServer.NoDelete {
		switch r.Method {
		case "Remove", "Rmdir", "Rename":
			nErr := errors.New("delete/rename not allowed due to 'no delete' option")
			logger.LogSFTPRequestBlocked(r, ip, nErr)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return nErr
		}
	}

	switch r.Method {
	case "Stat":
		_, err := os.Stat(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	case "Lstat":
		_, err := os.Lstat(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	case "Setstat":
		mode := os.FileMode(r.Attributes().Mode)
		if mode != 0 {
			if err := os.Chmod(fullPath, mode); err != nil {
				logger.LogSFTPRequestBlocked(r, ip, fmt.Errorf("chmod failed: %w", err))
				sftpServer.HandleWebhookSend("sftp", r, ip, true)
				return fmt.Errorf("chmod failed %w", err)
			}
		}
		logger.LogSFTPRequest(r, ip)
		sftpServer.HandleWebhookSend("sftp", r, ip, false)
		return nil

	case "Rename":
		targetPath, err := sanitizePath(r.Target, root)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		}
		err = os.Rename(fullPath, targetPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	case "Rmdir":
		err := os.RemoveAll(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	case "Mkdir":
		err := os.Mkdir(fullPath, 0o755)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	case "Remove":
		err := os.Remove(fullPath)
		if err != nil {
			logger.LogSFTPRequestBlocked(r, ip, err)
			sftpServer.HandleWebhookSend("sftp", r, ip, true)
			return err
		} else {
			logger.LogSFTPRequest(r, ip)
			sftpServer.HandleWebhookSend("sftp", r, ip, false)
			return err
		}
	default:
		logger.LogSFTPRequestBlocked(r, ip, fmt.Errorf("unsupported command: %s", r.Method))
		sftpServer.HandleWebhookSend("sftp", r, ip, true)
		return errors.New("unsupported command")
	}
}

func rewritePathWindows(path string) string {
	path = strings.TrimPrefix(path, "/")
	path = strings.ReplaceAll(path, "/", "\\")
	return path
}

func isAllowedIP(addr net.Addr, wl *httpserver.Whitelist) bool {
	// If Whitelist disabled just serve
	if !wl.Enabled {
		return true
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, net := range wl.Networks {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}
