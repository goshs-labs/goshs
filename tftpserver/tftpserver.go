// Package tftpserver implements a small, dependency-free TFTP server
// (RFC 1350) with blksize/tsize option negotiation (RFC 2347/2348/2349).
//
// It exists so goshs can offer the one classic transfer protocol it lacked
// next to HTTP/WebDAV/FTP/SFTP/SMB. TFTP is handy in CTF/pentest contexts
// because Windows ships a built-in tftp.exe client, giving a reliable
// ingress/egress path when HTTP is filtered.
//
// Transfers are binary (octet) regardless of the requested mode; netascii
// line-ending translation is intentionally not performed. Reads (RRQ) let a
// target pull files from the webroot; writes (WRQ) let a target push files
// into the upload folder (or webroot). Path traversal is rejected and the IP
// whitelist / ReadOnly / UploadOnly options are honoured, matching the other
// goshs protocol servers.
package tftpserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
)

// TFTP opcodes (RFC 1350).
const (
	opRRQ   = 1 // read request
	opWRQ   = 2 // write request
	opDATA  = 3
	opACK   = 4
	opERROR = 5
	opOACK  = 6 // option acknowledgement (RFC 2347)
)

// TFTP error codes (RFC 1350 §5).
const (
	errFileNotFound    = 1
	errAccessViolation = 2
	errDiskFull        = 3
	errIllegalOp       = 4
	errUnknownTID      = 5
)

const (
	defaultBlockSize = 512
	minBlockSize     = 8
	maxBlockSize     = 65464 // 65535 - 4 bytes IPv4 header room (RFC 2348)
	maxRetries       = 5
	ackTimeout       = 5 * time.Second
)

// TFTPServer serves files over UDP/69 (configurable).
type TFTPServer struct {
	IP         string
	Port       int
	Root       string // webroot, used for reads (RRQ)
	UploadRoot string // destination for writes (WRQ): upload folder or webroot
	ReadOnly   bool
	UploadOnly bool
	NoDelete   bool
	Webhook    webhook.Webhook
	Whitelist  *httpserver.Whitelist

	pc net.PacketConn // bound by Bind, served by Start
}

// NewTFTPServer builds a TFTPServer from the parsed options. Writes land in the
// dedicated upload folder when one is configured, otherwise in the webroot.
func NewTFTPServer(opts *options.Options, wl *httpserver.Whitelist, wh webhook.Webhook) *TFTPServer {
	uploadRoot := opts.UploadFolder
	if uploadRoot == "" {
		uploadRoot = opts.Webroot
	}
	return &TFTPServer{
		IP:         opts.IP,
		Port:       opts.TFTPPort,
		Root:       opts.Webroot,
		UploadRoot: uploadRoot,
		ReadOnly:   opts.ReadOnly,
		UploadOnly: opts.UploadOnly,
		NoDelete:   opts.NoDelete,
		Webhook:    wh,
		Whitelist:  wl,
	}
}

// Start binds the main UDP socket and dispatches each incoming request to its
// own goroutine. It blocks; callers run it in a goroutine like the other
// protocol servers.
// Bind acquires the main UDP socket so a port conflict is reported to the caller
// synchronously instead of the serving goroutine swallowing it.
func (s *TFTPServer) Bind() error {
	addr := net.JoinHostPort(s.IP, strconv.Itoa(s.Port))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("[TFTP] failed to bind %s: %w", addr, err)
	}
	s.pc = pc
	return nil
}

func (s *TFTPServer) Start() error {
	// Bind lazily if a caller did not already do so via Bind.
	if s.pc == nil {
		if err := s.Bind(); err != nil {
			logger.Errorf("%+v", err)
			return err
		}
	}
	logger.Infof("Starting TFTP server on %s:%d", s.IP, s.Port)

	buf := make([]byte, 65535)
	for {
		n, client, err := s.pc.ReadFrom(buf)
		if err != nil {
			logger.Warnf("[TFTP] read error on main socket: %v", err)
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		if udp, ok := client.(*net.UDPAddr); ok {
			go s.handleRequest(req, udp)
		}
	}
}

// HandleWebhookSend mirrors the FTP server's notification format.
func (s *TFTPServer) HandleWebhookSend(action, path, ip string, blocked bool) {
	var message string
	if blocked {
		message = fmt.Sprintf("[TFTP] BLOCKED %s - [%s] - \"%s\"", ip, action, path)
	} else {
		message = fmt.Sprintf("[TFTP] %s - [%s] - \"%s\"", ip, action, path)
	}
	logger.HandleWebhookSend(message, "tftp", s.Webhook)
}

// handleRequest parses an initial RRQ/WRQ and drives the matching transfer on a
// fresh socket (a new transfer identifier, per RFC 1350).
func (s *TFTPServer) handleRequest(req []byte, client *net.UDPAddr) {
	if !s.Whitelist.IsAllowed(client.IP.String()) {
		logger.Warnf("[TFTP] [WHITELIST] Access denied for %s", client.IP)
		s.HandleWebhookSend("REQUEST", "", client.IP.String(), true)
		// Reply on a throwaway socket so the client sees the denial.
		if conn, err := newTransferConn(); err == nil {
			_, _ = conn.WriteToUDP(buildError(errAccessViolation, "access denied"), client)
			_ = conn.Close()
		}
		return
	}

	if len(req) < 2 {
		return
	}
	opcode := binary.BigEndian.Uint16(req[:2])
	filename, _, topts, err := parseRequest(req[2:])
	if err != nil || filename == "" {
		if conn, cerr := newTransferConn(); cerr == nil {
			_, _ = conn.WriteToUDP(buildError(errIllegalOp, "malformed request"), client)
			_ = conn.Close()
		}
		return
	}

	conn, err := newTransferConn()
	if err != nil {
		logger.Errorf("[TFTP] failed to open transfer socket: %v", err)
		return
	}
	defer conn.Close()

	switch opcode {
	case opRRQ:
		s.handleRead(conn, client, filename, topts)
	case opWRQ:
		s.handleWrite(conn, client, filename, topts)
	default:
		_, _ = conn.WriteToUDP(buildError(errIllegalOp, "unsupported opcode"), client)
	}
}

// handleRead streams a file from the webroot to the client (RRQ).
func (s *TFTPServer) handleRead(conn *net.UDPConn, client *net.UDPAddr, filename string, topts map[string]string) {
	if s.UploadOnly {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "server is upload-only"), client)
		s.HandleWebhookSend("GET", filename, client.IP.String(), true)
		return
	}

	path, ok := safePath(s.Root, filename)
	if !ok {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "illegal path"), client)
		logger.Warnf("[TFTP] rejected traversal in RRQ %q from %s", filename, client.IP)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = conn.WriteToUDP(buildError(errFileNotFound, "file not found"), client)
		} else {
			_, _ = conn.WriteToUDP(buildError(errAccessViolation, "cannot read file"), client)
		}
		logger.Warnf("[TFTP] RRQ %q from %s failed: %v", filename, client.IP, err)
		return
	}

	logger.Infof("[TFTP] GET %q (%d bytes) by %s", filename, len(data), client.IP)
	s.HandleWebhookSend("GET", filename, client.IP.String(), false)

	blockSize := negotiateBlockSize(topts)

	// If the client requested options, acknowledge them (echoing tsize as the
	// real file size) and wait for its ACK 0 before sending data.
	if accepted := negotiateRead(topts, blockSize, int64(len(data))); accepted != nil {
		if !s.exchangeOACK(conn, client, accepted) {
			return
		}
	}

	s.sendFile(conn, client, data, blockSize)
}

// handleWrite receives a file from the client into the upload root (WRQ).
func (s *TFTPServer) handleWrite(conn *net.UDPConn, client *net.UDPAddr, filename string, topts map[string]string) {
	if s.ReadOnly {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "server is read-only"), client)
		s.HandleWebhookSend("PUT", filename, client.IP.String(), true)
		return
	}

	path, ok := safePath(s.UploadRoot, filename)
	if !ok {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "illegal path"), client)
		logger.Warnf("[TFTP] rejected traversal in WRQ %q from %s", filename, client.IP)
		return
	}

	// Enforce --no-delete / --upload-only: os.Create implies O_TRUNC, so a WRQ
	// for an existing filename would empty (destroy) its contents before any
	// DATA arrives. Treat overwrite of an existing file as a deletion and refuse
	// it, mirroring the HTTP/SFTP upload paths. Creating new files stays allowed.
	if s.NoDelete || s.UploadOnly {
		if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
			_, _ = conn.WriteToUDP(buildError(errAccessViolation, "overwrite of existing file not allowed"), client)
			logger.Warnf("[TFTP] rejected overwrite of existing file %q from %s (--no-delete/--upload-only)", filename, client.IP)
			s.HandleWebhookSend("PUT", filename, client.IP.String(), true)
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "cannot create directory"), client)
		return
	}
	f, err := os.Create(path)
	if err != nil {
		_, _ = conn.WriteToUDP(buildError(errAccessViolation, "cannot create file"), client)
		logger.Warnf("[TFTP] WRQ %q from %s failed: %v", filename, client.IP, err)
		return
	}
	defer f.Close()

	blockSize := negotiateBlockSize(topts)

	// Acknowledge negotiated options with an OACK, otherwise ACK block 0 to ask
	// the client to begin sending DATA.
	if accepted := negotiateWrite(topts, blockSize); accepted != nil {
		if _, err := conn.WriteToUDP(buildOACK(accepted), client); err != nil {
			return
		}
	} else if _, err := conn.WriteToUDP(buildACK(0), client); err != nil {
		return
	}

	logger.Infof("[TFTP] PUT %q started by %s", filename, client.IP)
	s.HandleWebhookSend("PUT", filename, client.IP.String(), false)

	if n, err := s.recvFile(conn, client, f, blockSize); err != nil {
		logger.Warnf("[TFTP] PUT %q from %s aborted: %v", filename, client.IP, err)
	} else {
		logger.Infof("[TFTP] PUT %q (%d bytes) completed by %s", filename, n, client.IP)
	}
}

// sendFile writes the payload to the client in lockstep DATA/ACK blocks,
// retransmitting the current block on timeout.
func (s *TFTPServer) sendFile(conn *net.UDPConn, client *net.UDPAddr, data []byte, blockSize int) {
	var block uint16 = 1
	for offset := 0; ; offset += blockSize {
		end := min(offset+blockSize, len(data))
		chunk := data[offset:end]
		packet := buildData(block, chunk)

		if !s.sendAndAwaitACK(conn, client, packet, block) {
			return
		}

		// A short (or empty) final block terminates the transfer.
		if len(chunk) < blockSize {
			return
		}
		block++
	}
}

// recvFile reads DATA blocks from the client, ACKing each, until a short block
// signals the end. Returns the number of bytes written.
func (s *TFTPServer) recvFile(conn *net.UDPConn, client *net.UDPAddr, f *os.File, blockSize int) (int64, error) {
	var expected uint16 = 1
	var total int64
	buf := make([]byte, blockSize+4)

	for {
		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return total, fmt.Errorf("timed out waiting for data block %d", expected)
		}
		if !addr.IP.Equal(client.IP) || addr.Port != client.Port {
			_, _ = conn.WriteToUDP(buildError(errUnknownTID, "unknown transfer id"), addr)
			continue
		}
		if n < 4 {
			continue
		}
		switch binary.BigEndian.Uint16(buf[:2]) {
		case opDATA:
			block := binary.BigEndian.Uint16(buf[2:4])
			if block != expected {
				// Duplicate/old block: re-ACK so the peer can move on.
				_, _ = conn.WriteToUDP(buildACK(block), client)
				continue
			}
			payload := buf[4:n]
			if _, err := f.Write(payload); err != nil {
				_, _ = conn.WriteToUDP(buildError(errDiskFull, "write failed"), client)
				return total, err
			}
			total += int64(len(payload))
			if _, err := conn.WriteToUDP(buildACK(expected), client); err != nil {
				return total, err
			}
			if len(payload) < blockSize {
				return total, nil // final block
			}
			expected++
		case opERROR:
			return total, fmt.Errorf("client aborted: %s", errorMessage(buf[:n]))
		default:
			// Ignore anything unexpected and keep waiting.
		}
	}
}

// sendAndAwaitACK transmits packet and waits for the matching ACK, retrying up
// to maxRetries times. Returns false if the transfer should be abandoned.
func (s *TFTPServer) sendAndAwaitACK(conn *net.UDPConn, client *net.UDPAddr, packet []byte, block uint16) bool {
	buf := make([]byte, 516)
	for range maxRetries {
		if _, err := conn.WriteToUDP(packet, client); err != nil {
			return false
		}
		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue // timeout: retransmit
		}
		if !addr.IP.Equal(client.IP) || addr.Port != client.Port {
			_, _ = conn.WriteToUDP(buildError(errUnknownTID, "unknown transfer id"), addr)
			continue
		}
		if n < 4 {
			continue
		}
		switch binary.BigEndian.Uint16(buf[:2]) {
		case opACK:
			if binary.BigEndian.Uint16(buf[2:4]) == block {
				return true
			}
		case opERROR:
			return false
		}
	}
	return false
}

// exchangeOACK sends an OACK for a read transfer and waits for the client's
// ACK 0 confirming the negotiated options.
func (s *TFTPServer) exchangeOACK(conn *net.UDPConn, client *net.UDPAddr, accepted []option) bool {
	buf := make([]byte, 516)
	packet := buildOACK(accepted)
	for range maxRetries {
		if _, err := conn.WriteToUDP(packet, client); err != nil {
			return false
		}
		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if !addr.IP.Equal(client.IP) || addr.Port != client.Port {
			_, _ = conn.WriteToUDP(buildError(errUnknownTID, "unknown transfer id"), addr)
			continue
		}
		if n >= 4 && binary.BigEndian.Uint16(buf[:2]) == opACK && binary.BigEndian.Uint16(buf[2:4]) == 0 {
			return true
		}
	}
	return false
}

// --- packet helpers ---------------------------------------------------------

// option is a single negotiated TFTP option, kept ordered for deterministic
// OACK output (and tests).
type option struct{ key, val string }

func buildData(block uint16, data []byte) []byte {
	p := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(p[:2], opDATA)
	binary.BigEndian.PutUint16(p[2:4], block)
	copy(p[4:], data)
	return p
}

func buildACK(block uint16) []byte {
	p := make([]byte, 4)
	binary.BigEndian.PutUint16(p[:2], opACK)
	binary.BigEndian.PutUint16(p[2:4], block)
	return p
}

func buildError(code uint16, msg string) []byte {
	p := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(p[:2], opERROR)
	binary.BigEndian.PutUint16(p[2:4], code)
	copy(p[4:], msg)
	return p
}

func buildOACK(opts []option) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, opOACK})
	for _, o := range opts {
		b.WriteString(o.key)
		b.WriteByte(0)
		b.WriteString(o.val)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// parseRequest splits the body of an RRQ/WRQ (everything after the 2-byte
// opcode) into filename, mode and any negotiated options.
func parseRequest(body []byte) (filename, mode string, opts map[string]string, err error) {
	fields := bytes.Split(body, []byte{0})
	if len(fields) < 2 {
		return "", "", nil, fmt.Errorf("malformed request")
	}
	filename = string(fields[0])
	mode = strings.ToLower(string(fields[1]))
	opts = make(map[string]string)
	for i := 2; i+1 < len(fields); i += 2 {
		key := strings.ToLower(string(fields[i]))
		if key == "" {
			break
		}
		opts[key] = string(fields[i+1])
	}
	return filename, mode, opts, nil
}

// errorMessage extracts the human-readable part of an ERROR packet.
func errorMessage(p []byte) string {
	if len(p) <= 4 {
		return "unknown error"
	}
	return string(bytes.TrimRight(p[4:], "\x00"))
}

// negotiateBlockSize returns the agreed block size, clamped to a sane range.
func negotiateBlockSize(topts map[string]string) int {
	v, ok := topts["blksize"]
	if !ok {
		return defaultBlockSize
	}
	bs, err := strconv.Atoi(v)
	if err != nil {
		return defaultBlockSize
	}
	if bs < minBlockSize {
		return minBlockSize
	}
	if bs > maxBlockSize {
		return maxBlockSize
	}
	return bs
}

// negotiateRead builds the OACK option list for a read transfer, echoing only
// the options the client actually sent. tsize is answered with the real file
// size. Returns nil when the client requested no options.
func negotiateRead(topts map[string]string, blockSize int, fileSize int64) []option {
	if len(topts) == 0 {
		return nil
	}
	var out []option
	if _, ok := topts["blksize"]; ok {
		out = append(out, option{"blksize", strconv.Itoa(blockSize)})
	}
	if _, ok := topts["tsize"]; ok {
		out = append(out, option{"tsize", strconv.FormatInt(fileSize, 10)})
	}
	if v, ok := topts["timeout"]; ok {
		out = append(out, option{"timeout", v})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// negotiateWrite builds the OACK option list for a write transfer. tsize is
// echoed back unchanged (the client states the size it intends to send).
func negotiateWrite(topts map[string]string, blockSize int) []option {
	if len(topts) == 0 {
		return nil
	}
	var out []option
	if _, ok := topts["blksize"]; ok {
		out = append(out, option{"blksize", strconv.Itoa(blockSize)})
	}
	if v, ok := topts["tsize"]; ok {
		out = append(out, option{"tsize", v})
	}
	if v, ok := topts["timeout"]; ok {
		out = append(out, option{"timeout", v})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// newTransferConn opens an ephemeral UDP socket for a single transfer (its own
// transfer identifier, per RFC 1350).
func newTransferConn() (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{Port: 0})
}

// safePath resolves a client-supplied filename against root and guarantees the
// result stays inside root. It rejects any name whose "../" segments would
// escape root; a leading "/" (or "\") is treated as relative to root rather
// than the system root, so "/etc/passwd" maps harmlessly to <root>/etc/passwd.
func safePath(root, name string) (string, bool) {
	// Normalise Windows separators so "..\\.." is caught on every platform.
	name = strings.ReplaceAll(name, "\\", "/")
	full := filepath.Join(root, filepath.FromSlash(name))

	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return full, true
}
