package tftpserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"goshs.de/goshs/v2/httpserver"
	"goshs.de/goshs/v2/webhook"
)

// allowAll is a disabled whitelist (every IP allowed).
func allowAll(t *testing.T) *httpserver.Whitelist {
	t.Helper()
	wl, err := httpserver.NewIPWhitelist("", false, "")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	return wl
}

// startServer launches a TFTPServer on an ephemeral UDP port and returns it
// plus the bound port. It listens on 127.0.0.1 so tests stay local.
func startServer(t *testing.T, s *TFTPServer) int {
	t.Helper()
	if s.Webhook == nil {
		s.Webhook = *webhook.Register(false, "", "discord", nil)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 65535)
		for {
			n, client, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := make([]byte, n)
			copy(req, buf[:n])
			s.handleRequest(req, client.(*net.UDPAddr))
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return port
}

// tclient is a minimal TFTP client over an unconnected UDP socket. After the
// first reply it locks onto the server's transfer port (TID), the way a real
// TFTP client does, so subsequent packets reach the per-transfer socket.
type tclient struct {
	conn *net.UDPConn
	peer *net.UDPAddr
}

func newClient(t *testing.T, serverPort int) *tclient {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &tclient{conn: conn, peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}}
}

func (c *tclient) send(t *testing.T, b []byte) {
	t.Helper()
	if _, err := c.conn.WriteToUDP(b, c.peer); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func (c *tclient) recv(t *testing.T) []byte {
	t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c.peer = addr // lock onto the server's transfer TID
	return buf[:n]
}

func rrq(filename string, opts ...string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, opRRQ})
	b.WriteString(filename)
	b.WriteByte(0)
	b.WriteString("octet")
	b.WriteByte(0)
	for _, o := range opts {
		b.WriteString(o)
		b.WriteByte(0)
	}
	return b.Bytes()
}

func wrq(filename string, opts ...string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, opWRQ})
	b.WriteString(filename)
	b.WriteByte(0)
	b.WriteString("octet")
	b.WriteByte(0)
	for _, o := range opts {
		b.WriteString(o)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// --- RRQ (download from goshs) ----------------------------------------------

func TestRRQRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := bytes.Repeat([]byte("goshs-tftp!"), 200) // ~2.2 KB → spans several blocks
	if err := os.WriteFile(filepath.Join(root, "loot.bin"), want, 0644); err != nil {
		t.Fatal(err)
	}

	port := startServer(t, &TFTPServer{Root: root, Whitelist: allowAll(t)})
	c := newClient(t, port)
	c.send(t, rrq("loot.bin"))

	var got []byte
	var block uint16 = 1
	for {
		pkt := c.recv(t)
		if binary.BigEndian.Uint16(pkt[:2]) != opDATA {
			t.Fatalf("expected DATA, got opcode %d (%q)", binary.BigEndian.Uint16(pkt[:2]), pkt)
		}
		if binary.BigEndian.Uint16(pkt[2:4]) != block {
			t.Fatalf("expected block %d, got %d", block, binary.BigEndian.Uint16(pkt[2:4]))
		}
		payload := pkt[4:]
		got = append(got, payload...)
		c.send(t, buildACK(block))
		if len(payload) < defaultBlockSize {
			break
		}
		block++
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("downloaded %d bytes, want %d (mismatch)", len(got), len(want))
	}
}

func TestRRQWithOptionsSendsOACK(t *testing.T) {
	root := t.TempDir()
	want := bytes.Repeat([]byte("x"), 1500)
	if err := os.WriteFile(filepath.Join(root, "a.txt"), want, 0644); err != nil {
		t.Fatal(err)
	}

	port := startServer(t, &TFTPServer{Root: root, Whitelist: allowAll(t)})
	c := newClient(t, port)

	// Request a 1024-byte block size and ask for the file size.
	c.send(t, rrq("a.txt", "blksize", "1024", "tsize", "0"))

	oack := c.recv(t)
	if binary.BigEndian.Uint16(oack[:2]) != opOACK {
		t.Fatalf("expected OACK, got opcode %d", binary.BigEndian.Uint16(oack[:2]))
	}
	fields := bytes.Split(oack[2:], []byte{0})
	opts := map[string]string{}
	for i := 0; i+1 < len(fields); i += 2 {
		opts[string(fields[i])] = string(fields[i+1])
	}
	if opts["blksize"] != "1024" {
		t.Errorf("blksize OACK = %q, want 1024", opts["blksize"])
	}
	if opts["tsize"] != "1500" {
		t.Errorf("tsize OACK = %q, want 1500 (real file size)", opts["tsize"])
	}

	// Confirm OACK, then the first DATA block should be the negotiated 1024 bytes.
	c.send(t, buildACK(0))
	data := c.recv(t)
	if binary.BigEndian.Uint16(data[:2]) != opDATA || len(data[4:]) != 1024 {
		t.Fatalf("expected 1024-byte DATA block, got opcode %d len %d", binary.BigEndian.Uint16(data[:2]), len(data[4:]))
	}
}

func TestRRQFileNotFound(t *testing.T) {
	port := startServer(t, &TFTPServer{Root: t.TempDir(), Whitelist: allowAll(t)})
	c := newClient(t, port)

	c.send(t, rrq("missing"))
	pkt := c.recv(t)
	if binary.BigEndian.Uint16(pkt[:2]) != opERROR || binary.BigEndian.Uint16(pkt[2:4]) != errFileNotFound {
		t.Fatalf("expected ERROR file-not-found, got opcode %d code %d", binary.BigEndian.Uint16(pkt[:2]), binary.BigEndian.Uint16(pkt[2:4]))
	}
}

func TestRRQRejectedWhenUploadOnly(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("data"), 0644)
	port := startServer(t, &TFTPServer{Root: root, UploadOnly: true, Whitelist: allowAll(t)})
	c := newClient(t, port)

	c.send(t, rrq("f"))
	pkt := c.recv(t)
	if binary.BigEndian.Uint16(pkt[:2]) != opERROR || binary.BigEndian.Uint16(pkt[2:4]) != errAccessViolation {
		t.Fatalf("upload-only should reject RRQ with access violation, got opcode %d code %d", binary.BigEndian.Uint16(pkt[:2]), binary.BigEndian.Uint16(pkt[2:4]))
	}
}

// --- WRQ (upload to goshs) --------------------------------------------------

func TestWRQRoundTrip(t *testing.T) {
	root := t.TempDir()
	port := startServer(t, &TFTPServer{Root: root, UploadRoot: root, Whitelist: allowAll(t)})
	c := newClient(t, port)

	want := bytes.Repeat([]byte("UP"), 400) // 800 bytes → 2 blocks
	c.send(t, wrq("up.bin"))

	// Server ACKs block 0 to start.
	ack := c.recv(t)
	if binary.BigEndian.Uint16(ack[:2]) != opACK || binary.BigEndian.Uint16(ack[2:4]) != 0 {
		t.Fatalf("expected ACK 0, got opcode %d block %d", binary.BigEndian.Uint16(ack[:2]), binary.BigEndian.Uint16(ack[2:4]))
	}

	var block uint16 = 1
	for offset := 0; offset < len(want) || block == 1; offset += defaultBlockSize {
		end := min(offset+defaultBlockSize, len(want))
		c.send(t, buildData(block, want[offset:end]))
		ack := c.recv(t)
		if binary.BigEndian.Uint16(ack[:2]) != opACK || binary.BigEndian.Uint16(ack[2:4]) != block {
			t.Fatalf("expected ACK %d, got opcode %d block %d", block, binary.BigEndian.Uint16(ack[:2]), binary.BigEndian.Uint16(ack[2:4]))
		}
		block++
	}

	// Give the server a moment to flush to disk.
	time.Sleep(50 * time.Millisecond)
	got, err := os.ReadFile(filepath.Join(root, "up.bin"))
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("uploaded %d bytes, want %d", len(got), len(want))
	}
}

func TestWRQRejectedWhenReadOnly(t *testing.T) {
	root := t.TempDir()
	port := startServer(t, &TFTPServer{Root: root, UploadRoot: root, ReadOnly: true, Whitelist: allowAll(t)})
	c := newClient(t, port)

	c.send(t, wrq("nope"))
	pkt := c.recv(t)
	if binary.BigEndian.Uint16(pkt[:2]) != opERROR || binary.BigEndian.Uint16(pkt[2:4]) != errAccessViolation {
		t.Fatalf("read-only should reject WRQ with access violation, got opcode %d code %d", binary.BigEndian.Uint16(pkt[:2]), binary.BigEndian.Uint16(pkt[2:4]))
	}
	if _, err := os.Stat(filepath.Join(root, "nope")); !os.IsNotExist(err) {
		t.Fatal("read-only server must not create the file")
	}
}

// TestWRQRejectedWhenNoDeleteOverwrite verifies a WRQ for an existing filename
// is refused under --no-delete and the original content is preserved (regression
// for GHSA-2q29-798w-6qcp / GHSA-vw29-46p5-7h7x). os.Create implies O_TRUNC, so
// without the guard the file would be emptied before the ACK-0 reply.
func TestWRQRejectedWhenNoDeleteOverwrite(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "protected.txt")
	original := []byte("ORIGINAL_PROTECTED_CONTENT")
	if err := os.WriteFile(existing, original, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	port := startServer(t, &TFTPServer{Root: root, UploadRoot: root, NoDelete: true, Whitelist: allowAll(t)})
	c := newClient(t, port)

	c.send(t, wrq("protected.txt"))
	pkt := c.recv(t)
	if binary.BigEndian.Uint16(pkt[:2]) != opERROR || binary.BigEndian.Uint16(pkt[2:4]) != errAccessViolation {
		t.Fatalf("--no-delete should reject WRQ overwrite with access violation, got opcode %d code %d", binary.BigEndian.Uint16(pkt[:2]), binary.BigEndian.Uint16(pkt[2:4]))
	}

	// The file must be untouched — not truncated by the destructive open.
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("existing file must survive: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing file was modified: got %q, want %q", got, original)
	}
}

// TestWRQNewFileAllowedWhenNoDelete confirms --no-delete still permits creating
// a brand-new file: the guard blocks overwrite of existing content only.
func TestWRQNewFileAllowedWhenNoDelete(t *testing.T) {
	root := t.TempDir()
	port := startServer(t, &TFTPServer{Root: root, UploadRoot: root, NoDelete: true, Whitelist: allowAll(t)})
	c := newClient(t, port)

	want := []byte("fresh upload")
	c.send(t, wrq("new.bin"))
	ack := c.recv(t)
	if binary.BigEndian.Uint16(ack[:2]) != opACK || binary.BigEndian.Uint16(ack[2:4]) != 0 {
		t.Fatalf("expected ACK 0 for new file under --no-delete, got opcode %d block %d", binary.BigEndian.Uint16(ack[:2]), binary.BigEndian.Uint16(ack[2:4]))
	}
	c.send(t, buildData(1, want))
	if ack := c.recv(t); binary.BigEndian.Uint16(ack[2:4]) != 1 {
		t.Fatalf("expected ACK 1, got block %d", binary.BigEndian.Uint16(ack[2:4]))
	}

	time.Sleep(50 * time.Millisecond)
	got, err := os.ReadFile(filepath.Join(root, "new.bin"))
	if err != nil {
		t.Fatalf("new file should have been created under --no-delete: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("new file content mismatch: got %q, want %q", got, want)
	}
}

// --- security & whitelist ---------------------------------------------------

func TestRRQPathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	port := startServer(t, &TFTPServer{Root: root, Whitelist: allowAll(t)})

	for _, name := range []string{"../../etc/passwd", "..\\..\\windows\\win.ini"} {
		c := newClient(t, port)
		c.send(t, rrq(name))
		pkt := c.recv(t)
		op := binary.BigEndian.Uint16(pkt[:2])
		code := binary.BigEndian.Uint16(pkt[2:4])
		if op != opERROR || code != errAccessViolation {
			t.Fatalf("traversal %q: expected ERROR access-violation, got opcode %d code %d", name, op, code)
		}
	}
}

func TestWhitelistBlocks(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("secret"), 0644)
	// Whitelist a network that does NOT include 127.0.0.1.
	wl, err := httpserver.NewIPWhitelist("10.0.0.0/8", true, "")
	if err != nil {
		t.Fatal(err)
	}
	port := startServer(t, &TFTPServer{Root: root, Whitelist: wl, Webhook: *webhook.Register(false, "", "discord", nil)})
	c := newClient(t, port)

	c.send(t, rrq("f"))
	pkt := c.recv(t)
	if binary.BigEndian.Uint16(pkt[:2]) != opERROR {
		t.Fatalf("blocked client should get ERROR, got opcode %d", binary.BigEndian.Uint16(pkt[:2]))
	}
}

// --- unit: helpers ----------------------------------------------------------

func TestSafePath(t *testing.T) {
	root := "/srv/goshs"
	cases := []struct {
		name   string
		in     string
		wantOK bool
		want   string
	}{
		{"plain", "file.txt", true, "/srv/goshs/file.txt"},
		{"subdir", "a/b.txt", true, "/srv/goshs/a/b.txt"},
		{"traversal", "../secret", false, ""},
		{"deep traversal", "../../etc/passwd", false, ""},
		{"windows traversal", "..\\..\\secret", false, ""},
		{"rooted collapses in", "/etc/passwd", true, "/srv/goshs/etc/passwd"},
		{"dot segments", "a/../b.txt", true, "/srv/goshs/b.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := safePath(root, c.in)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, c.wantOK, got)
			}
			if c.wantOK && got != filepath.FromSlash(c.want) {
				t.Fatalf("path = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	body := []byte("loot.bin\x00octet\x00blksize\x001024\x00tsize\x000\x00")
	filename, mode, opts, err := parseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if filename != "loot.bin" || mode != "octet" {
		t.Fatalf("got %q/%q", filename, mode)
	}
	if opts["blksize"] != "1024" || opts["tsize"] != "0" {
		t.Fatalf("options parsed wrong: %v", opts)
	}
}

func TestNegotiateBlockSizeClamping(t *testing.T) {
	cases := map[string]int{
		"512":    512,
		"1":      minBlockSize,
		"100000": maxBlockSize,
		"junk":   defaultBlockSize,
	}
	for in, want := range cases {
		if got := negotiateBlockSize(map[string]string{"blksize": in}); got != want {
			t.Errorf("blksize %q → %d, want %d", in, got, want)
		}
	}
	if got := negotiateBlockSize(map[string]string{}); got != defaultBlockSize {
		t.Errorf("no option → %d, want %d", got, defaultBlockSize)
	}
}
