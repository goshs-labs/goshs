package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/smtpattach"
)

// newTestModel builds a minimal model with empty panes for unit testing the
// ingest/selection logic without a running bubbletea program.
func newTestModel() *model {
	return &model{
		panes: []*pane{
			{name: "HTTP"},
			{name: "DNS"},
		},
	}
}

func row(s string) eventRow { return eventRow{summary: s} }

// tplSegment returns the "🧩 tpl" status segment, or "" if absent.
func tplSegment(m *model) string {
	for _, s := range m.statusSegments() {
		if strings.HasPrefix(s, "🧩 tpl") {
			return s
		}
	}
	return ""
}

// statusSegments must surface every --tpl-var, not just LHOST/LPORT, so the TUI
// status line matches the server's template context (regression for arbitrary
// --tpl-var KEY=VALUE entries being dropped).
func TestStatusSegmentsShowsArbitraryTplVars(t *testing.T) {
	m := &model{opts: &options.Options{
		IP:       "10.0.0.5",
		Port:     8080,
		Webroot:  "/srv",
		Template: true,
		TemplateVarsParsed: map[string]string{
			"LPORT": "4444",
			"FOO":   "BAR",
		},
	}}
	got := tplSegment(m)
	for _, want := range []string{"LHOST=10.0.0.5", "LPORT=4444", "FOO=BAR"} {
		if !strings.Contains(got, want) {
			t.Fatalf("tpl segment %q missing %q", got, want)
		}
	}
}

// statusSegments must surface the enabled transfer servers (FTP/SFTP/TFTP) so
// the TUI status line reflects every running protocol, like SMB/DNS/etc.
func TestStatusSegmentsShowsTransferServers(t *testing.T) {
	cases := []struct {
		name string
		opts *options.Options
		want string
	}{
		{"tftp", &options.Options{Webroot: "/srv", TFTP: true, TFTPPort: 69}, "📦 tftp :69"},
		{"ftp", &options.Options{Webroot: "/srv", FTP: true, FTPPort: 2121}, "📂 ftp :2121"},
		{"sftp", &options.Options{Webroot: "/srv", FTP: true, FTPSFTPMode: true, FTPPort: 2121}, "📂 sftp :2121"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seg := strings.Join((&model{opts: c.opts}).statusSegments(), " ")
			if !strings.Contains(seg, c.want) {
				t.Fatalf("status line %q missing %q", seg, c.want)
			}
		})
	}
}

func TestAddRowNewestFirst(t *testing.T) {
	m := newTestModel()
	m.addRow(paneHTTP, row("first"))
	m.addRow(paneHTTP, row("second"))
	p := m.panes[paneHTTP]
	if p.rows[0].summary != "second" {
		t.Fatalf("row 0 = %q, want second (newest first)", p.rows[0].summary)
	}
}

func TestAddRowRidesTopInListView(t *testing.T) {
	m := newTestModel()
	m.addRow(paneHTTP, row("a"))
	m.addRow(paneHTTP, row("b"))
	// Not in detail view and sitting at the top: selection stays on the newest.
	if got := m.panes[paneHTTP].sel; got != 0 {
		t.Fatalf("sel = %d, want 0 (riding the top)", got)
	}
}

func TestAddRowAnchorsSelectionWhenScrolled(t *testing.T) {
	m := newTestModel()
	for _, s := range []string{"a", "b", "c"} {
		m.addRow(paneHTTP, row(s))
	}
	p := m.panes[paneHTTP]
	// Operator scrolls down to inspect an older event.
	p.sel = 1
	want := p.rows[1].summary
	m.addRow(paneHTTP, row("d"))
	if p.rows[p.sel].summary != want {
		t.Fatalf("selection moved off its event: got %q, want %q", p.rows[p.sel].summary, want)
	}
}

func TestAddRowAnchorsSelectionInDetailView(t *testing.T) {
	m := newTestModel()
	m.addRow(paneHTTP, row("a"))
	m.addRow(paneHTTP, row("b"))
	p := m.panes[paneHTTP]
	// Open the detail view on the newest event (row 0).
	m.active = paneHTTP
	m.detail = true
	want := p.rows[0].summary
	m.addRow(paneHTTP, row("c"))
	if p.rows[p.sel].summary != want {
		t.Fatalf("detail view swapped events: got %q, want %q", p.rows[p.sel].summary, want)
	}
}

// TestViewFillsHeight guards the fixed-height layout: the rendered frame must
// be exactly m.height lines in both the list and detail views so the status
// bar stays pinned to the bottom of the screen regardless of event volume.
func TestViewFillsHeight(t *testing.T) {
	m := newModel(&options.Options{IP: "0.0.0.0", Port: 8000, Webroot: "/srv", DNS: true, DNSPort: 8053, SMB: true, SMBPort: 445}, nil, nil, nil, nil, nil, nil)
	m.width, m.height = 100, 30
	for i := 0; i < 50; i++ {
		m.addRow(paneHTTP, row(fmt.Sprintf("event %d", i)))
	}
	m.active = paneHTTP

	if got := lipgloss.Height(m.View()); got != m.height {
		t.Fatalf("list view height = %d, want %d", got, m.height)
	}

	m.detail = true
	if got := lipgloss.Height(m.View()); got != m.height {
		t.Fatalf("detail view height = %d, want %d", got, m.height)
	}
}

// TestDetailScrollClamps verifies the detail scroll offset is bounded to the
// content during render, so paging past the end cannot strand the operator.
func TestDetailScrollClamps(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv"}, nil, nil, nil, nil, nil, nil)
	m.width, m.height = 80, 24
	m.addRow(paneHTTP, eventRow{summary: "x", detail: strings.Repeat("line\n", 100)})
	m.active = paneHTTP
	m.detail = true

	p := m.panes[paneHTTP]
	p.detailTop = 9999
	_ = m.View()

	if p.detailTop == 9999 {
		t.Fatalf("detailTop was not clamped to the content")
	}
	if m.detailH <= 0 {
		t.Fatalf("detailH not recorded for paging: %d", m.detailH)
	}
}

// TestStatusBarTunnelURL verifies the live tunnel URL is surfaced in the status
// bar once available, and shows a connecting placeholder until then.
func TestStatusBarTunnelURL(t *testing.T) {
	url := ""
	m := newModel(&options.Options{Webroot: "/srv", Tunnel: true}, nil, nil, nil, nil, func() string { return url }, nil)

	if seg := strings.Join(m.statusSegments(), " "); !strings.Contains(seg, "tunnel (connecting)") {
		t.Fatalf("expected connecting placeholder before URL is up, got: %q", seg)
	}

	url = "https://abc123.tunnel.example"
	if seg := strings.Join(m.statusSegments(), " "); !strings.Contains(seg, url) {
		t.Fatalf("expected live tunnel URL in status bar, got: %q", seg)
	}
}

// TestExportPaneJSON verifies a per-pane export writes goshs-<proto>-log.json
// as a bare JSON array of the raw events, matching the web UI's exportHTTP().
func TestExportPaneJSON(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(cwd)

	m := newModel(&options.Options{Webroot: dir}, nil, nil, nil, nil, nil, nil)
	m.addHTTP([]byte(`{"type":"http","source":"10.0.0.5:5000","method":"GET","status":200,"url":"/secret"}`))

	m.exportPane(paneHTTP)

	if !strings.HasPrefix(m.flash, "exported 1 HTTP event(s)") {
		t.Fatalf("unexpected flash after export: %q", m.flash)
	}

	data, err := os.ReadFile(filepath.Join(dir, "goshs-http-log.json"))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var events []map[string]any
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("export is not a JSON array: %v\n%s", err, data)
	}
	if len(events) != 1 || events[0]["url"] != "/secret" || events[0]["type"] != "http" {
		t.Fatalf("unexpected export contents: %s", data)
	}
}

// TestExportAllJSON verifies the combined export mirrors the web UI's
// exportAllLogs() wrapper object: {generatedAt, http, dns, smtp, smb, ldap}.
func TestExportAllJSON(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(cwd)

	m := newModel(&options.Options{Webroot: dir}, nil, nil, nil, nil, nil, nil)
	m.addHTTP([]byte(`{"type":"http","source":"10.0.0.5:5000","method":"GET","status":200,"url":"/a"}`))
	m.addDNS([]byte(`{"type":"dns","name":"evil.example","qtype":"A","source":"10.0.0.6:5300"}`))

	m.exportAll()

	data, err := os.ReadFile(filepath.Join(dir, "goshs-all-logs.json"))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var all struct {
		GeneratedAt string           `json:"generatedAt"`
		HTTP        []map[string]any `json:"http"`
		DNS         []map[string]any `json:"dns"`
		SMTP        []map[string]any `json:"smtp"`
		SMB         []map[string]any `json:"smb"`
		LDAP        []map[string]any `json:"ldap"`
	}
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatalf("export is not the expected object: %v\n%s", err, data)
	}
	if all.GeneratedAt == "" {
		t.Fatalf("missing generatedAt; got:\n%s", data)
	}
	if len(all.HTTP) != 1 || len(all.DNS) != 1 {
		t.Fatalf("expected 1 http + 1 dns event, got http=%d dns=%d", len(all.HTTP), len(all.DNS))
	}
}

// TestExportEmptyPane verifies exporting a pane with no events writes nothing
// and flashes a "nothing to export" notice instead.
func TestExportEmptyPane(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(cwd)

	m := newModel(&options.Options{Webroot: dir}, nil, nil, nil, nil, nil, nil)
	m.exportPane(paneDNS)

	if m.flash != "nothing to export" {
		t.Fatalf("expected nothing-to-export flash, got %q", m.flash)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(matches) != 0 {
		t.Fatalf("expected no file written, found %v", matches)
	}
}

// TestChatRefreshOldestFirst verifies the CHAT pane mirrors the shared chat log
// in order, oldest message first (newest at the bottom).
func TestChatRefreshOldestFirst(t *testing.T) {
	ch := chat.New()
	_, _ = ch.AddEntry("alice", "first")
	_, _ = ch.AddEntry("bob", "second")

	m := newModel(&options.Options{}, nil, nil, nil, ch, nil, nil)
	m.refreshChat()

	p := m.panes[paneChat]
	if len(p.rows) != 2 {
		t.Fatalf("want 2 chat rows, got %d", len(p.rows))
	}
	if !strings.Contains(p.rows[0].summary, "first") {
		t.Fatalf("oldest message should be row 0, got %q", p.rows[0].summary)
	}
	if !strings.Contains(p.rows[1].summary, "second") {
		t.Fatalf("newest message should be the last row, got %q", p.rows[1].summary)
	}
}

// TestChatAddViaInput drives the post-message input mode and checks the message
// reaches the shared chat log (authored by the TUI) and the pane.
func TestChatAddViaInput(t *testing.T) {
	ch := chat.New()
	m := newModel(&options.Options{}, nil, nil, nil, ch, nil, nil)
	m.active = paneChat

	// "a" opens the input prompt with the chat-post submit callback wired.
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	if !m.inputActive {
		t.Fatal("expected input mode to open on 'a'")
	}

	m.handleInputKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("hello")})
	m.handleInputKey(tea.KeyMsg{Type: tea.KeySpace})
	m.handleInputKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("world")})
	if m.inputBuf != "hello world" {
		t.Fatalf("inputBuf = %q, want %q", m.inputBuf, "hello world")
	}

	m.handleInputKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.inputActive {
		t.Fatal("input mode should close on enter")
	}
	messages, _ := ch.GetEntries()
	if len(messages) != 1 || messages[0].Content != "hello world" {
		t.Fatalf("chat not updated as expected: %+v", messages)
	}
	if messages[0].Author == "" {
		t.Fatalf("chat message should carry a TUI author, got %+v", messages[0])
	}
	if !strings.Contains(m.panes[paneChat].rows[0].summary, "hello world") {
		t.Fatalf("chat pane not refreshed: %q", m.panes[paneChat].rows[0].summary)
	}
}

// TestChatDeleteAndClear verifies delete-selected and clear-all act on the
// shared chat log.
func TestChatDeleteAndClear(t *testing.T) {
	ch := chat.New()
	_, _ = ch.AddEntry("alice", "a")
	_, _ = ch.AddEntry("bob", "b")

	m := newModel(&options.Options{}, nil, nil, nil, ch, nil, nil)
	m.active = paneChat
	m.refreshChat()

	m.panes[paneChat].sel = 1 // newest ("b")
	m.deleteChatEntry()
	messages, _ := ch.GetEntries()
	if len(messages) != 1 || messages[0].Content != "a" {
		t.Fatalf("delete-selected wrong result: %+v", messages)
	}

	m.clearChat()
	if messages, _ := ch.GetEntries(); len(messages) != 0 {
		t.Fatalf("clear failed, %d messages left", len(messages))
	}
}

func TestParseListenerAddr(t *testing.T) {
	cases := []struct {
		in      string
		ip      string
		port    int
		wantErr bool
	}{
		{"4444", "0.0.0.0", 4444, false},
		{"127.0.0.1:9001", "127.0.0.1", 9001, false},
		{":8080", "0.0.0.0", 8080, false},
		{"notaport", "", 0, true},
		{"1.2.3.4:99999", "", 0, true},
		{"1.2.3.4:0", "", 0, true},
	}
	for _, c := range cases {
		ip, port, err := parseListenerAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error, got %s:%d", c.in, ip, port)
			}
			continue
		}
		if err != nil || ip != c.ip || port != c.port {
			t.Fatalf("%q: got %s:%d err=%v, want %s:%d", c.in, ip, port, err, c.ip, c.port)
		}
	}
}

// TestStartStopListener drives the SHELLS pane's start/stop actions against a
// real catcher manager and verifies the listener appears and disappears.
func TestStartStopListener(t *testing.T) {
	// Grab a free port so the bind cannot collide with anything in CI.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	mgr := catcher.NewManager(nil)
	m := newModel(&options.Options{}, nil, mgr, nil, nil, nil, nil)
	m.active = paneShells

	m.startListener(fmt.Sprintf("127.0.0.1:%d", port))
	if got := len(mgr.GetListeners()); got != 1 {
		t.Fatalf("expected 1 listener after start, got %d (flash: %q)", got, m.flash)
	}
	m.refreshShells()
	if len(m.panes[paneShells].rows) != 1 {
		t.Fatalf("SHELLS pane should show the listener row")
	}

	m.panes[paneShells].sel = 0
	m.stopSelectedListener()
	if got := len(mgr.GetListeners()); got != 0 {
		t.Fatalf("expected 0 listeners after stop, got %d", got)
	}
	if !strings.HasPrefix(m.flash, "stopped listener") {
		t.Fatalf("unexpected flash: %q", m.flash)
	}
}

// TestSaveSMTPAttachments verifies the selected mail's attachments are pulled
// from the in-process store and written to goshs-attachments in the working dir.
func TestSaveSMTPAttachments(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(cwd)

	smtpattach.Save("att-test-1", "report.pdf", "application/pdf", []byte("PDFDATA"))

	m := newModel(&options.Options{}, nil, nil, nil, nil, nil, nil)
	m.addSMTP([]byte(`{"type":"smtp","from":"a@b.c","subject":"hi","attachments":[{"id":"att-test-1","filename":"report.pdf","contentType":"application/pdf","size":7}]}`))
	m.active = paneSMTP
	m.panes[paneSMTP].sel = 0

	m.saveSMTPAttachments()
	if !strings.HasPrefix(m.flash, "saved 1 attachment") {
		t.Fatalf("unexpected flash: %q", m.flash)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "goshs-attachments", "*report.pdf"))
	if len(matches) != 1 {
		t.Fatalf("expected one saved attachment, found %d", len(matches))
	}
	if data, _ := os.ReadFile(matches[0]); string(data) != "PDFDATA" {
		t.Fatalf("attachment content = %q, want PDFDATA", data)
	}
}

// TestSaveSMTPAttachmentsNone reports cleanly when the selected mail has no
// attachments.
func TestSaveSMTPAttachmentsNone(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(cwd)

	m := newModel(&options.Options{}, nil, nil, nil, nil, nil, nil)
	m.addSMTP([]byte(`{"type":"smtp","from":"a@b.c","subject":"hi"}`))
	m.active = paneSMTP

	m.saveSMTPAttachments()
	if m.flash != "no attachments on this mail" {
		t.Fatalf("unexpected flash: %q", m.flash)
	}
}

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// Pressing 'p' opens the password popup masked; 'u' reveals the plaintext and
// 'esc' dismisses it.
func TestPasswordPopupMaskRevealClose(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv", Username: "patrick", Password: "correcthorse"}, nil, nil, nil, nil, nil, nil)
	m.width, m.height = 80, 24

	m.handleKey(runes("p"))
	if !m.showPassword || m.passwordSeen {
		t.Fatalf("after 'p': showPassword=%v passwordSeen=%v, want true/false", m.showPassword, m.passwordSeen)
	}
	if pop := m.passwordPopup(); strings.Contains(pop, "correcthorse") || !strings.Contains(pop, "•") {
		t.Fatalf("masked popup should hide plaintext behind dots, got:\n%s", pop)
	}

	m.handleKey(runes("u"))
	if !m.passwordSeen {
		t.Fatalf("after 'u': passwordSeen=false, want true")
	}
	if pop := m.passwordPopup(); !strings.Contains(pop, "correcthorse") {
		t.Fatalf("revealed popup should show plaintext, got:\n%s", pop)
	}

	// 'u' again re-masks.
	m.handleKey(runes("u"))
	if m.passwordSeen {
		t.Fatalf("second 'u' should re-mask, passwordSeen=true")
	}

	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.showPassword {
		t.Fatalf("esc should close the popup")
	}
}

// 'q' inside the popup dismisses it instead of quitting goshs.
func TestPasswordPopupQuitDismisses(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv", Username: "u", Password: "pw"}, nil, nil, nil, nil, nil, nil)
	m.handleKey(runes("p"))
	_, cmd := m.handleKey(runes("q"))
	if m.showPassword {
		t.Fatalf("'q' should close the popup")
	}
	if cmd != nil {
		t.Fatalf("'q' in popup should not emit a quit command")
	}
}

// Without basic-auth configured, 'p' does nothing.
func TestPasswordPopupNoAuthNoop(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv"}, nil, nil, nil, nil, nil, nil)
	m.handleKey(runes("p"))
	if m.showPassword {
		t.Fatalf("'p' with no password set should not open the popup")
	}
}

// In the GENERATOR pane 'p' edits LPORT, so it must not open the popup.
func TestPasswordPopupNotOpenedInGenerator(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv", Username: "u", Password: "pw"}, nil, nil, nil, nil, nil, nil)
	m.active = paneGenerator
	m.handleKey(runes("p"))
	if m.showPassword {
		t.Fatalf("'p' in the generator pane should edit LPORT, not open the popup")
	}
	if !m.inputActive {
		t.Fatalf("'p' in the generator pane should begin the LPORT input")
	}
}

// A pre-hashed (bcrypt) secret is flagged as unrecoverable plaintext.
func TestPasswordPopupHashedFlag(t *testing.T) {
	m := newModel(&options.Options{Webroot: "/srv", Username: "u", Password: "$2a$12$abcdefghijklmnopqrstuv"}, nil, nil, nil, nil, nil, nil)
	m.showPassword = true
	m.passwordSeen = true
	if pop := m.passwordPopup(); !strings.Contains(pop, "bcrypt hash") {
		t.Fatalf("hashed password popup should note the bcrypt hash, got:\n%s", pop)
	}
}
