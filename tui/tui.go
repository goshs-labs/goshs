// Package tui implements the optional interactive terminal dashboard for
// goshs. It is a second, in-process consumer of the WebSocket hub: it
// subscribes to the same broadcast stream and history that the browser Collab
// tab uses and renders it as a live full-screen view, so an operator running
// goshs headless over SSH gets situational awareness without port-forwarding
// the web UI.
package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aymanbagabas/go-osc52/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/smtpattach"
	"goshs.de/goshs/v2/utils"
	"goshs.de/goshs/v2/ws"
)

// maxRows caps how many events are retained per pane so a long-running
// session cannot grow the TUI's memory unbounded — mirroring the hub's own
// ring-buffer policy.
const maxRows = 500

// Run starts the dashboard and blocks until the operator quits it (q or
// Ctrl+C) or the self-destruct timer fires on ttlC. It subscribes to the hub
// for the duration and unsubscribes on exit. The caller is responsible for
// shutting the servers down afterwards. ttlC may be nil when --ttl is unset.
func Run(opts *options.Options, hub *ws.Hub, mgr *catcher.Manager, ch *chat.Chat, tunnelURL func() string, ttlC <-chan time.Time) error {
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)

	m := newModel(opts, hub, mgr, sub, ch, tunnelURL, ttlC)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// --- messages ---------------------------------------------------------------

type hubMsg []byte
type tickMsg time.Time
type subClosedMsg struct{}
type ttlExpiredMsg struct{}

func waitForEvent(sub chan []byte) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-sub
		if !ok {
			return subClosedMsg{}
		}
		return hubMsg(msg)
	}
}

func waitForTTL(ttlC <-chan time.Time) tea.Cmd {
	if ttlC == nil {
		return nil
	}
	return func() tea.Msg {
		<-ttlC
		return ttlExpiredMsg{}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// --- model ------------------------------------------------------------------

// row kinds for the SHELLS pane, distinguishing a listener row from a session
// row so key actions (attach, kill, stop, restart) target the right object.
const (
	rowEvent    = ""         // ordinary collab event (default)
	rowListener = "listener" // a catcher listener
	rowSession  = "session"  // a connected reverse-shell session under a listener
)

type eventRow struct {
	summary string
	detail  string
	accent  lipgloss.Color
	kind    string          // "" for events; rowListener/rowSession in the SHELLS pane
	raw     json.RawMessage // original event JSON, for export parity with the web UI
}

type pane struct {
	name      string
	icon      string
	rows      []eventRow
	sel       int
	top       int
	detailTop int // scroll offset within the open detail body
}

// add inserts a new event at the top of the pane so the newest event is
// always row 0, mirroring the Collab tab in the web UI. Selection adjustment
// is left to model.addRow, which knows whether the detail view is open.
func (p *pane) add(r eventRow) {
	p.rows = append([]eventRow{r}, p.rows...)
	if len(p.rows) > maxRows {
		p.rows = p.rows[:maxRows]
	}
}

const (
	paneHTTP = iota
	paneDNS
	paneSMB
	paneLDAP
	paneSMTP
	paneShells
	paneGenerator
	paneChat
)

type model struct {
	opts *options.Options
	hub  *ws.Hub
	mgr  *catcher.Manager
	chat *chat.Chat
	sub  chan []byte

	tunnelURL func() string    // live public tunnel URL getter; nil when unavailable
	ttl       <-chan time.Time // self-destruct trigger; nil when --ttl unset

	panes    []*pane
	active   int
	width    int
	height   int
	deadline time.Time // zero when no --ttl set
	detail   bool      // detail view of the selected row is open
	detailH  int       // last rendered detail viewport height (for paging)

	flash       string    // transient status message (e.g. export result)
	flashExpiry time.Time // when the flash message should clear

	clipSeq string // OSC 52 escape sequence to emit on the next render (one-shot clipboard copy), empty when nothing pending

	inputActive bool                 // single-line text input mode is open
	inputBuf    string               // text typed so far in input mode
	inputPrompt string               // label shown in the status bar while typing
	inputSubmit func(string) tea.Cmd // invoked with the trimmed buffer on enter

	// Reverse-shell generator state (GENERATOR pane). Mirrors the web UI
	// catcher generator: a selected payload template plus LHOST/LPORT and an
	// output encoding, all editable in place.
	genSel  int      // index into shellDB of the selected payload
	genIP   string   // LHOST substituted into the template
	genPort string   // LPORT substituted into the template
	genEnc  encoding // output encoding (none / url / base64)

	// Password reveal popup. The status bar shows the auth *user* but never the
	// password; this modal overlay lets the operator look it up — handy when the
	// password was generated inline at launch (e.g. -b "user:$(xkcdpass …)") and
	// is otherwise unknown. Masked on open; 'u' toggles the plaintext.
	showPassword bool // popup overlay is open
	passwordSeen bool // plaintext uncovered (vs. masked with dots)
}

func newModel(opts *options.Options, hub *ws.Hub, mgr *catcher.Manager, sub chan []byte, ch *chat.Chat, tunnelURL func() string, ttlC <-chan time.Time) *model {
	var deadline time.Time
	if opts.TTL > 0 {
		deadline = time.Now().Add(opts.TTL)
	}
	return &model{
		opts:      opts,
		hub:       hub,
		mgr:       mgr,
		chat:      ch,
		sub:       sub,
		tunnelURL: tunnelURL,
		ttl:       ttlC,
		deadline:  deadline,
		genIP:     defaultLHOST(opts),
		genPort:   "4444",
		panes: []*pane{
			{name: "HTTP", icon: "🌐"},
			{name: "DNS", icon: "📡"},
			{name: "SMB", icon: "🔑"},
			{name: "LDAP", icon: "📇"},
			{name: "SMTP", icon: "📨"},
			{name: "SHELLS", icon: "🐚"},
			{name: "GENERATOR", icon: "⚡"},
			{name: "CHAT", icon: "💬"},
		},
	}
}

// defaultLHOST picks a sensible LHOST for the generator: the bound IP when it is
// a concrete address, mirroring the server's --tpl-var LHOST derivation; a
// placeholder otherwise (e.g. when bound to 0.0.0.0) so the operator can edit it.
func defaultLHOST(opts *options.Options) string {
	if opts.IP != "" && opts.IP != "0.0.0.0" {
		return opts.IP
	}
	return "10.10.10.10"
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(waitForEvent(m.sub), waitForTTL(m.ttl), tick())
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case hubMsg:
		m.ingest([]byte(msg))
		return m, waitForEvent(m.sub)

	case subClosedMsg:
		return m, tea.Quit

	case shellClosedMsg:
		// Returned after detaching from (or losing) an attached session.
		m.refreshShells()
		if msg.err != nil {
			m.setFlash("shell session ended: " + msg.err.Error())
		} else {
			m.setFlash("returned from shell session")
		}
		return m, nil

	case ttlExpiredMsg:
		// Self-destruct fired; quitting returns control to main, which runs
		// the graceful shutdown.
		return m, tea.Quit

	case tickMsg:
		m.refreshShells()
		m.refreshChat()
		if !m.flashExpiry.IsZero() && time.Now().After(m.flashExpiry) {
			m.flash = ""
			m.flashExpiry = time.Time{}
		}
		return m, tick()
	}
	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// The password popup is a modal overlay: while it is open it captures every
	// key (so 'q' dismisses the popup rather than quitting goshs) and nothing
	// below runs.
	if m.showPassword {
		return m.handlePasswordKey(msg)
	}
	// While typing a new chat message, keys feed the input buffer instead of
	// driving navigation.
	if m.inputActive {
		return m.handleInputKey(msg)
	}
	// The GENERATOR pane is a form, not an event log, so it owns selection and
	// edit keys; only keys it does not handle (pane switching, quit) fall
	// through to the shared navigation below.
	if m.active == paneGenerator {
		if cmd, handled := m.handleGeneratorKey(msg); handled {
			return m, cmd
		}
	}
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab", "right", "l":
		m.detail = false
		m.active = (m.active + 1) % len(m.panes)
	case "shift+tab", "left", "h":
		m.detail = false
		m.active = (m.active - 1 + len(m.panes)) % len(m.panes)
	case "up", "k":
		p := m.panes[m.active]
		if p.sel > 0 {
			p.sel--
			p.detailTop = 0
		}
	case "down", "j":
		p := m.panes[m.active]
		if p.sel < len(p.rows)-1 {
			p.sel++
			p.detailTop = 0
		}
	case "home", "g":
		// Jump to the newest event (row 0). In detail view this surfaces any
		// events that arrived while the operator was reading an older one.
		p := m.panes[m.active]
		p.sel = 0
		p.detailTop = 0
	case "end", "G":
		p := m.panes[m.active]
		if len(p.rows) > 0 {
			p.sel = len(p.rows) - 1
			p.detailTop = 0
		}
	case "pgup", "ctrl+u":
		// Scroll the open detail body up; the view clamps the offset.
		p := m.panes[m.active]
		p.detailTop -= m.detailStep()
		if p.detailTop < 0 {
			p.detailTop = 0
		}
	case "pgdown", "ctrl+d", " ":
		m.panes[m.active].detailTop += m.detailStep()
	case "e":
		// Export the active pane to goshs-<proto>-log.json.
		m.exportPane(m.active)
	case "E":
		// Export all panes to goshs-all-logs.json.
		m.exportAll()
	case "a":
		// Chat: post a message. Shells: start a listener. Both open the
		// single-line input prompt.
		switch m.active {
		case paneChat:
			if m.chat != nil {
				m.beginInput("message", func(text string) tea.Cmd { return m.addChatEntry(text) })
			}
		case paneShells:
			if m.mgr != nil {
				m.beginInput("start listener (ip:port or port)", func(text string) tea.Cmd {
					return m.startListener(text)
				})
			}
		}
	case "d":
		// Chat: delete the selected message. Shells: stop the selected
		// listener.
		switch m.active {
		case paneChat:
			return m, m.deleteChatEntry()
		case paneShells:
			return m, m.shellDelete()
		}
	case "r":
		// Restart the selected listener on the same ip:port (shells pane only).
		if m.active == paneShells {
			return m, m.restartSelectedListener()
		}
	case "i":
		// Attach to the selected reverse-shell session (shells pane only).
		if m.active == paneShells {
			return m, m.attachSelectedSession()
		}
	case "u":
		// Stabilise the selected shell as a Unix PTY (shells pane only).
		if m.active == paneShells {
			return m, m.upgradeSelectedSession(false)
		}
	case "U":
		// Stabilise the selected shell via Windows ConPtyShell (shells pane only).
		if m.active == paneShells {
			return m, m.upgradeSelectedSession(true)
		}
	case "C":
		// Clear the whole chat log (chat pane only).
		if m.active == paneChat {
			return m, m.clearChat()
		}
	case "s":
		// Save the selected mail's attachments to disk (SMTP pane only).
		if m.active == paneSMTP {
			m.saveSMTPAttachments()
		}
	case "p":
		// Open the password reveal popup. Only meaningful when basic-auth
		// credentials are set — the status bar shows the user but not the
		// password. (In the GENERATOR pane 'p' edits LPORT and is consumed by
		// handleGeneratorKey before reaching here.)
		if m.opts.Password != "" {
			m.showPassword = true
			m.passwordSeen = false
		}
	case "enter":
		// On a reverse-shell session row, ⏎ attaches; otherwise toggle detail.
		if m.active == paneShells {
			if cmd := m.attachSelectedSession(); cmd != nil {
				return m, cmd
			}
		}
		p := m.panes[m.active]
		if len(p.rows) > 0 {
			m.detail = !m.detail
			p.detailTop = 0
		}
	case "esc":
		m.detail = false
	}
	return m, nil
}

// handlePasswordKey drives the modal password popup: 'u' toggles the plaintext,
// 'y'/'c' copy it to the operator's clipboard, and esc/q/p (or enter) dismiss.
// It captures all other keys so navigation underneath stays frozen while open.
func (m *model) handlePasswordKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "u":
		m.passwordSeen = !m.passwordSeen
	case "y", "c":
		m.copyToClipboard(m.opts.Password, "copied password to clipboard")
	case "esc", "q", "p", "enter":
		m.showPassword = false
		m.passwordSeen = false
	}
	return m, nil
}

// detailStep is how many lines pgup/pgdown scroll the detail body by — close
// to a full page based on the last rendered detail height.
func (m *model) detailStep() int {
	if m.detailH > 1 {
		return m.detailH - 1
	}
	return 10
}

// --- ingest -----------------------------------------------------------------

// addRow stores a new event in pane idx and keeps the operator anchored on
// whatever they were looking at. New events are prepended (row 0), so to hold
// the view steady the selection and scroll offset shift down with the older
// rows — except when sitting at the very top of the list view, where the
// selection rides the newest event as a live tail. While the detail view is
// open on this pane the selection always follows its event, so an incoming
// event never swaps out what is being inspected.
func (m *model) addRow(idx int, r eventRow) {
	p := m.panes[idx]
	p.add(r)
	if len(p.rows) == 1 {
		return
	}
	riding := p.sel == 0 && p.top == 0 && !(m.detail && idx == m.active)
	if riding {
		return
	}
	if p.sel < len(p.rows)-1 {
		p.sel++
	}
	p.top++
}

func (m *model) ingest(raw []byte) {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return
	}

	switch peek.Type {
	case "catchup":
		m.ingestCatchup(raw)
	case "http":
		m.addHTTP(raw)
	case "dns":
		m.addDNS(raw)
	case "smtp":
		m.addSMTP(raw)
	case "smb":
		m.addSMB(raw)
	case "ldap":
		m.addLDAP(raw)
	case "chatMessage", "chatEdit", "chatReaction", "chatDelete", "chatClear":
		// A web client (or our own mutation) changed the shared chat log; the
		// ws handler has already mutated the shared struct, so rebuild the pane
		// from it immediately rather than waiting for the next tick. (Reactions
		// aren't shown in the TUI pane yet, but rebuilding keeps edits current.)
		m.refreshChat()
	}
	// catcherConnection events are intentionally ignored here: the SHELLS pane
	// is rebuilt from the catcher manager on every tick, which reflects both
	// connects and disconnects accurately.
}

func (m *model) ingestCatchup(raw []byte) {
	var cu struct {
		HTTP []json.RawMessage `json:"http"`
		DNS  []json.RawMessage `json:"dns"`
		SMTP []json.RawMessage `json:"smtp"`
		SMB  []json.RawMessage `json:"smb"`
		LDAP []json.RawMessage `json:"ldap"`
	}
	if err := json.Unmarshal(raw, &cu); err != nil {
		return
	}
	for _, e := range cu.HTTP {
		m.addHTTP(e)
	}
	for _, e := range cu.DNS {
		m.addDNS(e)
	}
	for _, e := range cu.SMTP {
		m.addSMTP(e)
	}
	for _, e := range cu.SMB {
		m.addSMB(e)
	}
	for _, e := range cu.LDAP {
		m.addLDAP(e)
	}
}

func (m *model) addHTTP(raw []byte) {
	var e ws.HTTPEvent
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	accent := lipgloss.Color(nord14) // green: 2xx
	if e.Status >= 400 {
		accent = lipgloss.Color(nord11) // red: 4xx/5xx
	} else if e.Status >= 300 {
		accent = lipgloss.Color(nord9) // blue: 3xx
	}
	summary := fmt.Sprintf("%s  %-15s %-6s %-3d %s",
		tstamp(e.Timestamp), host(e.Source), e.Method, e.Status, e.URL)

	var b strings.Builder
	fmt.Fprintf(&b, "Time:      %s\n", e.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Source:    %s\n", e.Source)
	fmt.Fprintf(&b, "Request:   %s %s -> %d\n", e.Method, e.URL, e.Status)
	fmt.Fprintf(&b, "UserAgent: %s\n", e.UserAgent)
	if e.Parameters != "" {
		b.WriteString("\nParameters:\n")
		if out, any := decodeForm(e.Parameters); any {
			b.WriteString(indentBlock(out, "  ") + "\n")
		} else {
			fmt.Fprintf(&b, "  %s\n", e.Parameters)
		}
	}
	if len(e.Headers) > 0 {
		b.WriteString("\nHeaders:\n")
		for _, k := range sortedKeys(e.Headers) {
			b.WriteString("  " + formatHeader(k, e.Headers[k]) + "\n")
		}
	}
	if e.Body != "" {
		b.WriteString("\nBody:\n")
		if text, tag := smartDecode(e.Body); tag != "" {
			fmt.Fprintf(&b, "[%s]\n%s\n", tag, text)
		} else {
			fmt.Fprintf(&b, "%s\n", e.Body)
		}
	}
	m.addRow(paneHTTP, eventRow{summary: summary, detail: b.String(), accent: accent, raw: raw})
}

func (m *model) addDNS(raw []byte) {
	var e ws.DNSEvent
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	summary := fmt.Sprintf("%s  %-15s %-5s %s", tstamp(e.Time), host(e.Source), e.QType, e.Name)
	detail := fmt.Sprintf("Time:   %s\nSource: %s\nType:   %s\nName:   %s\n",
		e.Time.Format(time.RFC3339), e.Source, e.QType, e.Name)
	m.addRow(paneDNS, eventRow{summary: summary, detail: detail, accent: lipgloss.Color(nord8), raw: raw})
}

func (m *model) addSMTP(raw []byte) {
	var e ws.SMTPEvent
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	att := ""
	if len(e.Attachments) > 0 {
		att = fmt.Sprintf(" [%d att]", len(e.Attachments))
	}
	summary := fmt.Sprintf("%s  %-24s %s%s", tstamp(e.Timestamp), trunc(e.From, 24), e.Subject, att)

	var b strings.Builder
	fmt.Fprintf(&b, "Time:    %s\n", e.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "From:    %s\n", e.From)
	fmt.Fprintf(&b, "To:      %s\n", strings.Join(e.To, ", "))
	if len(e.CC) > 0 {
		fmt.Fprintf(&b, "CC:      %s\n", strings.Join(e.CC, ", "))
	}
	fmt.Fprintf(&b, "Subject: %s\n", e.Subject)
	for _, a := range e.Attachments {
		fmt.Fprintf(&b, "Attach:  %s (%s, %d bytes)\n", a.Filename, a.ContentType, a.Size)
	}
	if len(e.Attachments) > 0 {
		b.WriteString("         (press s to save attachments to disk)\n")
	}
	// Prefer the plaintext part; fall back to rendering the HTML body as text so
	// HTML-only mail is no longer blank in the TUI.
	switch {
	case e.Body != "":
		fmt.Fprintf(&b, "\n%s\n", e.Body)
	case e.HTMLBody != "":
		fmt.Fprintf(&b, "\n[rendered from HTML]\n%s\n", htmlToText(e.HTMLBody))
	}
	m.addRow(paneSMTP, eventRow{summary: summary, detail: b.String(), accent: lipgloss.Color(nord13), raw: raw})
}

// saveSMTPAttachments writes the selected mail's attachments to a
// goshs-attachments directory under the working dir, pulling the bytes from the
// in-process attachment store. Attachments may have been purged on a
// long-running instance, in which case they are skipped.
func (m *model) saveSMTPAttachments() {
	p := m.panes[paneSMTP]
	if len(p.rows) == 0 {
		return
	}
	var e ws.SMTPEvent
	if json.Unmarshal(p.rows[p.sel].raw, &e) != nil {
		m.setFlash("could not read selected mail")
		return
	}
	if len(e.Attachments) == 0 {
		m.setFlash("no attachments on this mail")
		return
	}

	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	dir = filepath.Join(dir, "goshs-attachments")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.setFlash("save failed: " + err.Error())
		return
	}

	saved := 0
	for _, att := range e.Attachments {
		a, ok := smtpattach.Get(att.ID)
		if !ok {
			continue // expired or purged from the store
		}
		// Prefix with a short ID so attachments sharing a filename (or matching
		// an existing file in the directory) cannot clobber one another.
		name := fmt.Sprintf("%s-%s", shortID(att.ID), safeFilename(att.Filename))
		if err := os.WriteFile(filepath.Join(dir, name), a.Data, 0o644); err != nil {
			m.setFlash("save failed: " + err.Error())
			return
		}
		saved++
	}
	if saved == 0 {
		m.setFlash("attachments expired — nothing saved")
		return
	}
	m.setFlash(fmt.Sprintf("saved %d attachment(s) → %s", saved, dir))
}

// safeFilename reduces an attachment filename to a single safe path component
// so a malicious name cannot escape the target directory.
func safeFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return "attachment"
	}
	return name
}

func (m *model) addSMB(raw []byte) {
	var e ws.NTLMEvent
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	cracked := ""
	if e.CrackedPassword != "" {
		cracked = " cracked=" + e.CrackedPassword
	}
	user := e.Username
	if e.Domain != "" {
		user = e.Domain + "\\" + e.Username
	}
	summary := fmt.Sprintf("%s  %-15s %-9s %s%s", tstamp(e.Timestamp), host(e.Source), e.HashType, user, cracked)

	var b strings.Builder
	fmt.Fprintf(&b, "Time:        %s\n", e.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Source:      %s\n", e.Source)
	fmt.Fprintf(&b, "User:        %s\n", user)
	fmt.Fprintf(&b, "Workstation: %s\n", e.Workstation)
	fmt.Fprintf(&b, "Hash type:   %s (hashcat mode %s)\n", e.HashType, e.HashcatMode)
	if e.CrackedPassword != "" {
		fmt.Fprintf(&b, "Cracked:     %s\n", e.CrackedPassword)
	}
	fmt.Fprintf(&b, "\nHash:\n%s\n", e.Hash)
	m.addRow(paneSMB, eventRow{summary: summary, detail: b.String(), accent: lipgloss.Color(nord15), raw: raw})
}

func (m *model) addLDAP(raw []byte) {
	var e ws.LDAPEvent
	if json.Unmarshal(raw, &e) != nil {
		return
	}
	var summary string
	var b strings.Builder
	fmt.Fprintf(&b, "Time:      %s\n", e.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Source:    %s\n", e.Source)
	fmt.Fprintf(&b, "Operation: %s\n", e.Operation)
	if e.Operation == "ntlm" {
		user := e.Username
		if e.Domain != "" {
			user = e.Domain + "\\" + e.Username
		}
		cracked := ""
		if e.CrackedPassword != "" {
			cracked = " cracked=" + e.CrackedPassword
		}
		summary = fmt.Sprintf("%s  %-15s ntlm  %-9s %s%s", tstamp(e.Timestamp), host(e.Source), e.HashType, user, cracked)
		fmt.Fprintf(&b, "User:      %s\n", user)
		fmt.Fprintf(&b, "Hash type: %s (hashcat mode %s)\n", e.HashType, e.HashcatMode)
		if e.CrackedPassword != "" {
			fmt.Fprintf(&b, "Cracked:   %s\n", e.CrackedPassword)
		}
		fmt.Fprintf(&b, "\nHash:\n%s\n", e.Hash)
	} else {
		summary = fmt.Sprintf("%s  %-15s %-6s %s", tstamp(e.Timestamp), host(e.Source), e.Operation, e.DN)
		fmt.Fprintf(&b, "DN:        %s\n", e.DN)
		if e.Password != "" {
			fmt.Fprintf(&b, "Password:  %s\n", e.Password)
		}
	}
	m.addRow(paneLDAP, eventRow{summary: summary, detail: b.String(), accent: lipgloss.Color(nord9), raw: raw})
}

// refreshShells rebuilds the SHELLS pane from the catcher manager. Each row is
// a listener (so idle listeners with no connections are still visible and
// selectable for stopping); the detail view lists that listener's sessions.
func (m *model) refreshShells() {
	if m.mgr == nil {
		return
	}
	p := m.panes[paneShells]
	prevSel := p.sel
	p.rows = p.rows[:0]
	listeners := m.mgr.GetListeners()
	sort.SliceStable(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].IP < listeners[j].IP
	})
	for _, ln := range listeners {
		accent := lipgloss.Color(nord8) // listening, idle
		if len(ln.Sessions) > 0 {
			accent = lipgloss.Color(nord14) // has live sessions
		}
		summary := fmt.Sprintf("%-21s  %d session(s)", fmt.Sprintf("%s:%d", ln.IP, ln.Port), len(ln.Sessions))

		var d strings.Builder
		fmt.Fprintf(&d, "Listener: %s:%d\nID:       %s\nSessions: %d\n", ln.IP, ln.Port, ln.ID, len(ln.Sessions))
		for _, s := range ln.Sessions {
			fmt.Fprintf(&d, "  • %s  (session %s)\n", s.RemoteAddr, shortID(s.ID))
		}
		raw, _ := json.Marshal(ln)
		p.rows = append(p.rows, eventRow{summary: summary, detail: d.String(), accent: accent, kind: rowListener, raw: raw})

		// One row per connected session, so each shell is selectable to attach
		// to or kill individually.
		for _, s := range ln.Sessions {
			sraw, _ := json.Marshal(s)
			ssummary := fmt.Sprintf("    ↳ %-15s  session %s", s.RemoteAddr, shortID(s.ID))
			sdetail := fmt.Sprintf("Session:   %s\nRemote:    %s\nListener:  %s:%d\n\nPress ⏎/i to attach (Ctrl+] detaches), u upgrade to PTY,\nU ConPtyShell (Windows), d to kill.\n", s.ID, s.RemoteAddr, ln.IP, ln.Port)
			p.rows = append(p.rows, eventRow{summary: ssummary, detail: sdetail, accent: lipgloss.Color(nord14), kind: rowSession, raw: sraw})
		}
	}
	if prevSel < len(p.rows) {
		p.sel = prevSel
	} else if len(p.rows) > 0 {
		p.sel = len(p.rows) - 1
	} else {
		p.sel = 0
	}
}

// --- listeners --------------------------------------------------------------

// startListener parses "ip:port" or a bare "port" and starts a catcher
// listener, reporting the outcome via a flash message. On success it returns a
// command that broadcasts refreshCatcher so the web UI adopts the new listener.
func (m *model) startListener(addr string) tea.Cmd {
	if m.mgr == nil {
		return nil
	}
	ip, port, err := parseListenerAddr(addr)
	if err != nil {
		m.setFlash("invalid address: " + err.Error())
		return nil
	}
	info, err := m.mgr.StartListener(ip, port)
	if err != nil {
		m.setFlash("start listener failed: " + err.Error())
		return nil
	}
	m.refreshShells()
	m.setFlash(fmt.Sprintf("listener started on %s:%d", info.IP, info.Port))
	return m.broadcast("refreshCatcher")
}

// stopSelectedListener stops the listener under the selection in the SHELLS
// pane (identified by the ListenerInfo stored on the row). On success it
// returns a command that broadcasts refreshCatcher so the web UI drops it.
func (m *model) stopSelectedListener() tea.Cmd {
	if m.mgr == nil {
		return nil
	}
	p := m.panes[paneShells]
	if len(p.rows) == 0 {
		m.setFlash("no listener selected")
		return nil
	}
	var info catcher.ListenerInfo
	if json.Unmarshal(p.rows[p.sel].raw, &info) != nil || info.ID == "" {
		m.setFlash("could not identify listener")
		return nil
	}
	if err := m.mgr.StopListener(info.ID); err != nil {
		m.setFlash("stop listener failed: " + err.Error())
		return nil
	}
	m.refreshShells()
	m.setFlash(fmt.Sprintf("stopped listener %s:%d", info.IP, info.Port))
	return m.broadcast("refreshCatcher")
}

// shellDelete acts on the selected SHELLS row: a session row is killed, a
// listener row is stopped. Both broadcast refreshCatcher so the web UI follows.
func (m *model) shellDelete() tea.Cmd {
	if m.mgr == nil {
		return nil
	}
	p := m.panes[paneShells]
	if len(p.rows) == 0 {
		m.setFlash("nothing selected")
		return nil
	}
	row := p.rows[p.sel]
	if row.kind == rowSession {
		var info catcher.SessionInfo
		if json.Unmarshal(row.raw, &info) != nil || info.ID == "" {
			m.setFlash("could not identify session")
			return nil
		}
		if err := m.mgr.KillSession(info.ID); err != nil {
			m.setFlash("kill session failed: " + err.Error())
			return nil
		}
		m.refreshShells()
		m.setFlash("killed session " + shortID(info.ID))
		return m.broadcast("refreshCatcher")
	}
	return m.stopSelectedListener()
}

// restartSelectedListener stops the selected listener (or the parent of the
// selected session) and starts a fresh one on the same ip:port, then broadcasts
// refreshCatcher so the web UI re-adopts it.
func (m *model) restartSelectedListener() tea.Cmd {
	if m.mgr == nil {
		return nil
	}
	p := m.panes[paneShells]
	if len(p.rows) == 0 {
		m.setFlash("no listener selected")
		return nil
	}
	row := p.rows[p.sel]
	if row.kind != rowListener {
		m.setFlash("select a listener to restart")
		return nil
	}
	var info catcher.ListenerInfo
	if json.Unmarshal(row.raw, &info) != nil || info.ID == "" {
		m.setFlash("could not identify listener")
		return nil
	}
	if err := m.mgr.StopListener(info.ID); err != nil {
		m.setFlash("restart failed: " + err.Error())
		return nil
	}
	started, err := m.mgr.StartListener(info.IP, info.Port)
	if err != nil {
		m.setFlash("restart failed: " + err.Error())
		m.refreshShells()
		return m.broadcast("refreshCatcher")
	}
	m.refreshShells()
	m.setFlash(fmt.Sprintf("restarted listener on %s:%d", started.IP, started.Port))
	return m.broadcast("refreshCatcher")
}

// attachSelectedSession bridges the operator's terminal to the selected
// reverse-shell session. It returns nil (so callers can fall through to other
// behaviour, e.g. ⏎ toggling detail) when the selection is not a session row.
func (m *model) attachSelectedSession() tea.Cmd {
	if m.mgr == nil || m.active != paneShells {
		return nil
	}
	p := m.panes[paneShells]
	if len(p.rows) == 0 {
		return nil
	}
	row := p.rows[p.sel]
	if row.kind != rowSession {
		return nil
	}
	var info catcher.SessionInfo
	if json.Unmarshal(row.raw, &info) != nil || info.ID == "" {
		m.setFlash("could not identify session")
		return nil
	}
	sess := m.mgr.GetSession(info.ID)
	if sess == nil {
		m.setFlash("session no longer connected")
		return nil
	}
	return tea.Exec(&shellBridge{session: sess}, func(err error) tea.Msg {
		return shellClosedMsg{err: err}
	})
}

// upgradeSelectedSession stabilises the selected reverse-shell session,
// mirroring the web UI's upgrade buttons. The Unix path spawns a PTY via
// python/script; the Windows path pulls ConPtyShell from this server and
// hijacks the socket. Both run before attaching — the operator presses ⏎/i once
// the upgrade has landed. Returns nil so the key handler can fall through when
// the selection is not a session row.
func (m *model) upgradeSelectedSession(windows bool) tea.Cmd {
	if m.mgr == nil || m.active != paneShells {
		return nil
	}
	p := m.panes[paneShells]
	if len(p.rows) == 0 {
		return nil
	}
	row := p.rows[p.sel]
	if row.kind != rowSession {
		m.setFlash("select a session row to upgrade")
		return nil
	}
	var info catcher.SessionInfo
	if json.Unmarshal(row.raw, &info) != nil || info.ID == "" {
		m.setFlash("could not identify session")
		return nil
	}
	sess := m.mgr.GetSession(info.ID)
	if sess == nil {
		m.setFlash("session no longer connected")
		return nil
	}
	// The attached shell gets the whole terminal, so size the PTY to the full
	// dashboard dimensions (with sane fallbacks before the first resize).
	rows, cols := m.height, m.width
	if windows {
		upgradeWindows(sess, m.conPtyURL(sess), rows, cols)
		m.setFlash("sent ConPtyShell upgrade — press ⏎ to attach")
	} else {
		upgradeUnix(sess, rows, cols)
		m.setFlash("sent PTY upgrade — wait a moment, then ⏎ to attach")
	}
	return nil
}

// conPtyURL builds the ConPtyShell download URL for an upgrade. It prefers the
// local address the victim connected to (so it works even when goshs is bound
// to 0.0.0.0), falling back to the configured IP and finally to loopback.
func (m *model) conPtyURL(sess *catcher.Session) string {
	scheme := "http"
	if m.opts.SSL {
		scheme = "https"
	}
	host := sess.LocalIP()
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = m.opts.IP
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s:%d/ConPtyShell.ps1?conpty", scheme, host, m.opts.Port)
}

// parseListenerAddr accepts "ip:port" or a bare "port" and returns the bind IP
// (defaulting to 0.0.0.0) and port.
func parseListenerAddr(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	ip, portStr := "0.0.0.0", s
	if strings.Contains(s, ":") {
		host, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", 0, err
		}
		if host != "" {
			ip = host
		}
		portStr = p
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("port must be a number")
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range")
	}
	return ip, port, nil
}

// --- chat --------------------------------------------------------------------

// tuiAuthor is the display name attached to messages posted from the TUI. The
// web UI lets each browser pick a nickname; the terminal operator has no such
// prompt yet (rich TUI chat is a later phase), so we derive a stable label from
// the host it runs on.
func tuiAuthor() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "tui"
	}
	return "tui@" + host
}

// refreshChat rebuilds the CHAT pane from the shared chat log so it reflects
// messages posted from the web UI as well as the TUI. The pane order matches
// the log order (oldest first), so the selection index maps directly to the
// message slice for delete.
func (m *model) refreshChat() {
	if m.chat == nil {
		return
	}
	p := m.panes[paneChat]
	prevSel := p.sel
	messages, _ := m.chat.GetEntries()
	p.rows = p.rows[:0]
	for _, e := range messages {
		edited := ""
		if e.Edited {
			edited = " (edited)"
		}
		summary := fmt.Sprintf("%s  %s: %s%s", e.Time, e.Author, oneLine(e.Content), edited)
		detail := fmt.Sprintf("From: %s\nTime: %s%s\n\n%s\n", e.Author, e.Time, edited, e.Content)
		raw, _ := json.Marshal(e)
		p.rows = append(p.rows, eventRow{summary: summary, detail: detail, accent: lipgloss.Color(nord7), raw: raw})
	}
	if prevSel < len(p.rows) {
		p.sel = prevSel
	} else if len(p.rows) > 0 {
		p.sel = len(p.rows) - 1
	} else {
		p.sel = 0
	}
}

// beginInput opens the single-line text prompt with a label and a submit
// callback run (with the trimmed buffer) when the operator presses enter.
func (m *model) beginInput(prompt string, submit func(string) tea.Cmd) {
	m.inputActive = true
	m.inputBuf = ""
	m.inputPrompt = prompt
	m.inputSubmit = submit
	m.detail = false
}

// handleInputKey feeds keystrokes into the active text input and dispatches its
// submit callback on enter.
func (m *model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		text := strings.TrimSpace(m.inputBuf)
		submit := m.inputSubmit
		m.inputActive, m.inputBuf, m.inputPrompt, m.inputSubmit = false, "", "", nil
		if text == "" || submit == nil {
			return m, nil
		}
		return m, submit(text)
	case tea.KeyEsc:
		m.inputActive, m.inputBuf, m.inputPrompt, m.inputSubmit = false, "", "", nil
	case tea.KeyBackspace, tea.KeyDelete:
		if r := []rune(m.inputBuf); len(r) > 0 {
			m.inputBuf = string(r[:len(r)-1])
		}
	case tea.KeySpace:
		m.inputBuf += " "
	case tea.KeyRunes:
		m.inputBuf += string(msg.Runes)
	}
	return m, nil
}

// addChatEntry posts a new chat message (authored by the TUI) and broadcasts
// the concrete chatMessage event so web clients append it live.
func (m *model) addChatEntry(text string) tea.Cmd {
	if m.chat == nil {
		return nil
	}
	msg, err := m.chat.AddEntry(tuiAuthor(), text)
	if err != nil {
		m.setFlash("chat post failed: " + err.Error())
		return nil
	}
	m.refreshChat()
	m.setFlash("posted message")
	return m.broadcastPayload(struct {
		Type string `json:"type"`
		chat.Message
	}{Type: "chatMessage", Message: msg})
}

// deleteChatEntry removes the selected message and broadcasts a chatDelete event
// so web clients drop it live.
func (m *model) deleteChatEntry() tea.Cmd {
	if m.chat == nil {
		return nil
	}
	p := m.panes[paneChat]
	if len(p.rows) == 0 {
		return nil
	}
	// The pane and GetEntries share the same order, so the selection index maps
	// to the message slice — but delete is keyed by the stable message ID.
	messages, _ := m.chat.GetEntries()
	if p.sel >= len(messages) {
		return nil
	}
	id := messages[p.sel].ID
	if err := m.chat.DeleteEntry(id); err != nil {
		m.setFlash("chat delete failed: " + err.Error())
		return nil
	}
	m.refreshChat()
	m.setFlash("deleted message")
	return m.broadcastPayload(struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}{Type: "chatDelete", ID: id})
}

// clearChat empties the shared chat log and broadcasts a chatClear event so web
// clients empty their view live.
func (m *model) clearChat() tea.Cmd {
	if m.chat == nil {
		return nil
	}
	if err := m.chat.Clear(); err != nil {
		m.setFlash("chat clear failed: " + err.Error())
		return nil
	}
	m.refreshChat()
	m.setFlash("cleared chat")
	return m.broadcastPayload(struct {
		Type string `json:"type"`
	}{Type: "chatClear"})
}

// broadcast notifies web clients (and our own subscription) of a state change
// of the given type (e.g. "refreshCatcher") so they re-fetch. The send runs in
// a command so it never blocks the UI loop on the unbuffered Broadcast channel.
func (m *model) broadcast(typ string) tea.Cmd {
	return m.broadcastPayload(struct {
		Type string `json:"type"`
	}{Type: typ})
}

// broadcastPayload marshals an arbitrary event and sends it to the hub in a
// command so it never blocks the UI loop on the unbuffered Broadcast channel.
func (m *model) broadcastPayload(v any) tea.Cmd {
	if m.hub == nil {
		return nil
	}
	msg, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return func() tea.Msg {
		m.hub.Broadcast <- msg
		return nil
	}
}

// --- export -----------------------------------------------------------------

// exportPane writes a single pane's events to goshs-<proto>-log.json — a bare
// JSON array of the raw events, matching the web UI's per-tab export
// (exportHTTP/exportDNS/… in collab.js).
func (m *model) exportPane(idx int) {
	p := m.panes[idx]
	events := rawEvents(p)
	if len(events) == 0 {
		m.setFlash("nothing to export")
		return
	}
	name := fmt.Sprintf("goshs-%s-log.json", strings.ToLower(p.name))
	path, err := writeJSONExport(name, events)
	if err != nil {
		m.setFlash("export failed: " + err.Error())
		return
	}
	m.setFlash(fmt.Sprintf("exported %d %s event(s) → %s", len(events), p.name, path))
}

// exportAll writes goshs-all-logs.json — the same wrapper object the web UI's
// exportAllLogs() produces: {generatedAt, http, dns, smtp, smb, ldap}. As in
// the web UI the SHELLS pane is not part of the combined export (use its
// per-pane export for that).
func (m *model) exportAll() {
	all := struct {
		GeneratedAt string            `json:"generatedAt"`
		HTTP        []json.RawMessage `json:"http"`
		DNS         []json.RawMessage `json:"dns"`
		SMTP        []json.RawMessage `json:"smtp"`
		SMB         []json.RawMessage `json:"smb"`
		LDAP        []json.RawMessage `json:"ldap"`
	}{
		GeneratedAt: time.Now().Format(time.RFC3339),
		HTTP:        rawEvents(m.panes[paneHTTP]),
		DNS:         rawEvents(m.panes[paneDNS]),
		SMTP:        rawEvents(m.panes[paneSMTP]),
		SMB:         rawEvents(m.panes[paneSMB]),
		LDAP:        rawEvents(m.panes[paneLDAP]),
	}
	total := len(all.HTTP) + len(all.DNS) + len(all.SMTP) + len(all.SMB) + len(all.LDAP)
	if total == 0 {
		m.setFlash("nothing to export")
		return
	}
	path, err := writeJSONExport("goshs-all-logs.json", all)
	if err != nil {
		m.setFlash("export failed: " + err.Error())
		return
	}
	m.setFlash(fmt.Sprintf("exported %d event(s) → %s", total, path))
}

// rawEvents collects a pane's stored raw event JSON in on-screen order (newest
// first), skipping any rows without a raw payload.
func rawEvents(p *pane) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(p.rows))
	for _, r := range p.rows {
		if len(r.raw) > 0 {
			out = append(out, r.raw)
		}
	}
	return out
}

// writeJSONExport marshals v to pretty-printed JSON (2-space indent, matching
// the web UI's JSON.stringify(…, null, 2)) and writes it to name in the working
// directory, returning the absolute path.
func writeJSONExport(name string, v any) (string, error) {
	// Marshal compactly first, then re-indent so embedded json.RawMessage event
	// objects are expanded too while preserving their original key order.
	compact, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		return "", err
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// setFlash shows a transient status message for a few seconds; the tick handler
// clears it once flashExpiry passes.
func (m *model) setFlash(msg string) {
	m.flash = msg
	m.flashExpiry = time.Now().Add(4 * time.Second)
}

// copyToClipboard writes text to the operator's clipboard by two complementary
// paths, because neither works everywhere:
//
//   - nativeCopy shells out to a local clipboard tool (xclip/xsel/wl-copy/
//     pbcopy/clip). This is the path that works when goshs runs on the same
//     machine as the terminal — many local emulators (gnome-terminal, konsole,
//     plain xterm) do NOT honour OSC 52, so the escape sequence alone copies
//     nothing there.
//   - An OSC 52 escape sequence staged on the next render (see View). This is
//     the path that works when the TUI is driven over SSH/tmux on a target box
//     with no local display: the operator's terminal emulator receives the
//     sequence and updates their real clipboard.
//
// Doing both covers local and remote operation; each is a no-op where it does
// not apply. Support is still best-effort, so the flash says "copied" even
// though we cannot read the clipboard back to confirm.
func (m *model) copyToClipboard(text, label string) {
	// nativeCopy already fills both the CLIPBOARD and PRIMARY selections locally.
	nativeCopy(text)
	// For the OSC 52 path (the one that reaches the operator over SSH), emit the
	// system CLIPBOARD ('c') sequence and, right after it, the X11 PRIMARY ('p')
	// sequence — so middle-click / Shift+Insert paste also works remotely, not
	// just Ctrl+V. Concatenated into a single clipSeq so View() flushes them
	// together on one frame.
	m.clipSeq = osc52Seq(text, osc52.SystemClipboard) + osc52Seq(text, osc52.PrimaryClipboard)
	m.setFlash(label)
}

// nativeCopy best-effort writes text to the operator's OS clipboard by shelling
// out to a platform clipboard tool. On X11/Wayland it fills BOTH the CLIPBOARD
// selection (Ctrl+V) and the PRIMARY selection (middle-click / Shift+Insert), so
// a paste works regardless of which convention the operator uses; unlike OSC 52,
// these are independent processes writing straight to the display server, so
// there is no two-sequences-break-each-other problem. On Linux/BSD it only runs
// when a local display is present (DISPLAY / WAYLAND_DISPLAY), so it stays a
// no-op over a plain SSH session where the OSC 52 path in copyToClipboard is what
// reaches the operator instead. Returns false when no suitable tool/display is
// available or every command failed.
func nativeCopy(text string) bool {
	// Each entry is a command + args; multiple entries target multiple
	// selections (e.g. clipboard + primary on X11).
	var cmds [][]string
	switch runtime.GOOS {
	case "darwin":
		cmds = [][]string{{"pbcopy"}} // macOS has a single clipboard
	case "windows":
		cmds = [][]string{{"clip"}} // Windows has a single clipboard
	default: // linux, *bsd
		switch {
		case os.Getenv("WAYLAND_DISPLAY") != "":
			if _, err := exec.LookPath("wl-copy"); err == nil {
				cmds = [][]string{{"wl-copy"}, {"wl-copy", "--primary"}}
			}
		case os.Getenv("DISPLAY") != "":
			if _, err := exec.LookPath("xclip"); err == nil {
				cmds = [][]string{
					{"xclip", "-selection", "clipboard"},
					{"xclip", "-selection", "primary"},
				}
			} else if _, err := exec.LookPath("xsel"); err == nil {
				cmds = [][]string{
					{"xsel", "--clipboard", "--input"},
					{"xsel", "--primary", "--input"},
				}
			}
		}
	}
	ok := false
	for _, c := range cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if cmd.Run() == nil {
			ok = true
		}
	}
	return ok
}

// osc52Seq builds a single OSC 52 copy sequence for the given clipboard buffer.
//
// Under GNU screen it wraps the sequence in screen's DCS passthrough so it
// reaches the outer terminal (screen passes DCS through permissively).
//
// Under tmux it does NOT wrap. tmux's own DCS-passthrough (osc52.Tmux()) requires
// `allow-passthrough on`, which is off by default and security-gated; relying on
// it left copies silently dropped for operators who had the far more common
// `set-clipboard on` set instead. So we emit a plain OSC 52 and let tmux forward
// it: with `set-clipboard on` tmux intercepts the app's sequence, sets its buffer
// and relays it to the outer terminal. (tmux's default `set-clipboard external`
// blocks in-pane apps, so `set-clipboard on` is the documented requirement.)
func osc52Seq(text string, buf osc52.Clipboard) string {
	seq := osc52.New(text).Clipboard(buf)
	if strings.HasPrefix(os.Getenv("TERM"), "screen") && os.Getenv("TMUX") == "" {
		seq = seq.Screen()
	}
	return seq.String()
}

// --- view -------------------------------------------------------------------

// Nord palette (https://www.nordtheme.com) — the same theme the web UI uses,
// so the TUI and browser dashboards share a look.
const (
	nord0  = "#2E3440" // polar night (background)
	nord1  = "#3B4252" // status-bar background
	nord3  = "#4C566A" // muted / dim
	nord4  = "#D8DEE9" // snow storm (foreground)
	nord6  = "#ECEFF4" // brightest foreground
	nord7  = "#8FBCBB" // frost (clipboard)
	nord8  = "#88C0D0" // frost (primary accent)
	nord9  = "#81A1C1" // frost (3xx / ldap)
	nord11 = "#BF616A" // aurora red (errors / shells)
	nord13 = "#EBCB8B" // aurora yellow (smtp)
	nord14 = "#A3BE8C" // aurora green (2xx)
	nord15 = "#B48EAD" // aurora purple (smb)
)

var (
	bannerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord8))
	bannerSubtle  = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))
	tabActive     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord0)).Background(lipgloss.Color(nord8)).Padding(0, 1)
	tabInactive   = lipgloss.NewStyle().Foreground(lipgloss.Color(nord4)).Background(lipgloss.Color(nord1)).Padding(0, 1)
	tabFiller     = lipgloss.NewStyle().Background(lipgloss.Color(nord1))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord0)).Background(lipgloss.Color(nord8))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord8))
	statusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color(nord4)).Background(lipgloss.Color(nord1))
	controlsStyle = lipgloss.NewStyle().Foreground(lipgloss.Color(nord6)).Background(lipgloss.Color(nord3))
	flashStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord0)).Background(lipgloss.Color(nord14))
	inputStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord0)).Background(lipgloss.Color(nord13))
	scrollThumb   = lipgloss.NewStyle().Foreground(lipgloss.Color(nord8))
	scrollTrack   = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))

	// Password reveal popup.
	popupBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(nord8)).Background(lipgloss.Color(nord1)).Foreground(lipgloss.Color(nord4)).Padding(1, 3)
	popupTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord8))
	popupLabel = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))
	popupValue = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(nord6))
	popupMask  = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))
	popupWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color(nord13))
	popupHint  = lipgloss.NewStyle().Foreground(lipgloss.Color(nord3))
)

// bannerArt is the goshs figlet logo, mirroring logger.PrintBanner so the
// dashboard greets the operator with the same brand mark as the CLI.
var bannerArt = []string{
	`  __ _  ___  ___| |__  ___ `,
	` / _` + "`" + ` |/ _ \/ __| '_ \/ __|`,
	`| (_| | (_) \__ \ | | \__ \`,
	` \__, |\___/|___/_| |_|___/`,
	`  __/ |`,
	` |___/`,
}

// --- generator --------------------------------------------------------------

// handleGeneratorKey processes keys specific to the GENERATOR pane and reports
// whether it consumed the event. Unhandled keys (tab/shift+tab, q, E, ...)
// return handled=false so the shared handler still drives pane switching,
// quitting and export-all.
func (m *model) handleGeneratorKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "up", "k":
		if m.genSel > 0 {
			m.genSel--
		}
	case "down", "j":
		if m.genSel < len(shellDB)-1 {
			m.genSel++
		}
	case "home", "g":
		m.genSel = 0
	case "end", "G":
		m.genSel = len(shellDB) - 1
	case "i":
		m.beginInput("set LHOST", func(text string) tea.Cmd {
			if text != "" {
				m.genIP = text
			}
			return nil
		})
	case "p":
		m.beginInput("set LPORT", func(text string) tea.Cmd {
			if text != "" {
				m.genPort = text
			}
			return nil
		})
	case "n":
		m.genEnc = m.genEnc.next()
	case "y", "c":
		// Copy the filled command to the operator's clipboard via OSC 52.
		m.copyToClipboard(generateCommand(shellDB[m.genSel].tmpl, m.genIP, m.genPort, m.genEnc), "copied command to clipboard")
	case "enter", "e":
		// The form has no detail view and no per-pane log to export; swallow
		// these so ⏎ does not toggle detail and e does not write an empty file.
	default:
		return nil, false
	}
	return nil, true
}

// generatorView renders the GENERATOR pane: a selectable payload list on top
// and the editable LHOST/LPORT/encoding fields plus the filled command and
// listener line below, in exactly h lines. The two are stacked (not columned)
// so the output rows span the full width and can be cleanly mouse-selected
// without the terminal's rectangular selection also grabbing the payload list.
func (m *model) generatorView(h int) string {
	if len(shellDB) == 0 {
		return padLines(nil, h)
	}
	// Cap the list height so the output (long PowerShell payloads especially)
	// gets the bulk of the pane; the list windows around the selection so a
	// short height just scrolls.
	listH := h / 2
	if listH > 10 {
		listH = 10
	}
	if listH < 3 {
		listH = 3
	}
	sepH := 1
	outH := h - listH - sepH
	if outH < 1 {
		// Pane too short to stack; give everything to the list.
		return m.generatorList(m.width, h)
	}
	list := m.generatorList(m.width, listH)
	out := m.generatorOutput(m.width, outH)
	return lipgloss.JoinVertical(lipgloss.Left, list, sepRow(m.width), out)
}

// generatorList renders the scrollable list of payload names, windowed so the
// selected entry stays visible, as exactly h lines of width w.
func (m *model) generatorList(w, h int) string {
	top := 0
	if m.genSel >= h {
		top = m.genSel - h + 1
	}
	end := top + h
	if end > len(shellDB) {
		end = len(shellDB)
	}
	var lines []string
	for i := top; i < end; i++ {
		marker, st := "  ", lipgloss.NewStyle().Foreground(lipgloss.Color(nord4))
		if i == m.genSel {
			marker, st = "▶ ", selectedStyle
		}
		lines = append(lines, st.Width(w).Render(trunc(marker+shellDB[i].name, w)))
	}
	blank := lipgloss.NewStyle().Width(w).Render("")
	for len(lines) < h {
		lines = append(lines, blank)
	}
	return strings.Join(lines, "\n")
}

// generatorOutput renders the right-hand panel: the LHOST/LPORT/encoding fields,
// the selected payload's name, the filled command (hard-wrapped), and the
// matching listener command, as exactly h lines of width w.
func (m *model) generatorOutput(w, h int) string {
	e := shellDB[m.genSel]
	cmd := generateCommand(e.tmpl, m.genIP, m.genPort, m.genEnc)

	field := func(k, v string) string { return dimStyle.Render(padRight(k, 7)) + trunc(v, w-7) }
	enc := m.genEnc.String()
	if strings.HasPrefix(e.tmpl, psB64Prefix) {
		enc = "powershell -e (encoding ignored)"
	}

	lines := []string{
		field("LHOST", m.genIP),
		field("LPORT", m.genPort),
		field("ENC", enc),
		"",
		titleStyle.Render(trunc("⚡ "+e.name, w)),
		"",
	}
	lines = append(lines, strings.Split(hardWrap(cmd, w), "\n")...)
	lines = append(lines, "", dimStyle.Render(trunc("Listener: nc -lvnp "+m.genPort, w)))
	return padLines(lines, h)
}

// sepRow renders a 1-line horizontal divider w columns wide.
func sepRow(w int) string {
	if w < 1 {
		w = 1
	}
	return dimStyle.Render(strings.Repeat("─", w))
}

func (m *model) View() string {
	if m.width == 0 || m.height == 0 {
		return "starting goshs dashboard..."
	}
	banner := m.banner()
	tabs := m.tabs()
	status := m.statusBar()
	chrome := lipgloss.Height(banner) + lipgloss.Height(tabs) + lipgloss.Height(status)
	bodyH := m.height - chrome
	if bodyH < 1 {
		bodyH = 1
	}
	body := m.bodyView(bodyH)
	// The password popup is drawn as an overlay centered in the body region,
	// leaving the banner/tabs/status chrome in place around it.
	if m.showPassword {
		body = lipgloss.Place(m.width, bodyH, lipgloss.Center, lipgloss.Center, m.passwordPopup())
	}
	frame := strings.Join([]string{banner, tabs, body, status}, "\n")
	// Flush a pending clipboard copy by appending its OSC 52 sequence to the
	// frame exactly once. OSC 52 does not move the cursor or occupy cells, so it
	// is invisible in the rendered output; embedding it in the frame is the
	// race-free way to reach the terminal under Bubble Tea v1 (which, unlike v2,
	// has no SetClipboard). Cleared here so it is emitted a single time.
	if m.clipSeq != "" {
		frame += m.clipSeq
		m.clipSeq = ""
	}
	return frame
}

// banner renders the goshs logo at the top. On short terminals it collapses to
// a single line so the event body keeps as much room as possible.
func (m *model) banner() string {
	if m.height < 18 || m.width < 30 {
		return bannerStyle.Render("goshs ") + bannerSubtle.Render(goshsversion.GoshsVersion)
	}
	var b strings.Builder
	for i, ln := range bannerArt {
		b.WriteString(bannerStyle.Render(ln))
		if i == len(bannerArt)-1 {
			b.WriteString(bannerSubtle.Render("   " + goshsversion.GoshsVersion))
		} else {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (m *model) tabs() string {
	var cells []string
	for i, p := range m.panes {
		// The GENERATOR pane is a form, not an event log, so it carries no count.
		label := fmt.Sprintf("%s %s(%d)", p.icon, p.name, len(p.rows))
		if i == paneGenerator {
			label = fmt.Sprintf("%s %s", p.icon, p.name)
		}
		if i == m.active {
			cells = append(cells, tabActive.Render(label))
		} else {
			cells = append(cells, tabInactive.Render(label))
		}
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
	// Extend the bar to the full terminal width so it reads as a solid strip
	// rather than cutting off after the last tab.
	if pad := m.width - lipgloss.Width(row); pad > 0 {
		row += tabFiller.Render(strings.Repeat(" ", pad))
	}
	return row
}

// statusBar renders the bottom chrome: a wrapping info bar of server facts and
// a context-sensitive controls line, both filling the terminal width.
func (m *model) statusBar() string {
	info := statusStyle.Width(m.width).Render(strings.Join(m.statusSegments(), "   "))
	// The controls line is taken over by the add-entry prompt while typing, or
	// by a transient flash (e.g. an export result), so the operator sees the
	// current mode/outcome without leaving the view.
	line, style := m.controlsHint(), controlsStyle
	switch {
	case m.inputActive:
		line, style = m.inputPrompt+" (enter save · esc cancel): "+m.inputBuf+"▌", inputStyle
	case m.flash != "":
		line, style = m.flash, flashStyle
	}
	controls := style.Width(m.width).Render(trunc(line, m.width))
	return info + "\n" + controls
}

// statusSegments collects the server facts shown in the status bar. Most come
// straight from the parsed options; the tunnel URL is read live via the
// tunnelURL getter since it is assigned asynchronously once the tunnel is up.
func (m *model) statusSegments() []string {
	o := m.opts
	scheme := "http"
	if o.SSL {
		scheme = "https"
	}
	var seg []string
	add := func(s string) { seg = append(seg, s) }

	add("🏷 " + goshsversion.GoshsVersion)
	// If o.IP is '0.0.0.0', resolve to all ip addresses and show all, sort by interface name
	if o.IP == "0.0.0.0" {
		interfaceAdresses, err := utils.GetAllIPAddresses()
		if err != nil {
			logger.Errorf("There has been an error fetching the interface addresses: %+v\n", err)
		}
		// Sort interface addresses by interface name
		keys := make([]string, 0, len(interfaceAdresses))
		for k := range interfaceAdresses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := interfaceAdresses[k]
			add(fmt.Sprintf("🔗 %s://%s:%d (%s)", scheme, v, o.Port, k))
		}
	} else {
		add(fmt.Sprintf("🔗 %s://%s:%d", scheme, o.IP, o.Port))
	}
	add("📁 " + o.Webroot)
	if o.UploadFolder != "" && o.UploadFolder != o.Webroot {
		add("📥 " + o.UploadFolder)
	}
	if !m.deadline.IsZero() {
		add("⏳ ttl " + remaining(m.deadline))
	}

	if o.Username != "" {
		add("🔒 auth " + o.Username)
	} else if o.BasicAuth != "" || o.CertAuth != "" {
		add("🔒 auth on")
	}
	if o.DropUser != "" {
		add("👤 " + o.DropUser)
	}

	var flags []string
	if o.ReadOnly {
		flags = append(flags, "read-only")
	}
	if o.UploadOnly {
		flags = append(flags, "upload-only")
	}
	if o.NoDelete {
		flags = append(flags, "no-delete")
	}
	if len(flags) > 0 {
		add("🚫 " + strings.Join(flags, ","))
	}

	if o.WebDav {
		add(fmt.Sprintf("🗂 webdav :%d", o.WebDavPort))
	}
	if o.CLI {
		add("⌨ cli")
	}
	if o.Tunnel {
		if url := m.tunnel(); url != "" {
			add("🌍 " + url)
		} else {
			add("🌍 tunnel (connecting)")
		}
	}
	if o.DNS {
		add(fmt.Sprintf("📡 dns :%d", o.DNSPort))
	}
	if o.SMTP {
		add(fmt.Sprintf("📨 smtp :%d", o.SMTPPort))
	}
	if o.SMB {
		s := fmt.Sprintf("🔑 smb :%d", o.SMBPort)
		if o.SMBDomain != "" || o.SMBShare != "" {
			s += fmt.Sprintf(" %s\\%s", o.SMBDomain, o.SMBShare)
		}
		add(s)
	}
	if o.LDAP {
		add(fmt.Sprintf("📇 ldap :%d", o.LDAPPort))
	}
	if o.FTP {
		if o.FTPSFTPMode {
			add(fmt.Sprintf("📂 sftp :%d", o.FTPPort))
		} else {
			add(fmt.Sprintf("📂 ftp :%d", o.FTPPort))
		}
	}
	if o.TFTP {
		add(fmt.Sprintf("📦 tftp :%d", o.TFTPPort))
	}
	if o.Catcher {
		add("🐚 catcher")
	}
	if o.Template {
		tpl := "🧩 tpl"
		// Mirror the server's LHOST resolution: explicit --tpl-var wins, else the
		// bound single IP, else unset (templates using {{.LHOST}} will error).
		lhost := o.TemplateVarsParsed["LHOST"]
		if lhost == "" && o.IP != "" && o.IP != "0.0.0.0" {
			lhost = o.IP
		}
		if lhost != "" {
			tpl += " LHOST=" + lhost
		}
		// Show every other --tpl-var (LPORT and any arbitrary KEY=VALUE) so the
		// status line reflects the full template context, not just LHOST. LHOST is
		// handled above (it has extra IP-derivation logic), so skip it here.
		keys := make([]string, 0, len(o.TemplateVarsParsed))
		for k := range o.TemplateVarsParsed {
			if k == "LHOST" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			tpl += fmt.Sprintf(" %s=%s", k, o.TemplateVarsParsed[k])
		}
		add(tpl)
	}
	return seg
}

// tunnel returns the current public tunnel URL, or "" when no getter was
// supplied (e.g. in tests) or the tunnel has not connected yet.
func (m *model) tunnel() string {
	if m.tunnelURL == nil {
		return ""
	}
	return m.tunnelURL()
}

// passwordPopup renders the modal box shown over the body when 'p' is pressed.
// The password is masked with dots until the operator presses 'u'. A bcrypt
// hash (from -b with a pre-hashed secret) is flagged since it cannot be undone
// to the plaintext.
func (m *model) passwordPopup() string {
	o := m.opts
	user := o.Username
	if user == "" {
		user = "(none)"
	}

	hashed := strings.Contains(o.Password, "$2a$") || strings.Contains(o.Password, "$2b$") || strings.Contains(o.Password, "$2y$")

	var pwLine string
	if m.passwordSeen {
		pwLine = popupValue.Render(o.Password)
	} else {
		n := len([]rune(o.Password))
		if n > 32 {
			n = 32 // cap the mask so a long bcrypt hash does not blow out the box
		}
		pwLine = popupMask.Render(strings.Repeat("•", n))
	}

	var b strings.Builder
	b.WriteString(popupTitle.Render("🔒 Basic Auth Credentials"))
	b.WriteString("\n\n")
	b.WriteString(popupLabel.Render("User:     ") + popupValue.Render(user))
	b.WriteString("\n")
	b.WriteString(popupLabel.Render("Password: ") + pwLine)
	if hashed {
		b.WriteString("\n")
		b.WriteString(popupWarn.Render("stored as a bcrypt hash — plaintext unknown"))
	}
	b.WriteString("\n\n")
	b.WriteString(popupHint.Render("u show/hide · y copy · esc close"))

	return popupBox.Render(b.String())
}

func (m *model) controlsHint() string {
	if m.detail {
		switch m.active {
		case paneSMTP:
			return "↑↓ event · PgUp/PgDn scroll · s save attachments · e/E export · esc close · q quit"
		case paneShells:
			return "↑↓ row · ⏎/i attach · u/U upgrade · a start · r restart · d stop/kill · esc close · q quit"
		}
		return "↑↓ event · PgUp/PgDn scroll · g/G newest/oldest · e/E export · esc close · q quit"
	}
	// The GENERATOR pane owns 'p' (LPORT), so it never advertises the password
	// popup; every other pane appends "p pass" when basic-auth is configured.
	if m.active == paneGenerator {
		return "⇄ Tab/←→ panes · ↑↓ shell · i LHOST · p LPORT · n encoding · y/c copy · q quit"
	}
	var hint string
	switch m.active {
	case paneChat:
		hint = "⇄ Tab/←→ panes · ↑↓ scroll · ⏎ view · a post · d delete · C clear · q quit"
	case paneShells:
		hint = "⇄ Tab/←→ panes · ↑↓ select · ⏎/i attach · u/U upgrade · a start · r restart · d stop/kill · q quit"
	case paneSMTP:
		hint = "⇄ Tab/←→ panes · ↑↓ scroll · ⏎ detail · s save attachments · e/E export · q quit"
	default:
		hint = "⇄ Tab/←→ panes · ↑↓ scroll · ⏎ detail · g/G top/bottom · e/E export · q quit"
	}
	if m.opts.Password != "" {
		hint += " · p pass"
	}
	return hint
}

// bodyView renders exactly h lines for the active pane so the status bar stays
// pinned to the bottom of the screen. The list view gets a vertical scrollbar
// in the rightmost column whenever the events overflow the viewport.
func (m *model) bodyView(h int) string {
	if m.active == paneGenerator {
		return m.generatorView(h)
	}
	p := m.panes[m.active]
	if m.detail {
		return m.detailView(p, h)
	}
	if len(p.rows) == 0 {
		return padLines([]string{dimStyle.Render("  (no events yet)")}, h)
	}

	// Keep the selected row within the visible window.
	if p.sel < p.top {
		p.top = p.sel
	}
	if p.sel >= p.top+h {
		p.top = p.sel - h + 1
	}
	if p.top < 0 {
		p.top = 0
	}

	bar := scrollColumn(len(p.rows), p.top, h)
	contentW := m.width
	if bar != nil {
		contentW = m.width - 1
	}
	if contentW < 1 {
		contentW = 1
	}

	end := p.top + h
	if end > len(p.rows) {
		end = len(p.rows)
	}
	var lines []string
	for i := p.top; i < end; i++ {
		line := trunc(p.rows[i].summary, contentW)
		st := lipgloss.NewStyle().Foreground(p.rows[i].accent)
		if i == p.sel {
			st = selectedStyle
		}
		lines = append(lines, st.Width(contentW).Render(line))
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", contentW))
	}
	if bar != nil {
		for i := range lines {
			lines[i] += scrollCell(bar, i)
		}
	}
	return strings.Join(lines, "\n")
}

// scrollColumn returns a per-row mask marking where the scrollbar thumb sits,
// or nil when all content fits (total <= viewH) and no bar is needed.
func scrollColumn(total, top, viewH int) []bool {
	if viewH <= 0 || total <= viewH {
		return nil
	}
	mask := make([]bool, viewH)
	thumb := viewH * viewH / total
	if thumb < 1 {
		thumb = 1
	}
	pos := 0
	if maxTop := total - viewH; maxTop > 0 {
		pos = (viewH - thumb) * top / maxTop
	}
	for i := 0; i < thumb && pos+i < viewH; i++ {
		mask[pos+i] = true
	}
	return mask
}

// scrollCell renders one cell of the scrollbar track for row i.
func scrollCell(bar []bool, i int) string {
	if i < len(bar) && bar[i] {
		return scrollThumb.Render("█")
	}
	return scrollTrack.Render("│")
}

// padLines pads (or clips) a slice of rendered lines to exactly h lines and
// joins them, so a section fills its reserved height.
func padLines(lines []string, h int) string {
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

// padRight pads a plain (ANSI-free) string with spaces to w display columns.
func padRight(s string, w int) string {
	if n := len([]rune(s)); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// detailView renders the inspected event in exactly h lines: a title line
// (with a position badge) plus a scrollable, hard-wrapped body. The badge
// surfaces that newer events have arrived while the operator was reading this
// one — rows are newest-first, so any row above the selection (index < p.sel)
// is newer. The count ticks up live as traffic comes in even though the
// inspected event stays anchored; ↑ (or home/g) jumps to them.
func (m *model) detailView(p *pane, h int) string {
	if p.sel >= len(p.rows) {
		return padLines(nil, h)
	}
	badge := fmt.Sprintf("%d/%d", p.sel+1, len(p.rows))
	if p.sel > 0 {
		badge += fmt.Sprintf(" · ↑ %d newer", p.sel)
	}
	title := titleStyle.Render(fmt.Sprintf("%s %s detail  %s", p.icon, p.name, badge))

	width := m.width - 1 // reserve the rightmost column for the scrollbar
	if width < 1 {
		width = 1
	}
	body := strings.Split(hardWrap(p.rows[p.sel].detail, width), "\n")

	bodyH := h - 1 // title consumes one line
	if bodyH < 1 {
		bodyH = 1
	}
	m.detailH = bodyH

	// Clamp the scroll offset to the content and write it back so the paging
	// keys stay bounded across renders.
	maxTop := len(body) - bodyH
	if maxTop < 0 {
		maxTop = 0
	}
	if p.detailTop > maxTop {
		p.detailTop = maxTop
	}
	if p.detailTop < 0 {
		p.detailTop = 0
	}

	bar := scrollColumn(len(body), p.detailTop, bodyH)
	end := p.detailTop + bodyH
	if end > len(body) {
		end = len(body)
	}
	lines := []string{title}
	for i := p.detailTop; i < end; i++ {
		ln := body[i]
		if bar != nil {
			ln = padRight(ln, width) + scrollCell(bar, i-p.detailTop)
		}
		lines = append(lines, ln)
	}
	return padLines(lines, h)
}

// hardWrap re-flows a detail body so no rendered line exceeds width. Unlike
// word wrapping it also breaks single long tokens (e.g. a captured NTLM hash,
// which contains no spaces) so they no longer run off the right edge.
func hardWrap(s string, width int) string {
	var out strings.Builder
	lines := strings.Split(s, "\n")
	for li, line := range lines {
		if li > 0 {
			out.WriteByte('\n')
		}
		for len([]rune(line)) > width {
			r := []rune(line)
			out.WriteString(string(r[:width]))
			out.WriteByte('\n')
			line = string(r[width:])
		}
		out.WriteString(line)
	}
	return out.String()
}

// --- helpers ----------------------------------------------------------------

// tstamp formats an event time for the one-line summaries. It includes the
// full date (year as well) plus the time so that, on long-running instances,
// events from previous days or years remain distinguishable at a glance.
func tstamp(t time.Time) string { return t.Format("2006-01-02 15:04:05") }

func host(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// oneLine collapses newlines and tabs to spaces so multi-line content (e.g. a
// chat message) fits on a single summary row.
func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t'
	}), " ")
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func remaining(deadline time.Time) string {
	d := time.Until(deadline).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}

func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n == 1 {
		return string(r[:1])
	}
	return string(r[:n-1]) + "…"
}
