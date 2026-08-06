package httpserver

import (
	"html/template"
	"net/http"

	"goshs.de/goshs/v2/logger"
)

// UIData is the struct passed to index.html on every page render.
// Map your existing FileServer fields onto this when calling renderIndex.
type UIData struct {
	// Meta
	GoshsVersion string

	// Current path
	AbsPath         string
	BreadcrumbParts []BreadcrumbPart
	Subdirectory    bool
	QRCode          string
	SharedLinks     map[string]SharedLink

	// Feature flags (controls which tabs/buttons appear)
	ReadOnly   bool
	UploadOnly bool
	NoChat     bool
	NoDelete   bool
	CLI        bool
	Embedded   bool
	Catcher    bool
	// ChatUpload is true when chat file upload is available (chat enabled and
	// the file server is not read-only). Drives the composer's upload button.
	ChatUpload bool
	// PersistChatImages is true when pasted images should be uploaded to disk
	// and linked, instead of inlined as base64 data URLs.
	PersistChatImages bool

	// File listing
	Items []FileItem

	// Embedded files
	EmbeddedItems []FileItem

	// Chat messages (pre-loaded from server state, oldest first)
	Chat []ChatMessage

	// CSRF token embedded into the page for JS to read
	CSRFToken string

	// MaxUpload is the server-enforced upload limit in bytes (0 = unlimited).
	// Embedded into the page so JS can show a human-readable error on 413.
	MaxUpload int64

	// TTLDeadlineUnixMs is the self-destruct moment in Unix milliseconds, or 0
	// when --ttl is unset. JS uses it to render a live countdown.
	TTLDeadlineUnixMs int64
}

// BreadcrumbPart is a single segment of the path breadcrumb.
type BreadcrumbPart struct {
	Name string
	Path string
}

// FileItem represents one row in the file listing table.
type FileItem struct {
	RelPath    string
	Name       string
	IsDir      bool
	Size       string // human-readable, e.g. "1.4 MB"
	SizeRaw    int64  // bytes, used for JS sorting
	LastMod    string // formatted date string
	LastModRaw int64  // unix timestamp, used for JS sorting
	Extension  string // lowercase with dot, e.g. ".go"
	QRCode     string
	Auth       bool
}

// ChatMessage is a single chat message rendered server-side.
type ChatMessage struct {
	ID      int
	Author  string
	Content string
	Time    string
	Edited  bool
	// ReactionsJSON is the reactions map marshalled to JSON (or "" when there
	// are none). It is emitted into a data-reactions attribute for chat.js to
	// parse and render, mirroring how the body carries data-raw.
	ReactionsJSON string
}

// renderIndex parses and executes the embedded index.html template.
func renderIndex(w http.ResponseWriter, data UIData) error {
	tmpl, err := template.New("index.html").
		Funcs(template.FuncMap{
			// {{if not .Flag}} helper — Go templates don't have "not" built-in
			"not": func(b bool) bool { return !b },
			"sub": func(a, b int) int { return a - b },
			"percent": func(used, total int) int {
				if total <= 0 {
					return 0
				}
				p := used * 100 / total
				if p > 100 {
					return 100
				}
				return p
			},
		}).
		ParseFS(static, "static/templates/index.html")
	if err != nil {
		logger.Errorf("parsing index.html: %+v", err)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		logger.Errorf("executing index.html: %+v", err)
	}

	return err
}
