package httpserver

import (
	"html/template"
	"net"
	"net/http"
	"sync"
	"time"

	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/chat"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
)

type baseTemplate struct {
	Chat            *chat.Chat
	GoshsVersion    string
	Directory       *directory
	EmbeddedContent *directory
	CLI             bool
	Embedded        bool
	NoChat          bool
	NoDelete        bool
	SharedLinks     map[string]SharedLink
	ReadOnly        bool
}

type directory struct {
	RelPath        string
	AbsPath        string
	IsSubdirectory bool
	Back           string
	Content        []item
	AuthEnabled    bool
}

type item struct {
	URI                 string       `json:"-"`
	QRCode              template.URL `json:"-"`
	Name                string       `json:"name"`
	IsDir               bool         `json:"is_dir"`
	IsSymlink           bool         `json:"is_symlink"`
	SymlinkTarget       string       `json:"symlink_target"`
	Ext                 string       `json:"extension"`
	DisplaySize         string       `json:"-"`
	SortSize            int64        `json:"size_bytes"`
	DisplayLastModified string       `json:"-"`
	SortLastModified    int64        `json:"last_modified"`
	ReadOnly            bool
	NoDelete            bool
	AuthEnabled         bool
}

// FileServer holds the fileserver information
type FileServer struct {
	IP                string
	Port              int
	CLI               bool
	WebdavPort        int
	Webroot           string
	UploadFolder      string
	SSL               bool
	SelfSigned        bool
	LetsEncrypt       bool
	MyKey             string
	MyCert            string
	MyP12             string
	P12NoPass         bool
	User              string
	Pass              string
	CACert            string
	DropUser          string
	Version           string
	Fingerprint256    string
	Fingerprint1      string
	UploadOnly        bool
	ReadOnly          bool
	NoChat            bool
	PersistChat       bool
	PersistChatImages bool
	NoDelete          bool
	Silent            bool
	Invisible         bool
	Embedded          bool
	Verbose           bool
	Webhook           webhook.Webhook
	Hub               *ws.Hub
	Chat              *chat.Chat
	Whitelist         *Whitelist
	MaxUpload         int64
	SharedLinks       map[string]SharedLink
	Tunnel            bool
	TunnelURL         string
	Options           *options.Options
	CatcherMgr        *catcher.Manager
	CSRFToken         string
	TTLDeadline       time.Time            // self-destruct moment; zero when --ttl is unset
	authCache         map[string]time.Time // expiry time per verified credential
	authCacheMu       sync.RWMutex
	authFailures      map[string]*authFailEntry
	authFailMu        sync.Mutex
	httpServer        *http.Server
	sharedLinksMu     sync.RWMutex
	mux               *CustomMux   // set by Bind, consumed by Start
	listener          net.Listener // pre-bound by Bind so port errors surface synchronously
}

type authFailEntry struct {
	count       int
	lockedUntil time.Time
}

type httperror struct {
	ErrorCode    int
	ErrorMessage string
	Directory    *directory
	AbsPath      string
	GoshsVersion string
	Statics      template.FuncMap
}

type configFile struct {
	Auth  string   `json:"auth"`
	Block []string `json:"block"`
}

type Middleware func(http.Handler) http.Handler

type CustomMux struct {
	mux        *http.ServeMux
	middleware []Middleware
}

type SharedLink struct {
	FilePath        string
	IsDir           bool
	Expires         time.Time
	DownloadLimit   int
	Downloaded      int
	DownloadEntries []DownloadEntry
}

type DownloadEntry struct {
	DownloadURL string
	QRCode      template.URL
}
