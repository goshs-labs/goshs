package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/ws"
)

func (fs *FileServer) emitCollabEvent(r *http.Request, status int) []byte {
	// Emit HTTP log event to webhook
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Failed to read request body: %v", err)
	}
	defer r.Body.Close()

	// Flatten headers into a simple map (join multi-value headers with ", ").
	// Strip sensitive headers so they are never exposed on the collaborator feed:
	//   - X-Csrf-Token: our own anti-CSRF secret.
	//   - Authorization: a legitimate write to a .goshs-protected directory
	//     carries "Authorization: Basic base64(user:pass)". The feed is anonymous
	//     when no global -b/-P is set, so broadcasting this header would leak the
	//     per-directory ACL credential to any watcher (GHSA-wfg4-m42q-9pvq).
	// Stripping here covers every call site unconditionally, including the write
	// handlers that emit after authenticating.
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		switch http.CanonicalHeaderKey(k) {
		case "X-Csrf-Token", "Authorization":
			continue
		}
		headers[k] = strings.Join(v, ", ")
	}

	event := ws.HTTPEvent{
		Type:       "http",
		Method:     r.Method,
		URL:        r.URL.String(),
		Body:       string(body),
		Parameters: r.URL.Query().Encode(),
		Headers:    headers,
		Source:     r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Status:     status,
		Timestamp:  time.Now(),
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorf("Error marshalling dns query event: %v", err)
		return body
	}

	fs.Hub.Broadcast <- eventBytes
	return body
}
