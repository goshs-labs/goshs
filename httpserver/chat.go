package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"goshs.de/goshs/v2/logger"
)

// chatDirName is the hidden directory inside the webroot that holds chat file
// uploads, persisted pasted images and (with --persist-chat) the chat log. It is
// excluded from directory listings but its files remain reachable by link.
const chatDirName = ".goshs-chat"

// chatDown streams the chat log to the browser as a JSON download for export.
func (fs *FileServer) chatDown(w http.ResponseWriter, req *http.Request) {
	filename := fmt.Sprintf("%d-chat.json", time.Now().Unix())
	contentDisposition := fmt.Sprintf("attachment; filename=\"%s\"", filename)
	// Handle as download
	w.Header().Add("Content-Type", "application/octet-stream")
	w.Header().Add("Content-Disposition", contentDisposition)
	content, err := fs.Chat.Download()
	if err != nil {
		fs.handleError(w, req, err, 500)
	}

	if _, err := w.Write(content); err != nil {
		logger.Errorf("Error writing response to browser: %+v", err)
	}
}

// chatUpload accepts a single multipart file, stores it under the hidden
// .goshs-chat/ directory in the webroot and replies with JSON describing the
// link the browser should embed into a chat message. It powers both the
// composer's upload button and --persist-chat-images. Writing to disk is gated
// on read-only mode (respected) and the chat being enabled.
func (fs *FileServer) chatUpload(w http.ResponseWriter, req *http.Request) {
	if !fs.checkCSRF(w, req) {
		return
	}
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("chat upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}

	chatDir := filepath.Join(fs.Webroot, chatDirName)
	if err := os.MkdirAll(chatDir, 0o755); err != nil {
		fs.handleError(w, req, err, http.StatusInternalServerError)
		return
	}

	// Enforce the global upload size limit if one is configured.
	if fs.MaxUpload > 0 {
		req.Body = http.MaxBytesReader(w, req.Body, fs.MaxUpload)
	}

	reader, err := req.MultipartReader()
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fs.handleError(w, req, fmt.Errorf("reading upload: %w", err), http.StatusBadRequest)
			return
		}
		if part.FileName() == "" {
			continue // skip non-file form fields
		}

		// Sanitize the filename: strip any path, reject traversal and the ACL
		// file name. Store under a unique, timestamped name so uploads never
		// overwrite each other or existing served files.
		slice := strings.Split(part.FileName(), "/")
		clean := filepath.Base(slice[len(slice)-1])
		if clean == "" || clean == "." || clean == ".." || clean == ".goshs" {
			fs.handleError(w, req, fmt.Errorf("invalid filename"), http.StatusBadRequest)
			return
		}
		stored := fmt.Sprintf("%d-%s", time.Now().UnixNano(), clean)

		// Defence in depth: the resolved destination must stay inside chatDir.
		if _, err := sanitizePath(chatDir, stored); err != nil {
			fs.handleError(w, req, fmt.Errorf("invalid destination"), http.StatusBadRequest)
			return
		}
		finalPath := filepath.Join(chatDir, stored)

		dst, err := os.Create(finalPath)
		if err != nil {
			fs.handleError(w, req, err, http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(dst, part); err != nil {
			dst.Close()
			os.Remove(finalPath)
			if _, ok := err.(*http.MaxBytesError); ok {
				fs.handleError(w, req, fmt.Errorf("upload exceeds size limit (%d bytes)", fs.MaxUpload), http.StatusRequestEntityTooLarge)
			} else {
				fs.handleError(w, req, fmt.Errorf("writing upload: %w", err), http.StatusInternalServerError)
			}
			return
		}
		if err := dst.Close(); err != nil {
			os.Remove(finalPath)
			fs.handleError(w, req, err, http.StatusInternalServerError)
			return
		}

		logger.HandleWebhookSend(fmt.Sprintf("[WEB] Chat file uploaded: %s", finalPath), "upload", fs.Webhook)

		// The link the browser embeds into the chat message. The path segment is
		// escaped so spaces/unicode in the stored name still resolve.
		link := "/" + chatDirName + "/" + url.PathEscape(stored)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"url":     link,
			"name":    clean,
			"isImage": isImageFilename(clean),
		}); err != nil {
			logger.Errorf("Error writing chat upload response: %+v", err)
		}
		return
	}

	fs.handleError(w, req, fmt.Errorf("no file supplied"), http.StatusBadRequest)
}

// isImageFilename reports whether name has a common raster image extension, so
// the client can embed it as a markdown image rather than a plain link.
func isImageFilename(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".avif":
		return true
	default:
		return false
	}
}
