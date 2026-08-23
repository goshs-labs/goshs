package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"

	"golang.org/x/net/webdav"
)

// webdavCtxKey carries the originating *http.Request into the webdav
// FileSystem so per-path .goshs ACLs can be evaluated against the caller's
// credentials (the FileSystem interface only receives a context.Context).
type webdavCtxKey struct{}

func reqFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(webdavCtxKey{}).(*http.Request)
	return r
}

// newWebdavFileSystem returns a webdav.FileSystem rooted at the webroot that
// enforces the same .goshs ACL rules as the HTTP file server.
func (fs *FileServer) newWebdavFileSystem() webdav.FileSystem {
	return webdavACLFileSystem{srv: fs, root: webdav.Dir(fs.Webroot)}
}

// webdavGuard wraps the webdav handler with mode-flag enforcement (read-only /
// upload-only / no-delete) and the .goshs ACL. It is the choke point for the
// "webdav" mux and is exercised directly in tests.
//
// The verb gating reflects what golang.org/x/net/webdav actually does on disk:
//   - MOVE always Rename()s the source (removing it from its original path) and,
//     with Overwrite:T, RemoveAll()s an existing destination first. Both are
//     deletions, so MOVE is blocked whenever deletion is disabled.
//   - COPY to a fresh path only creates, but COPY with Overwrite (the library
//     default unless the header is "F") onto an existing destination RemoveAll()s
//     it first — also a deletion. That single case is gated behind the delete
//     flags; a non-overwriting COPY stays allowed.
func (fs *FileServer) webdavGuard(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut, "MKCOL":
			if fs.ReadOnly {
				http.Error(w, "read-only", http.StatusForbidden)
				return
			}
			// A PUT onto an existing file truncates/replaces its contents, which
			// is a destruction of the previous data — gate it exactly like the
			// overwriting COPY case. MKCOL only ever creates, so it is unaffected.
			if r.Method == http.MethodPut && (fs.UploadOnly || fs.NoDelete) && fs.webdavTargetExists(r) {
				http.Error(w, "overwrite disabled", http.StatusForbidden)
				return
			}
		case http.MethodPost:
			// golang.org/x/net/webdav routes POST to the same read handler as GET,
			// so an unguarded POST returns the full file body — bypassing the
			// GET/HEAD upload-only block below. WebDAV POST has no legitimate use
			// in this server, so reject it outright regardless of mode.
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		case "COPY":
			if fs.ReadOnly {
				http.Error(w, "read-only", http.StatusForbidden)
				return
			}
			if (fs.UploadOnly || fs.NoDelete) && r.Header.Get("Overwrite") != "F" && fs.webdavDestExists(r) {
				http.Error(w, "overwrite disabled", http.StatusForbidden)
				return
			}
		case "MOVE":
			if fs.ReadOnly || fs.UploadOnly || fs.NoDelete {
				http.Error(w, "move disabled", http.StatusForbidden)
				return
			}
		case http.MethodDelete:
			if fs.ReadOnly || fs.UploadOnly || fs.NoDelete {
				http.Error(w, "delete disabled", http.StatusForbidden)
				return
			}
		case "LOCK", "UNLOCK":
			// LOCK is a mutating verb: golang.org/x/net/webdav's handleLock
			// creates a "lock-null" empty file when the target path does not
			// exist, so an unguarded LOCK plants files even under --read-only.
			// It is not enumerated by the cases above, so without this arm it
			// falls through and skips every mode check. Refuse it (and its
			// UNLOCK counterpart) whenever writes are disallowed.
			if fs.ReadOnly || fs.UploadOnly {
				http.Error(w, "read-only", http.StatusForbidden)
				return
			}
		case http.MethodGet, http.MethodHead:
			if fs.UploadOnly {
				http.Error(w, "upload-only", http.StatusForbidden)
				return
			}
		}
		// Enforce the .goshs ACL on the addressed resource (proper 401 with a
		// challenge), then hand the request to the ACL-aware FileSystem via the
		// context so recursive PROPFIND walks stay filtered too.
		if !fs.webdavEnforceACL(w, r) {
			return
		}
		ctx := context.WithValue(r.Context(), webdavCtxKey{}, r)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// webdavTargetExists reports whether the request URL itself already points at an
// existing (non-directory) resource inside the webroot. Used to distinguish an
// overwriting PUT (which truncates/replaces existing content) from a PUT that
// merely creates a new file.
func (fs *FileServer) webdavTargetExists(r *http.Request) bool {
	abs, err := sanitizePath(fs.Webroot, r.URL.Path)
	if err != nil {
		return false
	}
	info, err := os.Stat(abs)
	return err == nil && !info.IsDir()
}

// webdavDestExists reports whether the Destination header of a COPY/MOVE
// request already points at an existing resource inside the webroot. It is used
// to distinguish an overwriting COPY (which deletes the destination) from a
// harmless copy to a new path.
func (fs *FileServer) webdavDestExists(r *http.Request) bool {
	hdr := r.Header.Get("Destination")
	if hdr == "" {
		return false
	}
	u, err := url.Parse(hdr)
	if err != nil {
		return false
	}
	abs, err := sanitizePath(fs.Webroot, u.Path)
	if err != nil {
		return false
	}
	_, err = os.Stat(abs)
	return err == nil
}

// webdavEnforceACL applies the .goshs ACL to the directly-addressed WebDAV
// resource, mirroring the HTTP server (sendFile/doDir). It is the choke point
// in wdGuard and, unlike the FileSystem layer below, can return a proper 401
// with a WWW-Authenticate challenge so WebDAV clients can supply per-directory
// credentials. It returns false (after writing a response) when the request
// must not proceed.
func (fs *FileServer) webdavEnforceACL(w http.ResponseWriter, r *http.Request) bool {
	abs, err := sanitizePath(fs.Webroot, r.URL.Path)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return false
	}
	// Never expose the ACL config file itself — it holds the bcrypt hashes.
	if filepath.Base(abs) == ".goshs" {
		http.NotFound(w, r)
		return false
	}
	// A directory is governed by its own .goshs; a file by its parent's.
	governing := abs
	if info, statErr := os.Stat(abs); statErr != nil || !info.IsDir() {
		governing = filepath.Dir(abs)
	}
	acl, _ := fs.findEffectiveACL(governing)
	if !fs.applyCustomAuth(w, r, acl) {
		return false
	}
	if slices.Contains(acl.Block, filepath.Base(abs)) {
		http.NotFound(w, r)
		return false
	}
	return true
}

// webdavACLFileSystem wraps a webdav.FileSystem and enforces the .goshs ACL on
// every operation, including the recursive directory walks PROPFIND performs.
// This prevents listings from revealing the .goshs file, block-listed entries,
// or password-protected subdirectories the caller is not authorised for.
type webdavACLFileSystem struct {
	srv  *FileServer
	root webdav.FileSystem
}

// aclError mirrors the HTTP server's behaviour for ACL violations:
//   - the .goshs file and block-listed names look like they do not exist (404)
//   - an unsatisfied auth requirement is a permission error (403)
//
// It returns nil when access to name is permitted.
func (a webdavACLFileSystem) aclError(ctx context.Context, name string) error {
	if path.Base(name) == ".goshs" {
		return os.ErrNotExist
	}
	abs, err := sanitizePath(a.srv.Webroot, name)
	if err != nil {
		return os.ErrNotExist
	}
	governing := abs
	if info, statErr := os.Stat(abs); statErr != nil || !info.IsDir() {
		governing = filepath.Dir(abs)
	}
	acl, _ := a.srv.findEffectiveACL(governing)
	if acl.Auth != "" && !aclSatisfied(reqFromContext(ctx), acl) {
		return os.ErrPermission
	}
	if slices.Contains(acl.Block, path.Base(name)) {
		return os.ErrNotExist
	}
	return nil
}

func (a webdavACLFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if err := a.aclError(ctx, name); err != nil {
		return nil, err
	}
	f, err := a.root.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	abs, _ := sanitizePath(a.srv.Webroot, name)
	return aclFile{File: f, srv: a.srv, req: reqFromContext(ctx), dir: abs}, nil
}

func (a webdavACLFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if err := a.aclError(ctx, name); err != nil {
		return nil, err
	}
	return a.root.Stat(ctx, name)
}

func (a webdavACLFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if err := a.aclError(ctx, name); err != nil {
		return err
	}
	return a.root.Mkdir(ctx, name, perm)
}

func (a webdavACLFileSystem) RemoveAll(ctx context.Context, name string) error {
	if err := a.aclError(ctx, name); err != nil {
		return err
	}
	return a.root.RemoveAll(ctx, name)
}

func (a webdavACLFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if err := a.aclError(ctx, oldName); err != nil {
		return err
	}
	if err := a.aclError(ctx, newName); err != nil {
		return err
	}
	return a.root.Rename(ctx, oldName, newName)
}

// aclFile wraps a webdav.File so directory listings (PROPFIND) cannot reveal the
// .goshs config, block-listed entries, or password-protected subdirectories the
// caller is not authorised for.
type aclFile struct {
	webdav.File
	srv *FileServer
	req *http.Request
	dir string // absolute path of this resource
}

func (f aclFile) Readdir(count int) ([]os.FileInfo, error) {
	infos, err := f.File.Readdir(count)
	if err != nil {
		return infos, err
	}
	// Access to f.dir itself was already authorised; here we filter what is
	// visible inside it. acl is the effective ACL governing this directory.
	acl, _ := f.srv.findEffectiveACL(f.dir)
	filtered := infos[:0]
	for _, fi := range infos {
		name := fi.Name()
		if name == ".goshs" {
			continue
		}
		if slices.Contains(acl.Block, name) {
			continue
		}
		// A subdirectory may add its own auth requirement; hide it if unmet.
		if fi.IsDir() {
			childACL, _ := f.srv.findEffectiveACL(filepath.Join(f.dir, name))
			if childACL.Auth != "" && !aclSatisfied(f.req, childACL) {
				continue
			}
		}
		filtered = append(filtered, fi)
	}
	return filtered, nil
}
