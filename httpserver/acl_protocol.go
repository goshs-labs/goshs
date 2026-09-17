package httpserver

import (
	"os"
	"path/filepath"
	"slices"
)

// ProtocolACL enforces the per-directory .goshs ACL for file-transfer protocols
// other than HTTP/WebDAV — currently SFTP — which serve the same webroot but
// carry no per-request HTTP credential and therefore cannot satisfy a folder's
// basic-auth requirement.
//
// It fails closed, mirroring webdavEnforceACL / aclFile.Readdir: the .goshs file
// itself is never accessible; a path governed by a .goshs Auth requirement is
// denied outright (there is no way to present the per-folder credential over
// these protocols, so an unsatisfiable requirement means deny); and any path
// whose basename is on the effective block list is denied. This closes
// GHSA-2m7f-jq4x-rcj7, where the SFTP request handlers performed only a
// webroot-boundary check and never consulted the .goshs ACL at all.
type ProtocolACL struct {
	fs *FileServer
}

// NewProtocolACL builds a ProtocolACL bound to webroot. Only the webroot is
// needed: findEffectiveACL/findSpecialFile read it plus the .goshs files on disk
// and touch no other FileServer state.
func NewProtocolACL(webroot string) *ProtocolACL {
	return &ProtocolACL{fs: &FileServer{Webroot: webroot}}
}

// Allowed reports whether an operation on absPath (an absolute path inside the
// webroot) is permitted. absPath need not exist yet (e.g. an upload target or a
// mkdir): as in webdavEnforceACL, a missing or non-directory path is governed by
// its parent directory's effective ACL, while an existing directory is governed
// by its own.
func (p *ProtocolACL) Allowed(absPath string) bool {
	// Never expose the ACL config file itself — it holds the bcrypt hashes.
	if filepath.Base(absPath) == ".goshs" {
		return false
	}
	governing := absPath
	if info, err := os.Stat(absPath); err != nil || !info.IsDir() {
		governing = filepath.Dir(absPath)
	}
	acl, _ := p.fs.findEffectiveACL(governing)
	// A per-folder auth requirement cannot be satisfied over a credential-less
	// protocol, so it is a hard deny (the HTTP/WebDAV equivalent of an
	// unsatisfied aclSatisfied check).
	if acl.Auth != "" {
		return false
	}
	if slices.Contains(acl.Block, filepath.Base(absPath)) {
		return false
	}
	return true
}

// FilterListing removes entries a protocol client must not see from a listing of
// dir (an absolute path already authorised via Allowed): the .goshs file itself,
// block-listed names, and subdirectories that carry their own auth requirement.
// Mirrors aclFile.Readdir.
func (p *ProtocolACL) FilterListing(dir string, infos []os.FileInfo) []os.FileInfo {
	acl, _ := p.fs.findEffectiveACL(dir)
	filtered := infos[:0]
	for _, fi := range infos {
		name := fi.Name()
		if name == ".goshs" {
			continue
		}
		if slices.Contains(acl.Block, name) {
			continue
		}
		if fi.IsDir() {
			childACL, _ := p.fs.findEffectiveACL(filepath.Join(dir, name))
			if childACL.Auth != "" {
				continue
			}
		}
		filtered = append(filtered, fi)
	}
	return filtered
}
