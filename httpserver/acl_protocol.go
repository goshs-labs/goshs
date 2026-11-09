package httpserver

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ProtocolACL enforces the per-directory .goshs ACL for file-transfer protocols
// other than HTTP/WebDAV — SFTP, FTP, TFTP and SMB — which serve the same
// webroot but carry no per-request HTTP credential and therefore cannot satisfy
// a folder's basic-auth requirement.
//
// It fails closed, mirroring webdavEnforceACL / aclFile.Readdir: the .goshs file
// itself is never accessible; a path governed by a .goshs Auth requirement is
// denied outright (there is no way to present the per-folder credential over
// these protocols, so an unsatisfiable requirement means deny); and any path
// whose basename is on the effective block list is denied. This closes
// GHSA-2m7f-jq4x-rcj7, where the SFTP request handlers performed only a
// webroot-boundary check and never consulted the .goshs ACL at all, and
// GHSA-q8gg-q2wc-w52g, the same gap in TFTP, FTP and SMB.
type ProtocolACL struct {
	fs *FileServer
}

// aclFileName is the fixed basename of the per-directory ACL config file. It
// holds the bcrypt auth hashes, so it must never be served or listed.
const aclFileName = ".goshs"

// normalizeName folds the *syntactic* on-disk name aliases of a single path
// component so a request spelling matches the configured name. Windows (NTFS)
// resolves a trailing-dot or trailing-space segment to the un-suffixed name
// (".env." and ".env " both open ".env"), for any name; filepath.Clean and
// os.File.Stat().Name() keep the attacker's spelling, so a raw compare misses.
// We therefore strip trailing dots and spaces. A single trailing "/" (the
// folder block-list convention, e.g. "secret/") is preserved.
//
// Like the unconditional case-folding added for GHSA-3x28-6v7h-gg87, this runs
// on every platform: it is a denylist *widening* (it can only hide more), so on
// a case-sensitive, dot-significant filesystem a file genuinely named ".env."
// is hidden when ".env" is blocked — an acceptable, fail-closed trade for
// closing the Windows alias bypass. 8.3 short names are not syntactic and are
// resolved against the filesystem separately (canonicalBaseName).
func normalizeName(name string) string {
	slash := strings.HasSuffix(name, "/")
	trimmed := strings.TrimRight(strings.TrimSuffix(name, "/"), ". ")
	if slash {
		trimmed += "/"
	}
	return trimmed
}

// blockListed reports whether name appears in the block list. The comparison is
// case-insensitive (alternate-case spellings such as SECRET.TXT for an on-disk
// secret.txt — GHSA-3x28-6v7h-gg87) and alias-normalized (trailing dot/space —
// GHSA-wh5w-m4vw-7mjm), on both the request spelling and the configured entry.
func blockListed(block []string, name string) bool {
	n := normalizeName(name)
	return slices.ContainsFunc(block, func(s string) bool {
		return strings.EqualFold(normalizeName(s), n)
	})
}

// isACLFileName reports whether a single path component (possibly an alias)
// names the .goshs config file, using the same normalization as blockListed so
// ".goshs." / case variants cannot expose the credential hashes.
func isACLFileName(name string) bool {
	return strings.EqualFold(normalizeName(name), aclFileName)
}

// needsCanonical reports whether base might be a Windows 8.3 short name
// ("LONGSE~1.TXT"), which always contains a tilde. Trailing-dot/space aliases
// are handled syntactically by normalizeName and need no filesystem lookup, so
// gating the (relatively costly) canonical resolution on a tilde keeps the
// common download/list path free of extra stat/ReadDir work.
func needsCanonical(base string) bool {
	return strings.Contains(base, "~")
}

// canonicalBaseName returns the real on-disk base name of absPath. A Windows 8.3
// short name opens the same file as the long name, but filepath.Base and
// os.File.Stat().Name() still report the short spelling, so neither the block
// list nor the .goshs guard would match it. We recover the true directory-entry
// name by finding the sibling that is the same file: os.SameFile compares the
// volume + file index, so every alias of one file maps to its single real
// entry. Falls back to the lexical base when the path does not exist or its
// directory cannot be read.
func canonicalBaseName(absPath string) string {
	target, err := os.Stat(absPath)
	if err != nil {
		return filepath.Base(absPath)
	}
	entries, err := os.ReadDir(filepath.Dir(absPath))
	if err != nil {
		return filepath.Base(absPath)
	}
	for _, e := range entries {
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		if os.SameFile(target, info) {
			return e.Name()
		}
	}
	return filepath.Base(absPath)
}

// blockListedPath reports whether absPath is block-listed, testing both the
// request spelling and — only when it could be an 8.3 alias — the canonical
// on-disk name. This closes the GHSA-wh5w-m4vw-7mjm 8.3 short-name bypass while
// leaving the common path (no tilde, or no block list) free of extra I/O.
func blockListedPath(block []string, absPath string) bool {
	base := filepath.Base(absPath)
	if blockListed(block, base) {
		return true
	}
	if len(block) == 0 || !needsCanonical(base) {
		return false
	}
	return blockListed(block, canonicalBaseName(absPath))
}

// isACLFilePath is isACLFileName for an absolute path, additionally resolving an
// 8.3 alias of .goshs (e.g. GOSHS~1) to its canonical name so the credential
// file cannot be served via a short-name spelling (GHSA-wh5w-m4vw-7mjm).
func isACLFilePath(absPath string) bool {
	base := filepath.Base(absPath)
	if isACLFileName(base) {
		return true
	}
	if !needsCanonical(base) {
		return false
	}
	return isACLFileName(canonicalBaseName(absPath))
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
	// Never expose the ACL config file itself — it holds the bcrypt hashes —
	// and never touch a path beneath a .goshs-named directory, which could only
	// exist to mask an ACL file (GHSA-mhxc-hfx2-7w79).
	if isACLFilePath(absPath) {
		return false
	}
	if rel, err := filepath.Rel(p.fs.Webroot, absPath); err == nil && containsACLName(rel) {
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
	if blockListedPath(acl.Block, absPath) {
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
		if p.visible(dir, acl, fi.Name(), fi.IsDir()) {
			filtered = append(filtered, fi)
		}
	}
	return filtered
}

// FilterDirEntries is FilterListing for os.ReadDir results.
func (p *ProtocolACL) FilterDirEntries(dir string, entries []os.DirEntry) []os.DirEntry {
	acl, _ := p.fs.findEffectiveACL(dir)
	filtered := entries[:0]
	for _, de := range entries {
		if p.visible(dir, acl, de.Name(), de.IsDir()) {
			filtered = append(filtered, de)
		}
	}
	return filtered
}

// visible reports whether entry name of dir (whose effective ACL is acl) may be
// shown to a credential-less protocol client.
func (p *ProtocolACL) visible(dir string, acl configFile, name string, isDir bool) bool {
	if isACLFileName(name) {
		return false
	}
	if blockListed(acl.Block, name) {
		return false
	}
	if isDir {
		childACL, _ := p.fs.findEffectiveACL(filepath.Join(dir, name))
		if childACL.Auth != "" {
			return false
		}
	}
	return true
}

// SubtreeAllowed reports whether a recursive removal of absPath is permitted
// for a credential-less protocol client (SFTP Rmdir, FTP RemoveAll). Allowed
// only checks the addressed path; see subtreeRemovable for why that is not
// enough for a downward delete (GHSA-rf62-vgq5-ggq5).
func (p *ProtocolACL) SubtreeAllowed(absPath string) bool {
	return p.fs.subtreeRemovable(absPath, func(acl configFile) bool { return acl.Auth == "" })
}

// subtreeRemovable reports whether everything a recursive delete of absPath
// would destroy is accessible. findEffectiveACL only walks *up* towards the
// webroot, so checking the addressed path (or its parent) never sees a .goshs
// below it, and os.RemoveAll of an unprotected directory took every
// auth-protected or block-listed subtree with it (GHSA-rf62-vgq5-ggq5).
//
// It fails closed: the webroot itself is never removable; every directory in
// the subtree must have a readable effective ACL that satisfied accepts; and no
// entry may be block-listed by its directory (a hidden name must not be
// destroyable either). The walk does not follow symlinks, matching RemoveAll,
// which unlinks a symlink rather than descending into it. A non-directory (or
// missing) absPath has nothing below it and is left to the caller's own check.
func (fs *FileServer) subtreeRemovable(absPath string, satisfied func(configFile) bool) bool {
	root := filepath.Clean(absPath)
	if root == filepath.Clean(fs.Webroot) {
		return false
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return true
	}
	// The directory itself, as an entry of its parent ("name/" convention).
	if parentACL, aclErr := fs.findEffectiveACL(filepath.Dir(root)); aclErr != nil ||
		blockListed(parentACL.Block, canonicalBaseName(root)+"/") {
		return false
	}
	ok := true
	walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		acl, aclErr := fs.findEffectiveACL(p)
		if aclErr != nil || !satisfied(acl) {
			ok = false
			return filepath.SkipAll
		}
		entries, readErr := os.ReadDir(p)
		if readErr != nil {
			return readErr
		}
		for _, e := range entries {
			name := e.Name()
			if blockListed(acl.Block, name) || (e.IsDir() && blockListed(acl.Block, name+"/")) {
				ok = false
				return filepath.SkipAll
			}
		}
		return nil
	})
	return ok && walkErr == nil
}

// RenameAllowed reports whether a credential-less protocol client may rename
// oldAbs to newAbs (SFTP Rename, FTP RNFR/RNTO, SMB FileRenameInformation).
// Allowed only checks the two addressed paths; see subtreeMovable for why that
// is not enough for a directory (GHSA-95fx-g5c4-6f8f).
func (p *ProtocolACL) RenameAllowed(oldAbs, newAbs string) bool {
	return p.fs.subtreeMovable(oldAbs, newAbs, func(acl configFile) bool { return acl.Auth == "" })
}

// subtreeMovable reports whether renaming the directory oldAbs to newAbs keeps
// every .goshs constraint on its contents in force. Block entries and inherited
// auth are declared in an *ancestor* and resolved upwards, so moving a
// directory out from under the declaring .goshs silently dropped them: a
// block-listed file below an unprotected directory became readable at the new
// path (GHSA-95fx-g5c4-6f8f, the rename residual of GHSA-rf62-vgq5-ggq5).
//
// A .goshs inside the subtree travels with it, so only what the old parent
// contributes can be lost. The rename is therefore allowed when either nothing
// below oldAbs is protected (subtreeRemovable), or the new parent imposes at
// least the old parent's constraints: the same Auth (if any) and a superset of
// its block list. The directory itself must not be block-listed under its old
// name, since renaming it would shed that entry. A non-directory (or missing)
// oldAbs has nothing below it and is left to the caller's addressed-path checks.
func (fs *FileServer) subtreeMovable(oldAbs, newAbs string, satisfied func(configFile) bool) bool {
	root := filepath.Clean(oldAbs)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return true
	}
	if fs.subtreeRemovable(root, satisfied) {
		return true
	}
	src, srcErr := fs.findEffectiveACL(filepath.Dir(root))
	dst, dstErr := fs.findEffectiveACL(filepath.Dir(filepath.Clean(newAbs)))
	if srcErr != nil || dstErr != nil {
		return false
	}
	base := canonicalBaseName(root)
	if blockListed(src.Block, base) || blockListed(src.Block, base+"/") {
		return false
	}
	if src.Auth != "" && dst.Auth != src.Auth {
		return false
	}
	for _, b := range src.Block {
		if !blockListed(dst.Block, b) {
			return false
		}
	}
	return true
}
