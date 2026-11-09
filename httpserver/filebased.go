package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// denyAllAuth is the Auth value of a fail-closed ACL. It contains no ':' so it
// never parses as user:hash, making it unsatisfiable for aclSatisfied /
// applyCustomAuth and a hard deny for ProtocolACL.
const denyAllAuth = "\x00deny"

func (fs *FileServer) findSpecialFile(folder string) (configFile, error) {
	var config configFile

	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	file, err := os.Open(folder)
	if err != nil {
		return config, err
	}
	defer file.Close()

	fis, err := file.Readdir(-1)
	if err != nil {
		return config, err
	}

	for _, fi := range fis {
		if strings.EqualFold(fi.Name(), ".goshs") {
			openFile := filepath.Join(file.Name(), fi.Name())

			// Only a regular file can be an ACL config. A directory named .goshs
			// (e.g. created via mkdir) would make io.ReadAll fail with EISDIR;
			// skip it so it can neither shadow a real .goshs nor poison the
			// resolver (GHSA-mhxc-hfx2-7w79). Stat follows symlinks.
			if st, statErr := os.Stat(openFile); statErr == nil && !st.Mode().IsRegular() {
				continue
			}

			// disable G304 (CWE-22): Potential file inclusion via variable
			// #nosec G304
			configFileDisk, err := os.Open(openFile)
			if err != nil {
				return config, err
			}
			defer configFileDisk.Close()

			configFileBytes, err := io.ReadAll(configFileDisk)
			if err != nil {
				return config, err
			}

			if err := json.Unmarshal(configFileBytes, &config); err != nil {
				return config, err
			}

			return config, nil
		}
	}

	return config, nil
}

// findEffectiveACL walks up the directory tree from dir toward the webroot and
// MERGES every .goshs it finds into a single effective ACL, so a .goshs placed
// in a parent directory applies recursively to all subdirectories.
//
// The merge is deliberate and security-critical (GHSA-cfhc-8j7j-54wq): a naive
// "return the nearest non-empty .goshs" walk let a block-only child .goshs
// ({"block":[...]}, Auth=="") shadow and erase an ancestor's auth requirement,
// yielding unauthenticated access to the protected subtree. The merge rules are:
//
//   - Auth: the NEAREST ancestor that sets one wins. A nearer block-only .goshs
//     must never clear an ancestor's auth, so we fill Auth in exactly once (on
//     the first non-empty value encountered walking upward) and never overwrite.
//   - Block: the UNION of every .goshs block list along the walk, so a parent's
//     block entries keep applying to descendant directories (fail-closed).
//
// The walk never leaks upward past the webroot.
//
// It fails CLOSED (GHSA-mhxc-hfx2-7w79): if any .goshs along the walk cannot be
// read or parsed, the returned ACL carries denyAllAuth, an Auth value no
// credential can satisfy, alongside the error. Callers historically logged the
// error and carried on with the ACL, so returning an empty configFile silently
// dropped every ancestor's auth and block list. Directories that do not exist
// (yet) hold no .goshs and are skipped, so ancestors still govern e.g. the
// target of a nested mkdir.
func (fs *FileServer) findEffectiveACL(dir string) (configFile, error) {
	webroot := filepath.Clean(fs.Webroot)
	current := filepath.Clean(dir)

	var effective configFile
	for {
		config, err := fs.findSpecialFile(current)
		if err != nil {
			// Only a directory that is itself missing is skipped; any other
			// failure (unreadable dir, dangling or unreadable .goshs, bad JSON)
			// denies.
			if _, statErr := os.Lstat(current); !errors.Is(statErr, os.ErrNotExist) {
				return configFile{Auth: denyAllAuth}, err
			}
			config = configFile{}
		}
		if effective.Auth == "" && config.Auth != "" {
			effective.Auth = config.Auth
		}
		if len(config.Block) > 0 {
			effective.Block = append(effective.Block, config.Block...)
		}
		// Stop once we have checked the webroot itself
		if current == webroot {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			// Reached filesystem root – guard against infinite loop
			break
		}
		current = parent
	}

	return effective, nil
}

// containsACLName reports whether any component of p names .goshs, including
// its case and trailing-dot/space alias spellings (isACLFileName). Creating such
// a path would either plant an ACL file or a directory masking one, so every
// create path must refuse it. Windows opens ".goshs." / ".goshs " as the real
// .goshs, so an exact-spelling compare let an anonymous upload create or
// overwrite the ACL (GHSA-8v6q-gvgc-m3vq).
func containsACLName(p string) bool {
	return slices.ContainsFunc(strings.Split(filepath.ToSlash(p), "/"), isACLFileName)
}
