package httpserver

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

func (fs *FileServer) findSpecialFile(folder string) (configFile, error) {
	var config configFile

	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	file, err := os.Open(folder)
	if err != nil {
		return config, err
	}

	fis, err := file.Readdir(-1)
	if err != nil {
		return config, err
	}

	for _, fi := range fis {
		if fi.Name() == ".goshs" {
			openFile := filepath.Join(file.Name(), fi.Name())

			// disable G304 (CWE-22): Potential file inclusion via variable
			// #nosec G304
			configFileDisk, err := os.Open(openFile)
			if err != nil {
				return config, err
			}

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
func (fs *FileServer) findEffectiveACL(dir string) (configFile, error) {
	webroot := filepath.Clean(fs.Webroot)
	current := filepath.Clean(dir)

	var effective configFile
	for {
		config, err := fs.findSpecialFile(current)
		if err != nil {
			return configFile{}, err
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
