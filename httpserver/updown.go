package httpserver

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"goshs.de/goshs/v2/logger"
)

// prepareWrite enforces the ACL for dir and applies the upload size limit.
// Returns false if the request has already been rejected.
func (fs *FileServer) prepareWrite(w http.ResponseWriter, req *http.Request, dir string) bool {
	acl, aclErr := fs.findEffectiveACL(dir)
	if aclErr != nil {
		logger.Errorf("error reading file based access config: %+v", aclErr)
	}
	if ok := fs.applyCustomAuth(w, req, acl); !ok {
		return false
	}
	if fs.MaxUpload > 0 {
		req.Body = http.MaxBytesReader(w, req.Body, fs.MaxUpload)
	}
	return true
}

// put handles the PUT request to upload files
func (fs *FileServer) put(w http.ResponseWriter, req *http.Request) {
	if !fs.checkCSRF(w, req) {
		return
	}
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	savepath, err := sanitizePath(fs.UploadFolder, req.URL.Path)
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}

	// Block overwriting the .goshs ACL file
	if filepath.Base(savepath) == ".goshs" {
		fs.handleError(w, req, fmt.Errorf("cannot overwrite ACL file"), http.StatusForbidden)
		return
	}

	// Overwriting an existing file with O_TRUNC destroys its previous contents,
	// which is a deletion. Block it under --no-delete / --upload-only, mirroring
	// the WebDAV PUT/COPY overwrite guard. Creating a new file stays allowed.
	if fs.UploadOnly || fs.NoDelete {
		if info, statErr := os.Stat(savepath); statErr == nil && !info.IsDir() {
			fs.handleError(w, req, fmt.Errorf("%s", "Overwriting existing files is not allowed due to 'no delete' / 'upload only' option"), http.StatusForbidden)
			return
		}
	}

	// Enforce .goshs ACL and upload size limit
	if !fs.prepareWrite(w, req, filepath.Dir(savepath)) {
		return
	}

	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	osFile, err := os.OpenFile(savepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		logger.Errorf("Error opening file: %+v", err)
		fs.handleError(w, req, err, http.StatusInternalServerError)
		return
	}

	if _, err := io.Copy(osFile, req.Body); err != nil {
		osFile.Close()
		os.Remove(savepath)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			fs.handleError(w, req, fmt.Errorf("upload exceeds size limit (%d bytes)", fs.MaxUpload), http.StatusRequestEntityTooLarge)
		} else {
			logger.Errorf("Error writing file %s to disk: %+v", savepath, err)
			fs.handleError(w, req, err, http.StatusInternalServerError)
		}
		return
	}
	osFile.Close()

	// Log request
	_ = fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, nil)
}

// upload handles the POST request to upload files
func (fs *FileServer) upload(w http.ResponseWriter, req *http.Request) {
	if !fs.checkCSRF(w, req) {
		return
	}
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	// Derive and sanitize the target directory (strip trailing "/upload" from URL).
	upathDir := strings.TrimSuffix(req.URL.Path, "/upload")
	targetDir, err := sanitizePath(fs.UploadFolder, upathDir)
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}

	// Enforce .goshs ACL and upload size limit
	if !fs.prepareWrite(w, req, targetDir) {
		return
	}

	reader, err := req.MultipartReader()
	if err != nil {
		logger.Errorf("reading multipart request: %+v", err)
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				fs.handleError(w, req, fmt.Errorf("upload exceeds size limit (%d bytes)", fs.MaxUpload), http.StatusRequestEntityTooLarge)
			} else {
				logger.Errorf("reading multipart part: %+v", err)
			}
			return
		}
		if part.FileName() == "" {
			continue // skip form fields
		}

		// sanitize filename (No path traversal). part.FileName() already applies
		// filepath.Base, but that still lets ".." through, and filepath.Join with
		// ".." would resolve to the parent of targetDir — writing outside the
		// served tree. Reject any name that is empty, "." or ".." after cleaning.
		filenameSlice := strings.Split(part.FileName(), "/")
		filenameClean := filenameSlice[len(filenameSlice)-1]

		if filenameClean == "" || filenameClean == "." || filenameClean == ".." {
			logger.Warnf("blocked upload with invalid filename %q", part.FileName())
			continue
		}

		// Block overwriting the .goshs ACL file
		if filenameClean == ".goshs" {
			logger.Warnf("blocked attempt to upload file named .goshs")
			continue
		}

		// Prepare destination file paths
		finalPath := filepath.Join(targetDir, filenameClean)
		tempPath := finalPath + "~"

		// The final os.Rename clobbers any existing same-named file, destroying
		// its contents. Skip such overwrites under --no-delete / --upload-only,
		// matching the WebDAV PUT/COPY overwrite guard; new files still upload.
		if fs.UploadOnly || fs.NoDelete {
			if info, statErr := os.Stat(finalPath); statErr == nil && !info.IsDir() {
				logger.Warnf("blocked overwrite of existing file %q due to 'no delete' / 'upload only' option", finalPath)
				continue
			}
		}

		// Defence in depth: ensure the resolved destination stays inside targetDir
		// even if filenameClean ever slips a separator or traversal past the checks
		// above.
		if _, err := sanitizePath(targetDir, filenameClean); err != nil {
			logger.Warnf("blocked upload escaping target directory: %q", part.FileName())
			continue
		}

		// Create temp file
		dst, err := os.Create(tempPath)
		if err != nil {
			logger.Errorf("creating temp file: %+v", err)
			return
		}

		// Write in chunks
		buf := make([]byte, chunkSize)
		var totalWritten int64
		for {
			n, readErr := part.Read(buf)
			if n > 0 {
				written, writeErr := dst.Write(buf[:n])
				if writeErr != nil || written != n {
					dst.Close()
					os.Remove(tempPath)
					logger.Errorf("writing file to disk: %+v", writeErr)
					return
				}
				totalWritten += int64(written)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				dst.Close()
				os.Remove(tempPath)
				var maxErr *http.MaxBytesError
				if errors.As(readErr, &maxErr) {
					fs.handleError(w, req, fmt.Errorf("upload exceeds size limit (%d bytes)", fs.MaxUpload), http.StatusRequestEntityTooLarge)
				} else {
					logger.Errorf("reading uploaded data: %+v", readErr)
				}
				return
			}
		}

		// Ensure file is flushed and closed
		if err := dst.Sync(); err != nil {
			dst.Close()
			os.Remove(tempPath)
			logger.Errorf("syncing file: %+v", err)
			return
		}
		if err := dst.Close(); err != nil {
			os.Remove(tempPath)
			logger.Errorf("closing file: %+v", err)
			return
		}

		// Atomically rename to final path
		if err := os.Rename(tempPath, finalPath); err != nil {
			logger.Errorf("renaming file: %+v", err)
			return
		}

		// Webhook
		logger.HandleWebhookSend(fmt.Sprintf("[WEB] File uploaded: %s", finalPath), "upload", fs.Webhook)
	}

	// Log request
	body := fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)

	// Redirect back from where we came from
	http.Redirect(w, req, upathDir, http.StatusSeeOther)
}

// bulkDownload will provide zip archived download bundle of multiple selected files
func (fs *FileServer) bulkDownload(w http.ResponseWriter, req *http.Request) {
	if fs.UploadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Bulk download not allowed due to 'upload only' option"), http.StatusForbidden)
		return
	}
	// make slice and query files from request
	var filesCleaned []string
	files := req.URL.Query()["file"]

	// Handle if no files are selected
	if len(files) == 0 {
		fs.handleError(w, req, errors.New("you need to select a file before you can download a zip archive"), 404)
		return
	}

	// Validate each path, enforce .goshs ACL, and collect absolute paths.
	// ACL checks must happen here, before any response headers are written,
	// so that applyCustomAuth/handleError can still send a proper HTTP error.
	for _, file := range files {
		absPath, err := sanitizePath(fs.Webroot, file)
		if err != nil {
			continue
		}
		// Determine the directory whose ACL governs this selection. For a
		// directory we must start the (upward-walking) ACL lookup at the
		// directory itself, otherwise a .goshs placed *inside* the selected
		// directory would be ignored. For a file we start at its parent.
		governing := absPath
		if info, statErr := os.Stat(absPath); statErr != nil || !info.IsDir() {
			governing = filepath.Dir(absPath)
		}
		acl, aclErr := fs.findEffectiveACL(governing)
		if aclErr == nil {
			if ok := fs.applyCustomAuth(w, req, acl); !ok {
				return
			}
			if slices.Contains(acl.Block, filepath.Base(absPath)) {
				fs.handleError(w, req, fmt.Errorf("requested file is blocked"), http.StatusNotFound)
				return
			}
		}
		filesCleaned = append(filesCleaned, absPath)
	}

	// Construct filename to download
	filename := fmt.Sprintf("%d_goshs_download.zip", time.Now().Unix())

	// Set header and serve file
	contentDispo := fmt.Sprintf("attachment; filename=\"%s\"", filename)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDispo)
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Expires", "0")

	// Define Zip writer
	resultZip := zip.NewWriter(w)
	defer resultZip.Close()

	// Path walker for recursion
	walker := func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Never include the ACL config file itself — it contains credential hashes.
		if filepath.Base(walkPath) == ".goshs" {
			return nil
		}
		// Skip the chat's on-disk sink (uploads + persisted log); it is hidden
		// from the listing and shouldn't be swept into a bulk archive.
		if strings.Contains(walkPath, string(os.PathSeparator)+chatDirName+string(os.PathSeparator)) {
			return nil
		}

		// Re-enforce the effective ACL for this file's own directory. The
		// top-level selection was already checked above, but filepath.Walk
		// descends into nested directories that may carry their own restrictive
		// .goshs (auth or block list). Response headers are already written at
		// this point, so we cannot prompt — silently skip files the caller is
		// not allowed to read instead of leaking them into the archive.
		if acl, aclErr := fs.findEffectiveACL(filepath.Dir(walkPath)); aclErr == nil {
			if !aclSatisfied(req, acl) {
				return nil
			}
			if slices.Contains(acl.Block, filepath.Base(walkPath)) {
				return nil
			}
		}

		// disable G304 (CWE-22): Potential file inclusion via variable
		// #nosec G304
		file, err := os.Open(walkPath)
		if err != nil {
			return err
		}
		// disable G307 (CWE-703): Deferring unsafe method "Close" on type "*os.File"
		// #nosec G307
		defer file.Close()

		// walkPath is fs.Webroot + file relative path
		// this would result in a lot of nested folders
		// so we are stripping fs.Webroot again from the structure of the zip file
		// Leaving us with the relative path of the file
		zippath := strings.ReplaceAll(walkPath, fs.Webroot, "")
		header := &zip.FileHeader{
			Name:     zippath[1:],
			Method:   zip.Deflate,
			Modified: info.ModTime(),
		}
		f, err := resultZip.CreateHeader(header)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}

	// Loop over files and add to zip (filesCleaned contains validated absolute paths)
	for _, file := range filesCleaned {
		err := filepath.Walk(file, walker)
		if err != nil {
			logger.Errorf("creating zip file: %+v", err)
		}
	}

	// Close Zip Writer and Flush to http.ResponseWriter
	if err := resultZip.Close(); err != nil {
		logger.Error(err)
	} else {
		body := fs.emitCollabEvent(req, http.StatusOK)
		logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)
	}
}
