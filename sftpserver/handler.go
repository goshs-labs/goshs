package sftpserver

import (
	"errors"
	"io"

	"github.com/pkg/sftp"
	"goshs.de/goshs/v2/logger"
)

// ReadOnlyHandler is an SFTP handler that only allows read operations
type ReadOnlyHandler struct {
	Root       string
	ClientIP   string
	SFTPServer *SFTPServer
}

func (h *ReadOnlyHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FilePut:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileCmd:  &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileList: &ReadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
	}
}

func (h *ReadOnlyHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	return readFile(h.Root, r, h.ClientIP, h.SFTPServer)
}

func (h *ReadOnlyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("upload not allowed in read-only mode"))
	h.SFTPServer.HandleWebhookSend("sftp", r, h.ClientIP, true)
	return nil, errors.New("upload not allowed in read-only mode")
}

func (h *ReadOnlyHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP, h.SFTPServer)
}

func (h *ReadOnlyHandler) Filecmd(r *sftp.Request) error {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("file commands are not allowed in read-only mode"))
	h.SFTPServer.HandleWebhookSend("sftp", r, h.ClientIP, true)
	return errors.New("file commands are not allowed in read-only mode")
}

// UploadOnlyHandler is an SFTP handler that only allows upload operations
type UploadOnlyHandler struct {
	Root       string
	ClientIP   string
	SFTPServer *SFTPServer
}

func (h *UploadOnlyHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FilePut:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileCmd:  &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileList: &UploadOnlyHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
	}
}

func (h *UploadOnlyHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("download not allowed in upload-only mode"))
	h.SFTPServer.HandleWebhookSend("sftp", r, h.ClientIP, true)
	return nil, errors.New("download not allowed in upload-only mode")
}

func (h *UploadOnlyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	// A drop box must not let a client overwrite what is already in it
	// (GHSA-c3p2-6762-cf9j).
	return writeFile(h.Root, r, h.ClientIP, h.SFTPServer, true)
}

func (h *UploadOnlyHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP, h.SFTPServer)
}

func (h *UploadOnlyHandler) Filecmd(r *sftp.Request) error {
	logger.LogSFTPRequestBlocked(r, h.ClientIP, errors.New("file commands are not allowed in upload-only mode"))
	h.SFTPServer.HandleWebhookSend("sftp", r, h.ClientIP, true)
	return errors.New("file commands are not allowed in upload-only mode")
}

// DefaultHandler is an SFTP handler that allows all operations
type DefaultHandler struct {
	Root       string
	ClientIP   string
	SFTPServer *SFTPServer
}

func (h *DefaultHandler) GetHandler() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FilePut:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileCmd:  &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
		FileList: &DefaultHandler{Root: h.Root, ClientIP: h.ClientIP, SFTPServer: h.SFTPServer},
	}
}

func (h *DefaultHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	return readFile(h.Root, r, h.ClientIP, h.SFTPServer)
}

func (h *DefaultHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return writeFile(h.Root, r, h.ClientIP, h.SFTPServer, h.SFTPServer.NoDelete || h.SFTPServer.UploadOnly)
}

func (h *DefaultHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	return listFile(h.Root, r, h.ClientIP, h.SFTPServer)
}

func (h *DefaultHandler) Filecmd(r *sftp.Request) error {
	return cmdFile(h.Root, r, h.ClientIP, h.SFTPServer)
}
