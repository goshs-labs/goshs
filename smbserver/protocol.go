package smbserver

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"goshs.de/goshs/v2/logger"
)

// ── SMB2 Commands ──────────────────────────────────────────────────────────
const (
	SMB2_NEGOTIATE       uint16 = 0x0000
	SMB2_SESSION_SETUP   uint16 = 0x0001
	SMB2_LOGOFF          uint16 = 0x0002
	SMB2_TREE_CONNECT    uint16 = 0x0003
	SMB2_TREE_DISCONNECT uint16 = 0x0004
	SMB2_CREATE          uint16 = 0x0005
	SMB2_CLOSE           uint16 = 0x0006
	SMB2_FLUSH           uint16 = 0x0007
	SMB2_READ            uint16 = 0x0008
	SMB2_WRITE           uint16 = 0x0009
	SMB2_LOCK            uint16 = 0x000A
	SMB2_IOCTL           uint16 = 0x000B
	SMB2_CANCEL          uint16 = 0x000C
	SMB2_ECHO            uint16 = 0x000D
	SMB2_QUERY_DIRECTORY uint16 = 0x000E
	SMB2_CHANGE_NOTIFY   uint16 = 0x000F
	SMB2_QUERY_INFO      uint16 = 0x0010
	SMB2_SET_INFO        uint16 = 0x0011
)

// -- SMB2 access mask flags
const (
	DELETE               = 0x00010000
	FILE_READ_DATA       = 0x00000001
	FILE_READ_EA         = 0x00000008
	FILE_READ_ATTRIBUTES = 0x00000080
)

// ── NTSTATUS codes ─────────────────────────────────────────────────────────
const (
	STATUS_SUCCESS                    uint32 = 0x00000000
	STATUS_MORE_PROCESSING            uint32 = 0xC0000016
	STATUS_NOT_IMPLEMENTED            uint32 = 0xC0000002
	STATUS_INVALID_PARAMETER          uint32 = 0xC000000D
	STATUS_ACCESS_DENIED              uint32 = 0xC0000022
	STATUS_NO_SUCH_FILE               uint32 = 0xC000000F
	STATUS_OBJECT_NAME_NOT_FOUND      uint32 = 0xC0000034
	STATUS_OBJECT_NAME_COLLISION      uint32 = 0xC0000035
	STATUS_END_OF_FILE                uint32 = 0xC0000011
	STATUS_BAD_NETWORK_NAME           uint32 = 0xC00000CC
	STATUS_LOGON_FAILURE              uint32 = 0xC000006D
	STATUS_USER_SESSION_DELETED       uint32 = 0xC0000203
	STATUS_NOT_SUPPORTED              uint32 = 0xC00000BB
	STATUS_OBJECT_PATH_NOT_FOUND      uint32 = 0xC000003A
	STATUS_DIRECTORY_NOT_EMPTY        uint32 = 0xC0000101
	STATUS_FILE_IS_A_DIRECTORY        uint32 = 0xC00000BA
	STATUS_NOT_A_DIRECTORY            uint32 = 0xC0000103
	STATUS_SHARING_VIOLATION          uint32 = 0xC0000043
	STATUS_NETWORK_NAME_DELETED       uint32 = 0xC00000C9
	STATUS_INSUFFICIENT_RESOURCES     uint32 = 0xC000009A
	STATUS_DELETE_PENDING             uint32 = 0xC0000056
	STATUS_STOPPED_ON_SYMLINK         uint32 = 0x8000002D
	STATUS_IO_REPARSE_TAG_NOT_HANDLED uint32 = 0xC0000279
	STATUS_NO_MORE_FILES              uint32 = 0x80000006
	STATUS_FS_DRIVER_REQUIRED         uint32 = 0xC000019C
	STATUS_NOTIFY_ENUM_DIR            uint32 = 0x0000010C
	STATUS_CANCELLED                  uint32 = 0xC0000120
)

// ── Session flags ──────────────────────────────────────────────────────────
const (
	// SMB2_SESSION_FLAG_IS_GUEST: client MUST set Session.SigningRequired = FALSE.
	SMB2_SESSION_FLAG_IS_GUEST uint16 = 0x0001
	// SMB2_SESSION_FLAG_IS_NULL: null/anonymous session — no credentials were
	// exchanged and no signing key exists.  Per MS-SMB2 §3.2.5.3.1 the client
	// MUST set Session.SigningRequired = FALSE.  Unlike IS_GUEST, IS_NULL signals
	// that signing was never possible for this session, which Windows 11 (24H2+)
	// respects even when Connection.RequireSigning is TRUE from its local policy.
	SMB2_SESSION_FLAG_IS_NULL uint16 = 0x0002
)

// ── Dialect revisions ──────────────────────────────────────────────────────
const (
	SMB2_DIALECT_202 uint16 = 0x0202
	SMB2_DIALECT_210 uint16 = 0x0210
)

// ── Capabilities ───────────────────────────────────────────────────────────
const (
	SMB2_GLOBAL_CAP_LARGE_MTU uint32 = 0x00000004
)

// ── File attributes ────────────────────────────────────────────────────────
const (
	FILE_ATTRIBUTE_READONLY  uint32 = 0x00000001
	FILE_ATTRIBUTE_DIRECTORY uint32 = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE   uint32 = 0x00000020
	FILE_ATTRIBUTE_NORMAL    uint32 = 0x00000080
)

// ── Create disposition ─────────────────────────────────────────────────────
const (
	FILE_SUPERSEDE    uint32 = 0x00000000
	FILE_OPEN         uint32 = 0x00000001
	FILE_CREATE       uint32 = 0x00000002
	FILE_OPEN_IF      uint32 = 0x00000003
	FILE_OVERWRITE    uint32 = 0x00000004
	FILE_OVERWRITE_IF uint32 = 0x00000005
)

// ── Create action (response) ───────────────────────────────────────────────
const (
	FILE_SUPERSEDED  uint32 = 0x00000000
	FILE_OPENED      uint32 = 0x00000001
	FILE_CREATED     uint32 = 0x00000002
	FILE_OVERWRITTEN uint32 = 0x00000003
)

// ── Create options ─────────────────────────────────────────────────────────
const (
	FILE_DIRECTORY_FILE     uint32 = 0x00000001
	FILE_NON_DIRECTORY_FILE uint32 = 0x00000040
	FILE_DELETE_ON_CLOSE    uint32 = 0x00001000
)

// ── QueryDirectory info classes ────────────────────────────────────────────
const (
	FILE_BOTH_DIR_INFORMATION    uint8 = 3
	FILE_ID_BOTH_DIR_INFORMATION uint8 = 37
)

// ── QueryDir flags ─────────────────────────────────────────────────────────
const (
	SMB2_RESTART_SCANS       uint8 = 0x01
	SMB2_RETURN_SINGLE_ENTRY uint8 = 0x02
	SMB2_INDEX_SPECIFIED     uint8 = 0x04
	SMB2_REOPEN              uint8 = 0x10
)

// ── QueryInfo types ────────────────────────────────────────────────────────
const (
	SMB2_0_INFO_FILE       uint8 = 0x01
	SMB2_0_INFO_FILESYSTEM uint8 = 0x02
	SMB2_0_INFO_SECURITY   uint8 = 0x03
)

// ── File info classes ──────────────────────────────────────────────────────
const (
	FileBasicInformation       uint8 = 4
	FileStandardInformation    uint8 = 5
	FileInternalInformation    uint8 = 6
	FileEaInformation          uint8 = 7
	FileAccessInformation      uint8 = 8
	FileNameInformation        uint8 = 9
	FileRenameInformation      uint8 = 10
	FileDispositionInformation uint8 = 13
	FilePositionInformation    uint8 = 14
	FileModeInformation        uint8 = 16
	FileAllInformation         uint8 = 18
	FileAllocationInformation  uint8 = 19
	FileEndOfFileInformation   uint8 = 20
	FileStreamInformation      uint8 = 22
	FileNetworkOpenInformation uint8 = 34
)

// ── Filesystem info classes ────────────────────────────────────────────────
const (
	FileFsVolumeInformation    uint8 = 1
	FileFsSizeInformation      uint8 = 3
	FileFsDeviceInformation    uint8 = 4
	FileFsAttributeInformation uint8 = 5
	FileFsFullSizeInformation  uint8 = 7
	FileFsObjectIdInformation  uint8 = 8
)

// ── Ioctl codes ────────────────────────────────────────────────────────────
const (
	FSCTL_DFS_GET_REFERRALS         uint32 = 0x00060194
	FSCTL_VALIDATE_NEGOTIATE_INFO   uint32 = 0x00140204
	FSCTL_CREATE_OR_GET_OBJECT_ID   uint32 = 0x000900C0
	FSCTL_QUERY_ON_DISK_VOLUME_INFO uint32 = 0x9013C
	FSCTL_PIPE_TRANSCEIVE           uint32 = 0x0011C017
	FSCTL_PIPE_WAIT                 uint32 = 0x00110040
	FSCTL_PIPE_PEEK                 uint32 = 0x0011400C
)

// ── IOCTL flags ─────────────────────────────────────────────────────────────
const (
	SMB2_0_IOCTL_IS_FSCTL uint32 = 0x00000001
)

// ── smb2Hdr holds the parsed 64-byte SMB2 header ──────────────────────────
type smb2Hdr struct {
	Command   uint16
	Status    uint32
	Flags     uint32
	MessageID uint64
	TreeID    uint32
	SessionID uint64
}

// parseHdr parses the first 64 bytes of buf as an SMB2 header.
func parseHdr(buf []byte) (*smb2Hdr, error) {
	if len(buf) < 64 {
		return nil, fmt.Errorf("packet too short: %d", len(buf))
	}
	if buf[0] != 0xFE || buf[1] != 'S' || buf[2] != 'M' || buf[3] != 'B' {
		return nil, fmt.Errorf("not SMB2 magic")
	}
	h := &smb2Hdr{}
	h.Command = le16(buf, 12)
	h.Status = le32(buf, 8)
	h.Flags = le32(buf, 16)
	h.MessageID = le64(buf, 24)
	h.TreeID = le32(buf, 36)
	h.SessionID = le64(buf, 40)
	return h, nil
}

// buildRespHdr creates a 64-byte SMB2 response header.
func buildRespHdr(cmd uint16, status uint32, msgID uint64, treeID uint32, sessID uint64) []byte {
	h := make([]byte, 64)
	h[0] = 0xFE
	h[1] = 'S'
	h[2] = 'M'
	h[3] = 'B'
	putle16(h, 4, 64) // StructureSize always 64
	putle32(h, 8, status)
	putle16(h, 12, cmd)
	putle16(h, 14, 32)         // credits granted
	putle32(h, 16, 0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	putle64(h, 24, msgID)
	putle32(h, 36, treeID)
	putle64(h, 40, sessID)
	return h
}

// errResp builds a minimal SMB2 error response (header + 8-byte body).
func errResp(h *smb2Hdr, status uint32) []byte {
	resp := make([]byte, 64+8)
	copy(resp, buildRespHdr(h.Command, status, h.MessageID, h.TreeID, h.SessionID))
	putle16(resp, 64, 9) // StructureSize = 9
	logger.Debugf("errResp: cmd=%d status=%x", h.Command, status)
	return resp
}

// wrapNetBIOS prepends a 4-byte NetBIOS session message header.
func wrapNetBIOS(data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = 0x00 // Session Message
	out[1] = byte(len(data) >> 16)
	out[2] = byte(len(data) >> 8)
	out[3] = byte(len(data))
	copy(out[4:], data)
	return out
}

// ── Binary helpers ─────────────────────────────────────────────────────────
func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func putle16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func putle32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func putle64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

// toUTF16LE converts a Go string to UTF-16LE bytes.
func toUTF16LE(s string) []byte {
	buf := make([]byte, len([]rune(s))*2)
	i := 0
	for _, r := range s {
		binary.LittleEndian.PutUint16(buf[i:], uint16(r))
		i += 2
	}
	return buf
}

// fromUTF16LE converts UTF-16LE bytes to a Go string.
func fromUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		runes = append(runes, rune(binary.LittleEndian.Uint16(b[i:])))
	}
	return string(runes)
}

// winTime converts a time.Time to a Windows FILETIME (100ns intervals since 1601-01-01).
func winTime(t time.Time) uint64 {
	// Windows FILETIME = 100ns intervals since 1601-01-01 UTC.
	// Unix epoch (1970-01-01) in FILETIME units = 116444736000000000.
	// We compute via Unix time to avoid time.Duration overflow
	// (the 1601→now span is ~425 years which overflows int64 nanoseconds).
	const unixEpochAsFiletime uint64 = 116444736000000000
	if t.IsZero() {
		return 0
	}
	// Unix seconds + sub-second 100ns units
	unix100ns := uint64(t.Unix())*10_000_000 + uint64(t.Nanosecond())/100
	return unix100ns + unixEpochAsFiletime
}

// putWinTime writes a Windows FILETIME at offset off.
func putWinTime(b []byte, off int, t time.Time) {
	putle64(b, off, winTime(t))
}

// fromWinTime converts a Windows FILETIME to time.Time. Zero means "no change".
func fromWinTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const unixEpochAsFiletime uint64 = 116444736000000000
	if ft < unixEpochAsFiletime {
		return time.Time{}
	}
	diff := ft - unixEpochAsFiletime
	sec := int64(diff / 10_000_000)
	nsec := int64((diff % 10_000_000) * 100)
	return time.Unix(sec, nsec).UTC()
}

// matchPattern does case-insensitive wildcard matching (for QueryDir).
// Supports * (any sequence) and ? (any single char).
func matchPattern(pattern, name string) bool {
	p := strings.ToLower(pattern)
	n := strings.ToLower(name)
	return wildcardMatch(p, n)
}

// wildcardMatch is an iterative greedy matcher with single-star backtracking:
// O(len(p)*len(s)) worst case. The former recursive version tried every split
// for every '*' and was exponential in the star count, so an unauthenticated
// QUERY_DIRECTORY SearchPattern like "aaaaaaaaaa*b" (many stars) pinned a CPU
// core indefinitely (GHSA-3vjf-pqxp-rwpc). Semantics are unchanged: a
// remaining pattern of exactly "*.*" matches any rest (DOS-style).
func wildcardMatch(p, s string) bool {
	pi, si := 0, 0
	starP, starS := -1, 0
	for si < len(s) {
		if pi < len(p) && p[pi] == '*' {
			if p[pi:] == "*.*" {
				return true
			}
			starP, starS = pi, si
			pi++
			continue
		}
		if pi < len(p) && (p[pi] == '?' || p[pi] == s[si]) {
			pi++
			si++
			continue
		}
		if starP >= 0 {
			starS++
			pi, si = starP+1, starS
			continue
		}
		return false
	}
	for pi < len(p) && p[pi] == '*' {
		if p[pi:] == "*.*" {
			return true
		}
		pi++
	}
	return pi == len(p)
}

// align8 rounds n up to the next multiple of 8.
func align8(n int) int {
	return (n + 7) &^ 7
}

// fileIDOffset returns the byte offset within a full SMB2 packet (from the
// start of the 64-byte header) where the 16-byte FileId field begins, for
// commands that carry a FileId in their request body. Returns -1 if the
// command does not carry a FileId (or if we don't need to patch it).
//
// These offsets are: 64 (header) + body-field-offset.
// Body-field offsets come from MS-SMB2 §2.2:
//
//	CLOSE/FLUSH/QUERY_DIRECTORY/CHANGE_NOTIFY/IOCTL: FileId at body[8]  → 72
//	READ/WRITE/SET_INFO:                              FileId at body[16] → 80
//	QUERY_INFO:                                       FileId at body[24] → 88
func fileIDOffset(cmd uint16) int {
	switch cmd {
	case SMB2_CLOSE, SMB2_FLUSH, SMB2_QUERY_DIRECTORY, SMB2_CHANGE_NOTIFY, SMB2_IOCTL:
		return 72
	case SMB2_READ, SMB2_WRITE, SMB2_SET_INFO:
		return 80
	case SMB2_QUERY_INFO:
		return 88
	}
	return -1
}
