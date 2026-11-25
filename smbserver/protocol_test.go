package smbserver

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ─── le / putle helpers ───────────────────────────────────────────────────────

func TestLe16(t *testing.T) {
	b := []byte{0x34, 0x12, 0x00, 0x00}
	require.Equal(t, uint16(0x1234), le16(b, 0))
}

func TestLe32(t *testing.T) {
	b := []byte{0x78, 0x56, 0x34, 0x12}
	require.Equal(t, uint32(0x12345678), le32(b, 0))
}

func TestLe64(t *testing.T) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, 0xDEADBEEFCAFEBABE)
	require.Equal(t, uint64(0xDEADBEEFCAFEBABE), le64(b, 0))
}

func TestPutle16(t *testing.T) {
	b := make([]byte, 4)
	putle16(b, 0, 0xABCD)
	require.Equal(t, uint16(0xABCD), le16(b, 0))
}

func TestPutle32(t *testing.T) {
	b := make([]byte, 4)
	putle32(b, 0, 0xDEADBEEF)
	require.Equal(t, uint32(0xDEADBEEF), le32(b, 0))
}

func TestPutle64(t *testing.T) {
	b := make([]byte, 8)
	putle64(b, 0, 0x0102030405060708)
	require.Equal(t, uint64(0x0102030405060708), le64(b, 0))
}

// ─── fromUTF16LE / toUTF16LE roundtrip ───────────────────────────────────────

func TestFromUTF16LE_Empty(t *testing.T) {
	require.Equal(t, "", fromUTF16LE(nil))
	require.Equal(t, "", fromUTF16LE([]byte{}))
}

func TestFromUTF16LE_ASCII(t *testing.T) {
	encoded := toUTF16LE("hello")
	require.Equal(t, "hello", fromUTF16LE(encoded))
}

func TestFromUTF16LE_Unicode(t *testing.T) {
	encoded := toUTF16LE("αβγ")
	require.Equal(t, "αβγ", fromUTF16LE(encoded))
}

func TestFromUTF16LE_OddLength(t *testing.T) {
	// Odd-length input: last byte is ignored
	b := []byte{0x41, 0x00, 0xFF}
	require.Equal(t, "A", fromUTF16LE(b))
}

// ─── wrapNetBIOS ──────────────────────────────────────────────────────────────

func TestWrapNetBIOS_Empty(t *testing.T) {
	out := wrapNetBIOS([]byte{})
	require.Equal(t, 4, len(out))
	require.Equal(t, byte(0x00), out[0])
	require.Equal(t, byte(0x00), out[1])
	require.Equal(t, byte(0x00), out[2])
	require.Equal(t, byte(0x00), out[3])
}

func TestWrapNetBIOS_SmallPayload(t *testing.T) {
	payload := []byte{0xFE, 0x53, 0x4D, 0x42}
	out := wrapNetBIOS(payload)
	require.Equal(t, 8, len(out))
	require.Equal(t, byte(0x00), out[0]) // session message type
	require.Equal(t, uint32(4), uint32(out[1])<<16|uint32(out[2])<<8|uint32(out[3]))
	require.Equal(t, payload, out[4:])
}

func TestWrapNetBIOS_LargePayload(t *testing.T) {
	// 0x10203 = 66051 bytes — exercises all three length bytes
	payload := make([]byte, 0x10203)
	out := wrapNetBIOS(payload)
	require.Equal(t, len(payload)+4, len(out))
	require.Equal(t, byte(0x01), out[1]) // high byte
	require.Equal(t, byte(0x02), out[2]) // mid byte
	require.Equal(t, byte(0x03), out[3]) // low byte
}

// ─── parseHdr ─────────────────────────────────────────────────────────────────

func TestParseHdr_TooShort(t *testing.T) {
	_, err := parseHdr(make([]byte, 32))
	require.Error(t, err)
	require.Contains(t, err.Error(), "too short")
}

func TestParseHdr_BadMagic(t *testing.T) {
	buf := make([]byte, 64)
	_, err := parseHdr(buf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not SMB2")
}

func TestParseHdr_Valid(t *testing.T) {
	buf := make([]byte, 64)
	buf[0] = 0xFE
	buf[1] = 'S'
	buf[2] = 'M'
	buf[3] = 'B'
	putle16(buf, 12, SMB2_READ)
	putle32(buf, 8, STATUS_SUCCESS)
	putle32(buf, 16, 0x00000001)
	putle64(buf, 24, 42)
	putle32(buf, 36, 7)
	putle64(buf, 40, 99)

	h, err := parseHdr(buf)
	require.NoError(t, err)
	require.Equal(t, SMB2_READ, h.Command)
	require.Equal(t, STATUS_SUCCESS, h.Status)
	require.Equal(t, uint64(42), h.MessageID)
	require.Equal(t, uint32(7), h.TreeID)
	require.Equal(t, uint64(99), h.SessionID)
}

// ─── buildRespHdr ─────────────────────────────────────────────────────────────

func TestBuildRespHdr_Magic(t *testing.T) {
	h := buildRespHdr(SMB2_NEGOTIATE, STATUS_SUCCESS, 1, 2, 3)
	require.Equal(t, byte(0xFE), h[0])
	require.Equal(t, byte('S'), h[1])
	require.Equal(t, byte('M'), h[2])
	require.Equal(t, byte('B'), h[3])
}

func TestBuildRespHdr_Fields(t *testing.T) {
	h := buildRespHdr(SMB2_SESSION_SETUP, STATUS_MORE_PROCESSING, 10, 20, 30)
	require.Equal(t, SMB2_SESSION_SETUP, le16(h, 12))
	require.Equal(t, STATUS_MORE_PROCESSING, le32(h, 8))
	require.Equal(t, uint64(10), le64(h, 24))
	require.Equal(t, uint32(20), le32(h, 36))
	require.Equal(t, uint64(30), le64(h, 40))
}

func TestBuildRespHdr_StructureSize(t *testing.T) {
	h := buildRespHdr(SMB2_NEGOTIATE, STATUS_SUCCESS, 0, 0, 0)
	require.Equal(t, uint16(64), le16(h, 4))
}

// ─── errResp ──────────────────────────────────────────────────────────────────

func TestErrResp_Length(t *testing.T) {
	hdr := &smb2Hdr{Command: SMB2_READ, MessageID: 5, TreeID: 1, SessionID: 2}
	resp := errResp(hdr, STATUS_ACCESS_DENIED)
	require.Equal(t, 72, len(resp))
}

func TestErrResp_StatusAndCommand(t *testing.T) {
	hdr := &smb2Hdr{Command: SMB2_WRITE, MessageID: 7, TreeID: 3, SessionID: 9}
	resp := errResp(hdr, STATUS_LOGON_FAILURE)
	require.Equal(t, STATUS_LOGON_FAILURE, le32(resp, 8))
	require.Equal(t, SMB2_WRITE, le16(resp, 12))
	require.Equal(t, uint16(9), le16(resp, 64)) // ErrorResponse StructureSize = 9
}

// ─── matchPattern / wildcardMatch ────────────────────────────────────────────

func TestMatchPattern_Wildcard(t *testing.T) {
	require.True(t, matchPattern("*", "anything"))
	require.True(t, matchPattern("*.*", "file.txt"))
	require.True(t, matchPattern("*.*", "noext"))
}

func TestMatchPattern_ExactMatch(t *testing.T) {
	require.True(t, matchPattern("file.txt", "file.txt"))
	require.True(t, matchPattern("FILE.TXT", "file.txt")) // case-insensitive
	require.False(t, matchPattern("file.txt", "other.txt"))
}

func TestMatchPattern_QuestionMark(t *testing.T) {
	require.True(t, matchPattern("f?le.txt", "file.txt"))
	require.False(t, matchPattern("f?le.txt", "flee.txt"))
}

func TestMatchPattern_PrefixSuffix(t *testing.T) {
	require.True(t, matchPattern("*.txt", "readme.txt"))
	require.False(t, matchPattern("*.txt", "readme.go"))
	require.True(t, matchPattern("read*", "readme.txt"))
}

func TestMatchPattern_EmptyPatternAndString(t *testing.T) {
	require.True(t, matchPattern("", ""))
	require.False(t, matchPattern("", "nonempty"))
}

func TestWildcardMatch_StarAtEnd(t *testing.T) {
	require.True(t, wildcardMatch("abc*", "abcdef"))
	require.True(t, wildcardMatch("abc*", "abc"))
	require.False(t, wildcardMatch("abc*", "ab"))
}

// ─── align8 ───────────────────────────────────────────────────────────────────

func TestAlign8(t *testing.T) {
	require.Equal(t, 0, align8(0))
	require.Equal(t, 8, align8(1))
	require.Equal(t, 8, align8(7))
	require.Equal(t, 8, align8(8))
	require.Equal(t, 16, align8(9))
	require.Equal(t, 16, align8(16))
	require.Equal(t, 24, align8(17))
}

// ─── fileIDOffset ─────────────────────────────────────────────────────────────

func TestFileIDOffset(t *testing.T) {
	cases := []struct {
		cmd    uint16
		expect int
	}{
		{SMB2_CLOSE, 72},
		{SMB2_FLUSH, 72},
		{SMB2_QUERY_DIRECTORY, 72},
		{SMB2_CHANGE_NOTIFY, 72},
		{SMB2_IOCTL, 72},
		{SMB2_READ, 80},
		{SMB2_WRITE, 80},
		{SMB2_SET_INFO, 80},
		{SMB2_QUERY_INFO, 88},
		{SMB2_NEGOTIATE, -1},
		{SMB2_SESSION_SETUP, -1},
	}
	for _, tc := range cases {
		require.Equal(t, tc.expect, fileIDOffset(tc.cmd), "cmd=0x%04x", tc.cmd)
	}
}

// ─── winTime / putWinTime ─────────────────────────────────────────────────────

func TestWinTime_Zero(t *testing.T) {
	require.Equal(t, uint64(0), winTime(time.Time{}))
}

func TestWinTime_UnixEpoch(t *testing.T) {
	// 1970-01-01 00:00:00 UTC == FILETIME 116444736000000000
	const unixEpochAsFiletime uint64 = 116444736000000000
	epoch := time.Unix(0, 0).UTC()
	require.Equal(t, unixEpochAsFiletime, winTime(epoch))
}

func TestWinTime_KnownDate(t *testing.T) {
	// 2001-01-01 00:00:00 UTC — manually computed FILETIME
	t1 := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := winTime(t1)
	// Must be greater than the Unix epoch FILETIME value
	require.Greater(t, ft, uint64(116444736000000000))
}

func TestPutWinTime(t *testing.T) {
	buf := make([]byte, 8)
	t1 := time.Unix(0, 0).UTC()
	putWinTime(buf, 0, t1)
	const unixEpochAsFiletime uint64 = 116444736000000000
	require.Equal(t, unixEpochAsFiletime, le64(buf, 0))
}

// wildcardMatchRecursive is the former exponential matcher, kept as the
// reference for the equivalence test below.
func wildcardMatchRecursive(p, s string) bool {
	if p == "*" || p == "*.*" {
		return true
	}
	if p == "" {
		return s == ""
	}
	if p[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if wildcardMatchRecursive(p[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	if len(s) == 0 {
		return false
	}
	if p[0] == '?' || p[0] == s[0] {
		return wildcardMatchRecursive(p[1:], s[1:])
	}
	return false
}

// TestWildcardMatch_EquivalentToRecursive checks the linear matcher against the
// old recursive one over every short pattern/name from a small alphabet.
func TestWildcardMatch_EquivalentToRecursive(t *testing.T) {
	patAlpha := []string{"a", "b", ".", "*", "?"}
	nameAlpha := []string{"a", "b", "."}
	var gen func(alpha []string, n int) []string
	gen = func(alpha []string, n int) []string {
		out := []string{""}
		prev := []string{""}
		for i := 0; i < n; i++ {
			var next []string
			for _, p := range prev {
				for _, c := range alpha {
					next = append(next, p+c)
				}
			}
			out = append(out, next...)
			prev = next
		}
		return out
	}
	pats := gen(patAlpha, 5)
	names := gen(nameAlpha, 5)
	for _, p := range pats {
		for _, n := range names {
			if got, want := wildcardMatch(p, n), wildcardMatchRecursive(p, n); got != want {
				t.Fatalf("wildcardMatch(%q, %q) = %v, recursive = %v", p, n, got, want)
			}
		}
	}
}

// TestWildcardMatch_PathologicalPatternIsFast is the GHSA-3vjf-pqxp-rwpc
// regression: a many-star pattern against a long non-matching name must not
// backtrack exponentially.
func TestWildcardMatch_PathologicalPatternIsFast(t *testing.T) {
	name := strings.Repeat("a", 255)
	pattern := strings.Repeat("a*", 200) + "b"
	start := time.Now()
	require.False(t, matchPattern(pattern, name))
	require.Less(t, time.Since(start), time.Second)
}
