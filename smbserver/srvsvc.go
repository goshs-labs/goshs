package smbserver

import (
	"bytes"
	"encoding/binary"
	"strings"

	"goshs.de/goshs/v2/logger"
)

// ── DCE/RPC packet types ───────────────────────────────────────────────────
const (
	rpcBind     byte = 11
	rpcBindAck  byte = 12
	rpcRequest  byte = 0
	rpcResponse byte = 2
	rpcFault    byte = 3
)

// SRVSVC interface UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188, v3.0
var srvsvcUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

// NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860, v2
var ndrUUID = [16]byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

const (
	srvsvcOpNetShareEnumAll = 15
)

// handlePipeWrite processes one or more DCE/RPC PDUs written to a named pipe
// handle in a single SMB2 WRITE. Windows frequently concatenates a Bind PDU
// and a Request PDU in the same write; we process all of them and concatenate
// their responses so the READ returns the full reply.
func (s *SMBServer) handlePipeWrite(handle *smbHandle, data []byte) []byte {
	// Dump the full PDU (up to 200 bytes) so we can see all 3 contexts.
	dumpLen := min(len(data), 200)
	logger.Debugf("SMB: pipeWrite pipe=%q dataLen=%d hdr=%X", handle.PipeName, len(data), data[:dumpLen])

	var out []byte
	for len(data) >= 16 {
		fragLen := int(binary.LittleEndian.Uint16(data[8:10]))
		logger.Debugf("SMB: pipeWrite pdu pktType=0x%02X fragLen=%d totalData=%d", data[2], fragLen, len(data))
		if fragLen < 16 || fragLen > len(data) {
			logger.Debugf("SMB: pipeWrite fragLen out of range — stopping")
			break
		}
		pdu := data[:fragLen]
		data = data[fragLen:]

		pktType := pdu[2]
		callID := binary.LittleEndian.Uint32(pdu[12:16])

		var resp []byte
		switch pktType {
		case rpcBind:
			resp = s.buildBindAck(callID, pdu, handle.PipeName)
			if resp != nil {
				dumpB := min(len(resp), 256)
				logger.Debugf("SMB: pipeWrite BindAck len=%d full=%X", len(resp), resp[:dumpB])
			}
		case rpcRequest:
			resp = s.handleRPCRequest(handle, callID, pdu)
		default:
			logger.Debugf("SMB: pipeWrite unhandled pktType=0x%02X", pktType)
		}
		if resp != nil {
			out = append(out, resp...)
		}
	}
	return out
}

// buildBindAck responds to a DCE/RPC Bind request.
// Windows sends n_context_elem contexts; we must return exactly that many
// results or it discards the BindAck and retries indefinitely.
// MS-RPCE 3.3.3.5.3.2: the client MUST verify the secondary address matches
// the pipe endpoint — wrong sec_addr causes the client to abort immediately.
func (s *SMBServer) buildBindAck(callID uint32, req []byte, pipePath string) []byte {
	// Bind body layout after the 16-byte header:
	//   max_xmit_frag(2) + max_recv_frag(2) + assoc_group_id(4)
	//   n_context_elem(2) + reserved(2) + context items
	// n_context_elem is at byte offset 24 of the full PDU.
	nCtx := uint16(1)
	if len(req) >= 26 {
		nCtx = binary.LittleEndian.Uint16(req[24:26])
		if nCtx == 0 {
			nCtx = 1
		}
	}

	// Parse bind request contexts to find which one proposes NDR transfer syntax.
	// Context elements start at offset 28 of the PDU.
	// Each context: p_cont_id(2) + n_transfer_syn(2) + abstract_syntax(20) + xfer(n*20)
	acceptCtx := -1
	ctxOff := 28
	for i := 0; i < int(nCtx); i++ {
		if ctxOff+24 > len(req) {
			break
		}
		contID := binary.LittleEndian.Uint16(req[ctxOff : ctxOff+2])
		nXfer := int(binary.LittleEndian.Uint16(req[ctxOff+2 : ctxOff+4]))
		absUUID := req[ctxOff+4 : ctxOff+20]
		absVer := binary.LittleEndian.Uint32(req[ctxOff+20 : ctxOff+24])
		logger.Debugf("SMB: Bind ctx[%d] contID=%d nXfer=%d absUUID=%X absVer=%d",
			i, contID, nXfer, absUUID, absVer)

		// Check each transfer syntax for NDR match
		xferOff := ctxOff + 24
		for j := range nXfer {
			if xferOff+20 > len(req) {
				break
			}
			xferUUID := req[xferOff : xferOff+16]
			xferVer := binary.LittleEndian.Uint32(req[xferOff+16 : xferOff+20])
			logger.Debugf("SMB: Bind ctx[%d] xfer[%d] UUID=%X ver=%d", i, j, xferUUID, xferVer)
			if bytes.Equal(xferUUID, ndrUUID[:]) && xferVer == 2 && acceptCtx < 0 {
				acceptCtx = i
			}
			xferOff += 20
		}
		ctxOff += 24 + nXfer*20
	}
	// Fallback: if no context proposes NDR, accept context 0 (best effort)
	if acceptCtx < 0 {
		acceptCtx = 0
		logger.Debugf("SMB: Bind no NDR context found, falling back to ctx[0]")
	} else {
		logger.Debugf("SMB: Bind accepting ctx[%d] with NDR transfer syntax", acceptCtx)
	}

	// Secondary address: use the actual pipe name so Windows validates it correctly.
	pipeName := pipePath
	if idx := strings.LastIndex(pipePath, "\\"); idx >= 0 {
		pipeName = pipePath[idx+1:]
	}
	if pipeName == "" {
		pipeName = "srvsvc"
	}
	secAddr := []byte("\\PIPE\\" + pipeName + "\x00")
	// Pad (length-field + string) to 4-byte alignment.
	totalSecAddr := 2 + len(secAddr)
	pad := (4 - totalSecAddr%4) % 4

	var body []byte
	// MaxXmitFrag / MaxRecvFrag
	body = append(body, 0xb8, 0x10, 0xb8, 0x10)
	// AssocGroupId: must be non-zero when client sends 0 (server allocates new group)
	body = append(body, 0x01, 0x00, 0x00, 0x00)
	// SecondaryAddress: uint16 length + string + alignment pad
	body = append(body, byte(len(secAddr)), 0x00)
	body = append(body, secAddr...)
	body = append(body, make([]byte, pad)...)

	// p_result_list: MS-RPCE 2.2.2.4 — n_results(uint8) + reserved(uint8) + reserved2(uint16)
	body = append(body, byte(nCtx)) // n_results (uint8)
	body = append(body, 0x00)       // reserved
	body = append(body, 0x00, 0x00) // reserved2

	// Build result entries: accept the matching context, reject the rest
	for i := uint16(0); i < nCtx; i++ {
		if int(i) == acceptCtx {
			body = append(body, 0x00, 0x00) // result: acceptance
			body = append(body, 0x00, 0x00) // reason: not_specified
			body = append(body, ndrUUID[:]...)
			body = append(body, 0x02, 0x00, 0x00, 0x00) // transfer syntax version 2
		} else {
			body = append(body, 0x02, 0x00)          // result: provider_rejection
			body = append(body, 0x02, 0x00)          // reason: proposed_transfer_syntaxes_not_supported
			body = append(body, make([]byte, 20)...) // null transfer syntax UUID + version
		}
	}

	return buildRPCHeader(rpcBindAck, callID, body)
}

const (
	srvsvcOpNetShareGetInfo        = 16
	srvsvcOpNetServerGetInfo       = 13
	srvsvcOpNetServerTransportEnum = 21
	wkssvcOpNetWkstaGetInfo        = 0
)

// handleRPCRequest dispatches an RPC request by opnum.
func (s *SMBServer) handleRPCRequest(handle *smbHandle, callID uint32, req []byte) []byte {
	if len(req) < 24 {
		return buildRPCFault(callID)
	}
	opnum := binary.LittleEndian.Uint16(req[22:24])
	stub := req[24:]
	pipeName := strings.ToLower(strings.TrimLeft(strings.ReplaceAll(handle.PipeName, "\\", "/"), "/"))

	logger.Debugf("SMB: RPC pipe=%s opnum=%d callID=%d", handle.PipeName, opnum, callID)

	switch pipeName {
	case "srvsvc", "pipe/srvsvc":
		switch opnum {
		case srvsvcOpNetShareEnumAll:
			return s.handleNetShareEnumAll(callID, stub)
		case srvsvcOpNetShareGetInfo:
			return s.handleNetShareGetInfo(callID, stub)
		case srvsvcOpNetServerGetInfo:
			return s.handleNetServerGetInfo(callID, stub)
		case srvsvcOpNetServerTransportEnum:
			return s.handleNetServerTransportEnum(callID)
		default:
			logger.Debugf("SMB: srvsvc unknown opnum=%d", opnum)
			return buildRPCFault(callID)
		}
	case "wkssvc", "pipe/wkssvc":
		switch opnum {
		case wkssvcOpNetWkstaGetInfo:
			return s.handleNetWkstaGetInfo(callID, stub)
		default:
			logger.Debugf("SMB: wkssvc unknown opnum=%d", opnum)
			return buildRPCFault(callID)
		}
	default:
		logger.Debugf("SMB: RPC unknown pipe %q opnum=%d", handle.PipeName, opnum)
		return buildRPCFault(callID)
	}
}

// handleNetShareEnumAll builds a NetShareEnumAll response listing our shares.
// We return SHARE_INFO_1 level (type + name + comment).
func (s *SMBServer) handleNetShareEnumAll(callID uint32, stub []byte) []byte {
	// Shares to advertise
	type shareEntry struct {
		name    string
		stype   uint32 // 0=disk, 3=IPC
		comment string
	}
	shares := []shareEntry{
		{s.ShareName, 0, "goshs file share"},
		{"IPC$", 3, "IPC Service"},
	}

	// NDR encode SHARE_INFO_1_CONTAINER
	// We build the response stub manually in little-endian NDR format.
	var stub2 []byte

	// Level = 1  (SHARE_ENUM_STRUCT.Level)
	stub2 = putle32Slice(stub2, 1)
	// Non-encapsulated union discriminant (SHARE_ENUM_UNION switch value = Level)
	stub2 = putle32Slice(stub2, 1)
	// Level1 container pointer (non-null referent)
	stub2 = putle32Slice(stub2, 1)
	// Count
	stub2 = putle32Slice(stub2, uint32(len(shares)))
	// Array pointer (non-null)
	stub2 = putle32Slice(stub2, 0x00020004)
	// Max count for conformant array
	stub2 = putle32Slice(stub2, uint32(len(shares)))

	// Array of SHARE_INFO_1 structs (name_ptr, type, remark_ptr)
	for i := range shares {
		// name pointer (unique ptr, use index+1 as referent)
		stub2 = putle32Slice(stub2, uint32(0x00040008+i*4))
		// type
		stub2 = putle32Slice(stub2, shares[i].stype)
		// remark pointer
		stub2 = putle32Slice(stub2, uint32(0x00060010+i*4))
	}

	// Deferred referents: NDR emits referents in the order pointers were encountered
	// (struct-by-struct, field-by-field), so name then remark for each share.
	for _, sh := range shares {
		stub2 = ndrString(stub2, sh.name)
		stub2 = ndrString(stub2, sh.comment)
	}

	// TotalEntries
	stub2 = putle32Slice(stub2, uint32(len(shares)))
	// ResumeHandle pointer (null)
	stub2 = putle32Slice(stub2, 0)
	// Return code: NERR_Success
	stub2 = putle32Slice(stub2, 0)

	return buildRPCResponse(callID, 0, stub2)
}

// ── NDR helpers ────────────────────────────────────────────────────────────

// ndrString appends an NDR conformant/varying string (UTF-16LE).
func ndrString(buf []byte, s string) []byte {
	utf16 := toUTF16LE(s + "\x00") // include null terminator
	count := uint32(len(utf16) / 2)
	buf = putle32Slice(buf, count) // MaxCount
	buf = putle32Slice(buf, 0)     // Offset
	buf = putle32Slice(buf, count) // ActualCount
	buf = append(buf, utf16...)
	// Align to 4 bytes
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func putle32Slice(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

// ── DCE/RPC framing ────────────────────────────────────────────────────────

func buildRPCHeader(pktType byte, callID uint32, body []byte) []byte {
	fragLen := uint16(16 + len(body))
	hdr := []byte{
		5, 0, // Version 5.0
		pktType,                // PacketType
		0x03,                   // Flags: first+last fragment
		0x10, 0x00, 0x00, 0x00, // DataRepresentation: little-endian
	}
	hdr = append(hdr, byte(fragLen), byte(fragLen>>8)) // FragLength
	hdr = append(hdr, 0x00, 0x00)                      // AuthLength
	hdr = append(hdr, byte(callID), byte(callID>>8), byte(callID>>16), byte(callID>>24))
	return append(hdr, body...)
}

func buildRPCResponse(callID uint32, ctxID uint16, stub []byte) []byte {
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // AllocHint
		byte(ctxID), byte(ctxID >> 8), // ContextID
		0x00, 0x00, // CancelCount + reserved
	}
	// Patch AllocHint
	binary.LittleEndian.PutUint32(body[0:], uint32(len(stub)))
	body = append(body, stub...)
	return buildRPCHeader(rpcResponse, callID, body)
}

func buildRPCFault(callID uint32) []byte {
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // AllocHint
		0x00, 0x00, // ContextID
		0x00,                   // CancelCount
		0x00,                   // reserved
		0x1c, 0x00, 0x1c, 0x00, // status: nca_s_op_rng_error
	}
	return buildRPCHeader(rpcFault, callID, body)
}

// handleNetShareGetInfo returns SHARE_INFO_1 for any requested share name.
// Windows calls this (opnum 16) to validate individual shares after EnumAll.
func (s *SMBServer) handleNetShareGetInfo(callID uint32, stub []byte) []byte {
	// We return goshs info regardless of the requested share name.
	var out []byte
	out = putle32Slice(out, 1)          // Level = 1
	out = putle32Slice(out, 0x00020000) // pointer to SHARE_INFO_1 (non-null)

	// SHARE_INFO_1 referent
	out = putle32Slice(out, 0x00040004) // shi1_netname pointer
	out = putle32Slice(out, 0)          // shi1_type = 0 (STYPE_DISKTREE)
	out = putle32Slice(out, 0x00060008) // shi1_remark pointer

	// Deferred strings: name then remark
	out = ndrString(out, s.ShareName)
	out = ndrString(out, "goshs file share")

	// Return value
	out = putle32Slice(out, 0) // NERR_Success
	return buildRPCResponse(callID, 0, out)
}

// handleNetServerGetInfo returns a minimal SERVER_INFO_101 response.
// Windows calls this (opnum 13) to learn the server platform/version.
func (s *SMBServer) handleNetServerGetInfo(callID uint32, stub []byte) []byte {
	// SERVER_INFO_101 at level 101
	var out []byte
	out = putle32Slice(out, 101)        // Level = 101
	out = putle32Slice(out, 0x00020000) // pointer to SERVER_INFO_101

	// SERVER_INFO_101 referent
	out = putle32Slice(out, 500)        // sv101_platform_id = PLATFORM_ID_NT
	out = putle32Slice(out, 0x00040004) // sv101_name pointer
	out = putle32Slice(out, 5)          // sv101_version_major
	out = putle32Slice(out, 2)          // sv101_version_minor
	out = putle32Slice(out, 0x00009003) // sv101_type = SV_TYPE_SERVER|WORKSTATION|NT
	out = putle32Slice(out, 0x00060008) // sv101_comment pointer

	// Deferred strings: server name then comment
	out = ndrString(out, s.ServerName)
	out = ndrString(out, "")

	// Return value
	out = putle32Slice(out, 0) // NERR_Success
	return buildRPCResponse(callID, 0, out)
}

// handleNetServerTransportEnum returns an empty transport list.
// Windows calls this (opnum 21 / NetServerTransportEnum) during share discovery.
func (s *SMBServer) handleNetServerTransportEnum(callID uint32) []byte {
	var out []byte
	// InfoStruct pointer (non-null) + Level = 0
	out = putle32Slice(out, 0x00020000) // pointer to SERVER_TRANSPORT_INFO_0_CONTAINER
	// SERVER_TRANSPORT_INFO_0_CONTAINER referent: EntriesRead = 0, Buffer = NULL
	out = putle32Slice(out, 0) // EntriesRead = 0
	out = putle32Slice(out, 0) // Buffer pointer (NULL)
	// TotalEntries
	out = putle32Slice(out, 0)
	// ResumeHandle pointer (NULL)
	out = putle32Slice(out, 0)
	// Return value: NERR_Success
	out = putle32Slice(out, 0)
	return buildRPCResponse(callID, 0, out)
}

// handleNetWkstaGetInfo returns a minimal WKSTA_INFO_100 response.
// Windows calls this (opnum 0) to learn the workstation platform/version.
func (s *SMBServer) handleNetWkstaGetInfo(callID uint32, stub []byte) []byte {
	var out []byte
	out = putle32Slice(out, 100)        // Level = 100
	out = putle32Slice(out, 0x00020000) // pointer to WKSTA_INFO_100

	// WKSTA_INFO_100 referent
	out = putle32Slice(out, 500)        // wki100_platform_id = PLATFORM_ID_NT
	out = putle32Slice(out, 0x00040004) // wki100_computername pointer
	out = putle32Slice(out, 0x00060008) // wki100_langroup pointer
	out = putle32Slice(out, 10)         // wki100_ver_major
	out = putle32Slice(out, 0)          // wki100_ver_minor

	// Deferred strings: computername then langroup
	out = ndrString(out, s.ServerName)
	out = ndrString(out, "WORKGROUP")

	// Return value
	out = putle32Slice(out, 0) // NERR_Success
	return buildRPCResponse(callID, 0, out)
}

// isPipeName returns true if the given SMB path refers to a named pipe.
func isPipeName(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	path = strings.TrimPrefix(path, "/")
	return strings.HasPrefix(path, "pipe/") || path == "srvsvc" ||
		strings.HasSuffix(path, "/srvsvc") ||
		strings.HasSuffix(path, "/svcctl") ||
		strings.HasSuffix(path, "/samr") ||
		strings.HasSuffix(path, "/lsarpc")
}
