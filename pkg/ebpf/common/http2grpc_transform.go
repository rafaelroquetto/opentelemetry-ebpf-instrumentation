// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/net/http2"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type BPFHTTP2Info BpfHttp2GrpcRequestT

type Protocol uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	HTTP2 Protocol = iota + 1
	GRPC
)

const initialHeaderTableSize = 4096

var (
	validPath        = regexp.MustCompile(`^[A-Za-z0-9\-/._~]+$`)
	validContentType = regexp.MustCompile(`^[A-Za-z\-/\+]+$`)
)

type h2Connection struct {
	hdec     *bhpack.Decoder
	hdecRet  *bhpack.Decoder
	protocol Protocol
}

func byteFramer(data []uint8) *http2.Framer {
	fr := http2.NewFramer(
		// we never write. We can save some resources
		io.Discard,
		bytes.NewReader(data))

	return fr
}

// not all requests for a given stream specify the protocol, but one must
// we remember if we see grpc mentioned and tag the rest of the streams for
// a given connection as grpc. default assumes plain HTTP2
// this is why we need the h2c cache
func getOrInitH2Conn(activeGRPCConnections *lru.Cache[uint64, h2Connection], connID uint64) *h2Connection {
	v, ok := activeGRPCConnections.Get(connID)

	dynamicTableSize := initialHeaderTableSize
	if connID == 0 {
		dynamicTableSize = 0
	}

	if !ok {
		h := h2Connection{
			hdec:     bhpack.NewDecoder(uint32(dynamicTableSize), nil),
			hdecRet:  bhpack.NewDecoder(uint32(dynamicTableSize), nil),
			protocol: HTTP2,
		}
		activeGRPCConnections.Add(connID, h)
		v, ok = activeGRPCConnections.Get(connID)
		if !ok {
			return nil
		}
	}

	return &v
}

func protocolIsGRPC(activeGRPCConnections *lru.Cache[uint64, h2Connection], connID uint64) {
	h2c := getOrInitH2Conn(activeGRPCConnections, connID)
	if h2c != nil {
		h2c.protocol = GRPC
	}
}


func isHTTPOp(op string) bool {
	return op == "GET" || op == "POST" || op == "PATCH" || op == "DELETE" || op == "OPTIONS" || op == "HEAD"
}

func handleHeaderField(hf *bhpack.HeaderField) bool {
	switch hf.Name {
	case ":method":
		if isHTTPOp(hf.Value) {
			return true
		}
	case ":scheme":
		if hf.Value == "http" {
			return true
		}
	case "traceparent":
		return true
	case ":path":
		val := hf.Value
		if pos := strings.Index(val, "?"); pos >= 0 {
			val = val[:pos]
		}
		if validPath.MatchString(val) {
			return true
		}
	case "content-type":
		val := hf.Value
		if validContentType.MatchString(val) {
			return true
		}
	case "grpc-status":
		return true
	case ":status":
		return true
	}

	return false
}

func knownFrameKeys(fr *http2.Framer, hf *http2.HeadersFrame) bool {
	knownCount := 0
	dec := bhpack.NewDecoder(initialHeaderTableSize, nil)
	dec.SetEmitFunc(func(hf bhpack.HeaderField) {
		if handleHeaderField(&hf) {
			knownCount++
		}
	})
	defer dec.Close()

	frag := hf.HeaderBlockFragment()
	for {
		if _, err := dec.Write(frag); err != nil {
			break
		}
		if hf.HeadersEnded() {
			break
		}
		hff, err := fr.ReadFrame()
		if err != nil {
			break
		}
		cf, ok := hff.(*http2.ContinuationFrame)
		if !ok {
			break
		}
		frag = cf.HeaderBlockFragment()
	}

	return knownCount >= 1
}

func readMetaFrame(parseContext *EBPFParseContext, connID uint64, fr *http2.Framer, hf *http2.HeadersFrame) (string, string, string, bool) {
	h2c := getOrInitH2Conn(parseContext.h2c, connID)

	ok := false
	method := ""
	path := ""
	contentType := ""

	if h2c == nil {
		return method, path, contentType, ok
	}

	h2c.hdec.SetEmitFunc(func(hf bhpack.HeaderField) {
		switch hf.Name {
		case ":method":
			method = hf.Value
			ok = true
		case ":path":
			path = hf.Value
			ok = true
		case "content-type":
			contentType = hf.Value
			if contentType == "application/grpc" {
				protocolIsGRPC(parseContext.h2c, connID)
			}
			ok = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdec.SetEmitFunc(func(_ bhpack.HeaderField) {})
	defer h2c.hdec.Close()

	frag := hf.HeaderBlockFragment()
	for {
		if _, err := h2c.hdec.Write(frag); err != nil {
			return method, path, contentType, ok
		}
		if hf.HeadersEnded() {
			break
		}
		hff, err := fr.ReadFrame()
		if err != nil {
			break
		}
		cf, ok := hff.(*http2.ContinuationFrame)
		if !ok {
			break
		}
		frag = cf.HeaderBlockFragment()
	}

	return method, path, contentType, ok
}

func http2grpcStatus(status int) int {
	if status < 100 {
		return status
	}
	if status < 400 {
		return 0
	}

	return 2 // Unknown
}

func readRetMetaFrame(parseContext *EBPFParseContext, connID uint64, fr *http2.Framer, hf *http2.HeadersFrame) (int, bool, bool) {
	h2c := getOrInitH2Conn(parseContext.h2c, connID)

	ok := false
	status := 0
	grpc := false

	if h2c == nil {
		return status, grpc, ok
	}

	h2c.hdecRet.SetEmitFunc(func(hf bhpack.HeaderField) {
		// grpc requests may have :status and grpc-status. :status will be HTTP code.
		// we prefer the grpc one if it exists, it's always later since : tagged headers
		// end up first in the headers list.
		switch hf.Name {
		case ":status":
			if !grpc { // only set the HTTP status if we didn't find grpc status
				status, _ = strconv.Atoi(hf.Value)
			}
			ok = true
		case "grpc-status":
			status, _ = strconv.Atoi(hf.Value)
			protocolIsGRPC(parseContext.h2c, connID)
			grpc = true
			ok = true
		case "grpc-message":
			if hf.Value != "" {
				if !grpc { // unset or we have the HTTP status
					status = 2
				}
			}
			protocolIsGRPC(parseContext.h2c, connID)
			grpc = true
			ok = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdecRet.SetEmitFunc(func(_ bhpack.HeaderField) {})
	defer h2c.hdecRet.Close()

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := h2c.hdecRet.Write(frag); err != nil {
			return status, grpc, ok
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return status, grpc, ok
		}
	}

	return status, grpc, ok
}

func http2InfoToSpan(info *BPFHTTP2Info, method, path, peer, host string, status int, protocol Protocol) request.Span {
	return request.Span{
		Type:          info.eventType(protocol),
		Method:        method,
		Path:          removeQuery(path),
		Peer:          peer,
		PeerPort:      int(info.ConnInfo.S_port),
		Host:          host,
		HostPort:      int(info.ConnInfo.D_port),
		ContentLength: int64(info.Len),
		RequestStart:  int64(info.StartMonotimeNs),
		Start:         int64(info.StartMonotimeNs),
		End:           int64(info.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.TraceID(info.Tp.TraceId),
		SpanID:        trace.SpanID(info.Tp.SpanId),
		ParentSpanID:  trace.SpanID(info.Tp.ParentId),
		TraceFlags:    info.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(info.Pid.HostPid),
			UserPID:   app.PID(info.Pid.UserPid),
			Namespace: info.Pid.Ns,
		},
	}
}

// The eBPF kernel side gives us information only if the event type is server or client. We reuse what's
// done for HTTP 1.1. We figure out what the protocol is by looking at the response status, is it :grpc-status,
// or :status. Then we know what the protocol actually is.
func (event *BPFHTTP2Info) eventType(protocol Protocol) request.EventType {
	eventType := request.EventType(event.Type)

	switch protocol {
	case HTTP2:
		return eventType // just use HTTP as is, no special handling
	case GRPC:
		switch eventType {
		case request.EventTypeHTTP:
			return request.EventTypeGRPC
		case request.EventTypeHTTPClient:
			return request.EventTypeGRPCClient
		}
	}

	return 0
}

func readFrameHeader(buf []byte) (http2.FrameHeader, error) {
	if len(buf) < frameHeaderLen {
		return http2.FrameHeader{}, errors.New("EOF")
	}
	return http2.FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2.FrameType(buf[3]),
		Flags:    http2.Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
	}, nil
}

// parseHTTP2Frames is the shared core for HTTP/2 frame scanning and HPACK decoding.
// requestData is mutable — it may be modified to fix up partial-buffer frame lengths.
//
//nolint:cyclop
func parseHTTP2Frames(
	parseCtx *EBPFParseContext,
	requestData []byte,
	requestLen int,
	responseData []byte,
	connID uint64,
	ssl uint8,
) (method, path string, status int, protocol Protocol, streamID uint32, ok, responseFound bool) {
	protocol = HTTP2

	bLen := min(requestLen, len(requestData))
	framer := byteFramer(requestData[:bLen])
	retFramer := byteFramer(responseData)

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			fail := true
			if strings.Contains(err.Error(), "unexpected EOF") && bLen > frameHeaderLen {
				fh, ferr := readFrameHeader(requestData[:bLen])
				if ferr == nil && fh.Length > uint32(bLen-frameHeaderLen) {
					newLen := min(bLen-frameHeaderLen, 255)
					requestData[0] = 0
					requestData[1] = 0
					requestData[2] = uint8(newLen)
					framer = byteFramer(requestData[:bLen])
					f, err = framer.ReadFrame()
					if err == nil {
						fail = false
					}
				}
			}
			if fail {
				break
			}
		}

		if ff, ffOK := f.(*http2.HeadersFrame); ffOK {
			rok := false
			streamID = ff.StreamID
			var contentType string
			method, path, contentType, ok = readMetaFrame(parseCtx, connID, framer, ff)
			if pos := strings.Index(path, "?"); pos >= 0 {
				path = path[:pos]
			}
			if path == "" || !validPath.MatchString(path) {
				path = "*"
			}

			grpcInStatus := false
			for {
				retF, retErr := retFramer.ReadFrame()
				if retErr != nil {
					break
				}
				if rff, rfOK := retF.(*http2.HeadersFrame); rfOK {
					status, grpcInStatus, rok = readRetMetaFrame(parseCtx, connID, retFramer, rff)
					break
				}
			}

			if !ok && !rok {
				return
			}

			responseFound = rok

			if protocol != GRPC && (grpcInStatus || contentType == "application/grpc" || (contentType == "" && ssl == 0)) {
				protocol = GRPC
				status = http2grpcStatus(status)
			}

			ok = true
			return
		}
	}

	// No HEADERS in the request buffer — try the response buffer independently.
	// This handles the second TCP event on an HTTP/2 connection where the client
	// sends a SETTINGS-ACK and the server sends the actual response HEADERS.
	for {
		retF, retErr := retFramer.ReadFrame()
		if retErr != nil {
			break
		}
		if rff, rfOK := retF.(*http2.HeadersFrame); rfOK {
			streamID = rff.StreamID
			var grpcInStatus bool
			status, grpcInStatus, ok = readRetMetaFrame(parseCtx, connID, retFramer, rff)
			if ok {
				responseFound = true
				if grpcInStatus {
					protocol = GRPC
					status = http2grpcStatus(status)
				}
			}
			break
		}
	}

	return
}

func http2FromBuffers(parseContext *EBPFParseContext, event *BPFHTTP2Info) (request.Span, bool, error) {
	bLen := len(event.Data)
	if event.Len < int32(bLen) {
		bLen = int(event.Len)
	}

	method, path, status, protocol, _, ok, _ := parseHTTP2Frames(
		parseContext, event.Data[:], bLen, event.RetData[:], event.NewConnId, event.Ssl)
	if !ok {
		return request.Span{}, true, nil
	}

	peer := ""
	host := ""
	if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
		source, target := (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()
		host = target
		peer = source
	}

	return http2InfoToSpan(event, method, path, peer, host, status, protocol), false, nil
}

// http2StreamKey identifies a single HTTP/2 stream for pending span correlation.
// Stream IDs are per-connection and odd for client-initiated streams, so keying
// on both connID and streamID is required to handle concurrent streams correctly.
type http2StreamKey struct {
	connID   uint64
	streamID uint32
}

// pendingHTTP2Span holds partial HTTP/2 span state when the request HEADERS and
// response HEADERS arrive in separate TCP events (the common socktracer case).
type pendingHTTP2Span struct {
	method string
	path   string
	proto  Protocol
	peer   string
	host   string
	event  TCPRequestInfo
}

// http2PrefaceLen is the byte length of the HTTP/2 client connection preface.
const http2PrefaceLen = 24

// tcpConnInfoID derives a stable uint64 connection ID from the 4-tuple for HPACK state keying.
func tcpConnInfoID(conn *BpfConnectionInfoT) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(conn.S_addr[:])
	_, _ = h.Write(conn.D_addr[:])
	_, _ = h.Write([]byte{byte(conn.S_port >> 8), byte(conn.S_port)})
	_, _ = h.Write([]byte{byte(conn.D_port >> 8), byte(conn.D_port)})
	return h.Sum64()
}

func http2TCPToSpan(event *TCPRequestInfo, method, path, peer, host string, status int, protocol Protocol) request.Span {
	eventType := request.EventTypeHTTP
	if !event.IsServer {
		eventType = request.EventTypeHTTPClient
	}
	if protocol == GRPC {
		if event.IsServer {
			eventType = request.EventTypeGRPC
		} else {
			eventType = request.EventTypeGRPCClient
		}
	}

	return request.Span{
		Type:          eventType,
		Method:        method,
		Path:          removeQuery(path),
		Peer:          peer,
		PeerPort:      int(event.ConnInfo.S_port),
		Host:          host,
		HostPort:      int(event.ConnInfo.D_port),
		ContentLength: int64(event.Len),
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}
}

// http2SpanFromTCPEvent parses HTTP/2 from a socktracer tcp_req_t event.
// The client connection preface (if present) is stripped before frame parsing.
func http2SpanFromTCPEvent(parseCtx *EBPFParseContext, event *TCPRequestInfo, reqBuf, respBuf *largebuf.LargeBuffer) (request.Span, bool, error) {
	connID := tcpConnInfoID(&event.ConnInfo)

	reqData := reqBuf.UnsafeView()

	// Strip the 24-byte HTTP/2 client connection preface when present — the
	// http2.Framer cannot read it since it is unframed raw bytes.
	// The preface appears in buf regardless of whether we instrument the client or server side.
	if len(reqData) >= http2PrefaceLen &&
		bytes.Equal(reqData[:http2PrefaceLen], []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		reqData = reqData[http2PrefaceLen:]
	}

	method, path, status, proto, streamID, ok, responseFound := parseHTTP2Frames(
		parseCtx, reqData, len(reqData), respBuf.UnsafeView(), connID, event.Ssl)
	if !ok {
		return request.Span{}, true, nil
	}

	peer := ""
	host := ""
	if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
		source, target := (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()
		host = target
		peer = source
	}

	skey := http2StreamKey{connID: connID, streamID: streamID}

	if method != "" && !responseFound {
		// Request HEADERS found but no response yet — defer until the response arrives.
		parseCtx.pendingHTTP2.Add(skey, pendingHTTP2Span{
			method: method,
			path:   path,
			proto:  proto,
			peer:   peer,
			host:   host,
			event:  *event,
		})
		return request.Span{}, true, nil
	}

	if method == "" && responseFound {
		// Response HEADERS found but no request — look up a deferred span for this stream.
		if pending, found := parseCtx.pendingHTTP2.Get(skey); found {
			parseCtx.pendingHTTP2.Remove(skey)
			pendingEvent := pending.event
			pendingEvent.EndMonotimeNs = event.EndMonotimeNs
			if proto == GRPC {
				pending.proto = GRPC
			}
			return http2TCPToSpan(&pendingEvent, pending.method, pending.path, pending.peer, pending.host, status, pending.proto), false, nil
		}
		return request.Span{}, true, nil
	}

	// Both request and response HEADERS in the same event.
	parseCtx.pendingHTTP2.Remove(skey)
	return http2TCPToSpan(event, method, path, peer, host, status, proto), false, nil
}

func ReadHTTP2BufferIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	pkt := largebuf.NewLargeBufferFrom(event.Buf[:l])
	empty := largebuf.NewLargeBufferFrom(event.Buf[:0])

	// TCP_SEND (directionSend=1) = request direction; TCP_RECV (directionRecv=0) = response direction.
	if event.Direction == directionSend {
		return http2SpanFromTCPEvent(parseCtx, event, pkt, empty)
	}
	return http2SpanFromTCPEvent(parseCtx, event, empty, pkt)
}

func ReadHTTP2InfoIntoSpan(parseContext *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BPFHTTP2Info](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	return http2FromBuffers(parseContext, event)
}

type http2FrameType uint8

type frameHeader struct {
	Length   uint32
	Type     http2FrameType
	Flags    uint8
	Ignore   uint8
	StreamID uint32
}

const (
	FrameData         http2FrameType = 0x0
	FrameHeaders      http2FrameType = 0x1
	FramePriority     http2FrameType = 0x2
	FrameRSTStream    http2FrameType = 0x3
	FrameSettings     http2FrameType = 0x4
	FramePushPromise  http2FrameType = 0x5
	FramePing         http2FrameType = 0x6
	FrameGoAway       http2FrameType = 0x7
	FrameWindowUpdate http2FrameType = 0x8
	FrameContinuation http2FrameType = 0x9
)

const frameHeaderLen = 9

func readHTTP2Frame(buf []uint8, length int) (*frameHeader, bool) {
	if length < frameHeaderLen {
		return nil, false
	}

	frame := frameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    buf[4],
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
	}

	if frame.Type > FrameContinuation {
		return nil, false
	}

	return &frame, true
}

func isHeadersFrame(frame *frameHeader) bool {
	return frame.Type == FrameHeaders && frame.StreamID != 0
}

func isInvalidFrame(frame *frameHeader) bool {
	return frame.Length == 0 && frame.Type == FrameData
}

func isLikelyHTTP2(data []uint8, eventLen int) bool {
	pos := 0
	l := min(eventLen, len(data))
	for range 8 {
		if pos > l-frameHeaderLen {
			break
		}

		fr, ok := readHTTP2Frame(data[pos:], l)
		if !ok {
			break
		}

		if isHeadersFrame(fr) {
			return true
		}

		if isInvalidFrame(fr) {
			break
		}

		if pos < (l - int(fr.Length+frameHeaderLen)) {
			pos += int(fr.Length + frameHeaderLen)
			continue
		}

		break
	}

	return false
}

func isHTTP2(data *largebuf.LargeBuffer, eventLen int) bool {
	// Parsing HTTP2 frames with the Go HTTP2/gRPC parser is very expensive.
	// Therefore, we replicate some of our HTTP2 frame reader from eBPF here to
	// check if this payload even remotely looks like HTTP2/gRPC, e.g. we must
	// find a resonably looking HTTP "headers" frame.
	raw := data.UnsafeView()

	// Strip the HTTP/2 client connection preface — it is not a framed payload
	// and causes the frame scanner to fail immediately.
	if len(raw) >= http2PrefaceLen && string(raw[:http2PrefaceLen]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		raw = raw[http2PrefaceLen:]
		eventLen -= http2PrefaceLen
	}

	if !isLikelyHTTP2(raw, eventLen) {
		return false
	}

	framer := http2.NewFramer(io.Discard, bytes.NewReader(raw))

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			return knownFrameKeys(framer, ff)
		}
	}

	return false
}
