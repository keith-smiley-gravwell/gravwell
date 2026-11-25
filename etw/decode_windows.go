//go:build windows && (amd64 || arm64)

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TDH in/out types used for typed (non string) rendering, see tdh.h
const (
	tdhInTypeUnicodeString = 1
	tdhInTypeAnsiString    = 2
	tdhInTypeInt8          = 3
	tdhInTypeUint8         = 4
	tdhInTypeInt16         = 5
	tdhInTypeUint16        = 6
	tdhInTypeInt32         = 7
	tdhInTypeUint32        = 8
	tdhInTypeInt64         = 9
	tdhInTypeUint64        = 10
	tdhInTypeFloat         = 11
	tdhInTypeDouble        = 12
	tdhInTypeBoolean       = 13
	tdhInTypeBinary        = 14
	tdhInTypeGUID          = 15
	tdhInTypePointer       = 16
	tdhInTypeFiletime      = 17
	tdhInTypeSystemtime    = 18
	tdhInTypeSID           = 19
	tdhInTypeHexInt32      = 20
	tdhInTypeHexInt64      = 21
	tdhInTypeWbemSID       = 310

	// TDH_OUT_TYPE values
	tdhOutTypeNull         = 0
	tdhOutTypeByte         = 3
	tdhOutTypeUnsignedLong = 10
	tdhOutTypeHexInt8      = 16
	tdhOutTypeHexInt16     = 17
	tdhOutTypeHexInt32     = 18
	tdhOutTypeHexInt64     = 19
	tdhOutTypePID          = 20
	tdhOutTypeTID          = 21
	tdhOutTypeIPv6         = 24
	tdhOutTypeErrorCode    = 29
	tdhOutTypeWin32Error   = 30
	tdhOutTypeNTStatus     = 31
	tdhOutTypeHResult      = 32
	tdhOutTypeCodePointer  = 37

	errorEvtInvalidEventData = 15005
	maxArrayElements         = 4096
	maxInfoCacheEntries      = 4096
)

// filetimeEpochDelta is the number of 100ns intervals between 1601 and 1970.
const filetimeEpochDelta = 116444736000000000

func filetimeToTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (ft-filetimeEpochDelta)*100).UTC()
}

type infoKey struct {
	provider GUID
	id       uint16
	version  uint8
}

// decoder turns EVENT_RECORDs into Events.  It is used from the single
// ProcessTrace thread of a consumer and is not safe for concurrent use.
type decoder struct {
	infoCache map[infoKey][]byte
	mapCache  map[string][]byte
	fmtBuf    []uint16
}

func newDecoder() *decoder {
	return &decoder{
		infoCache: map[infoKey][]byte{},
		mapCache:  map[string][]byte{},
		fmtBuf:    make([]uint16, 512),
	}
}

var sidCache sync.Map // string SID -> account name

func lookupAccount(sid *windows.SID, str string) string {
	if v, ok := sidCache.Load(str); ok {
		return v.(string)
	}
	acct, dom, _, err := sid.LookupAccount(``)
	name := ``
	if err == nil {
		if dom != `` {
			name = dom + `\` + acct
		} else {
			name = acct
		}
	}
	sidCache.Store(str, name)
	return name
}

// eventInfo fetches the TRACE_EVENT_INFO, caching manifest based schemas.
func (d *decoder) eventInfo(r *eventRecord) ([]byte, error) {
	key := infoKey{provider: r.EventHeader.ProviderID, id: r.EventHeader.EventDescriptor.ID, version: r.EventHeader.EventDescriptor.Version}
	if b, ok := d.infoCache[key]; ok {
		return b, nil
	}
	buf, err := tdhBuffer(4096, func(b []byte, size *uint32) uintptr {
		ret, _, _ := procTdhGetEventInformation.Call(uintptr(unsafe.Pointer(r)), 0, 0, bufPtr(b), uintptr(unsafe.Pointer(size)))
		return ret
	})
	if err != nil {
		return nil, err
	}
	if len(buf) < int(unsafe.Sizeof(traceEventInfo{})) {
		return nil, errors.New("short TRACE_EVENT_INFO")
	}
	tei := (*traceEventInfo)(unsafe.Pointer(&buf[0]))
	// manifest and MOF schemas are fixed per id/version, TraceLogging schemas travel with each event
	if tei.DecodingSource == DecodingSourceXMLFile {
		if len(d.infoCache) >= maxInfoCacheEntries {
			clear(d.infoCache)
		}
		d.infoCache[key] = buf
	}
	return buf, nil
}

func (d *decoder) mapInfo(r *eventRecord, name string, namePtr *uint16) []byte {
	key := r.EventHeader.ProviderID.String() + `|` + name
	if b, ok := d.mapCache[key]; ok {
		return b
	}
	buf, err := tdhBuffer(1024, func(b []byte, size *uint32) uintptr {
		ret, _, _ := procTdhGetEventMapInformation.Call(uintptr(unsafe.Pointer(r)), uintptr(unsafe.Pointer(namePtr)), bufPtr(b), uintptr(unsafe.Pointer(size)))
		return ret
	})
	if err != nil {
		buf = nil
	}
	if len(d.mapCache) >= maxInfoCacheEntries {
		clear(d.mapCache)
	}
	d.mapCache[key] = buf
	return buf
}

// decode converts the record.  It never fails; decoding problems are recorded
// on the event along with the raw user data.
func (d *decoder) decode(r *eventRecord) *Event {
	h := &r.EventHeader
	ev := &Event{
		Timestamp:       filetimeToTime(h.TimeStamp),
		ProviderGUID:    h.ProviderID,
		EventID:         h.EventDescriptor.ID,
		Version:         h.EventDescriptor.Version,
		Level:           h.EventDescriptor.Level,
		Opcode:          h.EventDescriptor.Opcode,
		Task:            h.EventDescriptor.Task,
		Keywords:        h.EventDescriptor.Keyword,
		Channel:         h.EventDescriptor.Channel,
		ProcessID:       h.ProcessID,
		ThreadID:        h.ThreadID,
		ProcessorNumber: r.BufferContext.ProcessorIndex,
		ActivityID:      h.ActivityID,
		DecodingSource:  DecodingSourceUnavailable,
	}
	if sp, ok := sensitiveProviders[h.ProviderID]; ok {
		ev.ProviderName = sp
	}
	d.extended(r, ev)
	var userData []byte
	if r.UserData != nil {
		userData = unsafe.Slice((*byte)(r.UserData), int(r.UserDataLength))
	}

	if h.Flags&eventHeaderFlagStringOnly != 0 {
		s := utf16Bytes(userData)
		ev.Properties = []Property{{Name: `Data`, Value: s}}
		ev.Message = s
		ev.DecodingSource = DecodingSourceUnavailable
		return ev
	}

	info, err := d.eventInfo(r)
	if err != nil {
		ev.DecodingError = fmt.Sprintf("no schema available: %v", err)
		ev.RawUserData = append([]byte(nil), userData...)
		return ev
	}
	tei := (*traceEventInfo)(unsafe.Pointer(&info[0]))
	ev.DecodingSource = tei.DecodingSource
	ev.ProviderName = cleanName(utf16At(info, tei.ProviderNameOffset))
	ev.LevelName = cleanName(utf16At(info, tei.LevelNameOffset))
	ev.TaskName = cleanName(utf16At(info, tei.TaskNameOffset))
	ev.OpcodeName = cleanName(utf16At(info, tei.OpcodeNameOffset))
	ev.ChannelName = cleanName(utf16At(info, tei.ChannelNameOffset))
	ev.KeywordNames = multiString(info, tei.KeywordsNameOffset)
	if tei.DecodingSource == DecodingSourceTlg {
		ev.EventName = cleanName(utf16At(info, tei.EventNameOffset))
	}

	ptrSize := uint32(8)
	if h.Flags&eventHeaderFlag32BitHeader != 0 {
		ptrSize = 4
	}
	pd := &propDecoder{d: d, r: r, info: info, tei: tei, data: userData, ptrSize: ptrSize, ints: map[uint32]uint64{}}
	props, err := pd.decodeRange(0, tei.TopLevelPropertyCount)
	ev.Properties = props
	if err != nil {
		ev.DecodingError = err.Error()
		ev.RawUserData = append([]byte(nil), userData...)
	}
	if tmpl := utf16At(info, tei.EventMessageOffset); tmpl != `` {
		ev.Message = FormatMessage(tmpl, ev.MessageArgs())
	}
	return ev
}

func (d *decoder) extended(r *eventRecord, ev *Event) {
	if r.ExtendedDataCount == 0 || r.ExtendedData == nil {
		return
	}
	items := unsafe.Slice(r.ExtendedData, int(r.ExtendedDataCount))
	for _, it := range items {
		if it.ExtType == eventHeaderExtTypeRelatedActivityID && it.DataSize >= 16 && it.DataPtr != nil {
			ev.RelatedActivityID = *(*GUID)(it.DataPtr)
		}
	}
}

// multiString reads a double NUL terminated list of strings.
func multiString(buf []byte, off uint32) (r []string) {
	for off != 0 && int(off)+2 <= len(buf) {
		s := utf16At(buf, off)
		if s == `` {
			break
		}
		r = append(r, cleanName(s))
		off += uint32(len(windows.StringToUTF16(s))) * 2
	}
	return
}

func utf16Bytes(b []byte) string {
	if len(b) < 2 {
		return ``
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u)
}

type propDecoder struct {
	d       *decoder
	r       *eventRecord
	info    []byte
	tei     *traceEventInfo
	data    []byte
	off     int
	ptrSize uint32
	ints    map[uint32]uint64 // integer values by property index, for length/count references
}

func (p *propDecoder) prop(i uint32) (*eventPropertyInfo, error) {
	off := unsafe.Sizeof(traceEventInfo{}) + uintptr(i)*unsafe.Sizeof(eventPropertyInfo{})
	if i >= p.tei.PropertyCount || off+unsafe.Sizeof(eventPropertyInfo{}) > uintptr(len(p.info)) {
		return nil, fmt.Errorf("property index %d out of range", i)
	}
	return (*eventPropertyInfo)(unsafe.Pointer(&p.info[off])), nil
}

func (p *propDecoder) decodeRange(start, count uint32) ([]Property, error) {
	props := make([]Property, 0, count)
	for i := start; i < start+count; i++ {
		epi, err := p.prop(i)
		if err != nil {
			return props, err
		}
		name := utf16At(p.info, epi.NameOffset)
		v, err := p.decodeProperty(i, epi)
		props = append(props, Property{Name: name, Value: v})
		if err != nil {
			return props, fmt.Errorf("property %q: %w", name, err)
		}
	}
	return props, nil
}

func (p *propDecoder) refValue(idx uint16) (uint64, error) {
	v, ok := p.ints[uint32(idx)]
	if !ok {
		return 0, fmt.Errorf("referenced property %d has no integer value", idx)
	}
	return v, nil
}

func (p *propDecoder) decodeProperty(i uint32, epi *eventPropertyInfo) (any, error) {
	count := uint64(epi.Count)
	isArray := epi.Flags&(propertyParamCount|propertyParamFixedCount) != 0 || count > 1
	if epi.Flags&propertyParamCount != 0 {
		var err error
		if count, err = p.refValue(epi.Count); err != nil {
			return nil, err
		}
	}
	if count > maxArrayElements {
		return nil, fmt.Errorf("array count %d too large", count)
	}
	length := uint64(epi.Length)
	if epi.Flags&propertyParamLength != 0 {
		var err error
		if length, err = p.refValue(epi.Length); err != nil {
			return nil, err
		}
	}
	if !isArray {
		return p.decodeOne(i, epi, length)
	}
	arr := make([]any, 0, count)
	for c := uint64(0); c < count; c++ {
		v, err := p.decodeOne(i, epi, length)
		arr = append(arr, v)
		if err != nil {
			return arr, err
		}
	}
	return arr, nil
}

func (p *propDecoder) decodeOne(i uint32, epi *eventPropertyInfo, length uint64) (any, error) {
	if epi.Flags&propertyStruct != 0 {
		return p.decodeRange(uint32(epi.structStartIndex()), uint32(epi.numOfStructMembers()))
	}
	if length > math.MaxUint16 {
		return nil, fmt.Errorf("property length %d too large", length)
	}
	// IPv6 addresses are declared as zero length binary
	if epi.InType == tdhInTypeBinary && epi.OutType == tdhOutTypeIPv6 && length == 0 {
		length = 16
	}
	rest := p.data[min(p.off, len(p.data)):]

	var mapBuf []byte
	if epi.MapNameOffset != 0 {
		mapName := utf16At(p.info, epi.MapNameOffset)
		if np, err := windows.UTF16PtrFromString(mapName); err == nil {
			mapBuf = p.d.mapInfo(p.r, mapName, np)
		}
	}

	// typed fast paths for unmapped scalars
	if mapBuf == nil {
		if v, n, ok := p.typed(i, epi, rest); ok {
			p.off += n
			return v, nil
		}
	}

	s, consumed, err := p.format(epi, mapBuf, uint16(length), rest)
	if err != nil {
		return nil, err
	}
	p.off += int(consumed)
	if mapBuf != nil {
		mi := (*eventMapInfo)(unsafe.Pointer(&mapBuf[0]))
		// remember the raw integer for count/length references
		if raw, ok := rawUint(epi.InType, rest); ok {
			p.ints[i] = raw
		}
		if mi.Flag&(eventMapInfoFlagManifestBitmap|eventMapInfoFlagWbemBitmap) != 0 {
			return splitBitmap(s), nil
		}
	}
	return s, nil
}

// splitBitmap turns TDH's "A | B" bitmap rendering into a list of names.
func splitBitmap(s string) any {
	parts := strings.Split(s, `|`)
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != `` {
			out = append(out, p)
		}
	}
	return out
}

func rawUint(inType uint16, b []byte) (uint64, bool) {
	switch inType {
	case tdhInTypeInt8, tdhInTypeUint8:
		if len(b) >= 1 {
			return uint64(b[0]), true
		}
	case tdhInTypeInt16, tdhInTypeUint16:
		if len(b) >= 2 {
			return uint64(binary.LittleEndian.Uint16(b)), true
		}
	case tdhInTypeInt32, tdhInTypeUint32, tdhInTypeHexInt32:
		if len(b) >= 4 {
			return uint64(binary.LittleEndian.Uint32(b)), true
		}
	case tdhInTypeInt64, tdhInTypeUint64, tdhInTypeHexInt64:
		if len(b) >= 8 {
			return binary.LittleEndian.Uint64(b), true
		}
	}
	return 0, false
}

// intOutKind classifies how an integer in-type with the given out-type is
// rendered: as a JSON number, as a hex string, or (anything else, e.g. IPv4,
// port, string, datetime) through TdhFormatProperty.
type intOutKind int

const (
	intOutFormat intOutKind = iota
	intOutNumber
	intOutHex
)

func intOut(out uint16) intOutKind {
	switch {
	case out == tdhOutTypeNull, out >= tdhOutTypeByte && out <= tdhOutTypeUnsignedLong, out == tdhOutTypePID, out == tdhOutTypeTID:
		return intOutNumber
	case out >= tdhOutTypeHexInt8 && out <= tdhOutTypeHexInt64, out >= tdhOutTypeErrorCode && out <= tdhOutTypeHResult, out == tdhOutTypeCodePointer:
		return intOutHex
	}
	return intOutFormat
}

// typed decodes scalar types into native JSON types without going through TDH.
func (p *propDecoder) typed(idx uint32, epi *eventPropertyInfo, b []byte) (v any, n int, ok bool) {
	need := func(sz int) bool { return len(b) >= sz }
	in := epi.InType
	kind := intOutNumber
	switch in {
	case tdhInTypeInt8, tdhInTypeUint8, tdhInTypeInt16, tdhInTypeUint16, tdhInTypeInt32, tdhInTypeUint32, tdhInTypeInt64, tdhInTypeUint64:
		if kind = intOut(epi.OutType); kind == intOutFormat {
			// still remember the raw value for length/count references
			if raw, rok := rawUint(in, b); rok {
				p.ints[idx] = raw
			}
			return nil, 0, false
		}
	}
	switch in {
	case tdhInTypeInt8:
		if need(1) {
			v, n, ok = int64(int8(b[0])), 1, true
		}
	case tdhInTypeUint8:
		if need(1) {
			v, n, ok = uint64(b[0]), 1, true
		}
	case tdhInTypeInt16:
		if need(2) {
			v, n, ok = int64(int16(binary.LittleEndian.Uint16(b))), 2, true
		}
	case tdhInTypeUint16:
		if need(2) {
			v, n, ok = uint64(binary.LittleEndian.Uint16(b)), 2, true
		}
	case tdhInTypeInt32:
		if need(4) {
			v, n, ok = int64(int32(binary.LittleEndian.Uint32(b))), 4, true
		}
	case tdhInTypeUint32:
		if need(4) {
			v, n, ok = uint64(binary.LittleEndian.Uint32(b)), 4, true
		}
	case tdhInTypeInt64:
		if need(8) {
			v, n, ok = int64(binary.LittleEndian.Uint64(b)), 8, true
		}
	case tdhInTypeUint64:
		if need(8) {
			v, n, ok = binary.LittleEndian.Uint64(b), 8, true
		}
	case tdhInTypeHexInt32:
		if need(4) {
			u := uint64(binary.LittleEndian.Uint32(b))
			return fmt.Sprintf("0x%X", u), 4, true
		}
	case tdhInTypeHexInt64:
		if need(8) {
			return fmt.Sprintf("0x%X", binary.LittleEndian.Uint64(b)), 8, true
		}
	case tdhInTypeFloat:
		if need(4) {
			return float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 4, true
		}
		return
	case tdhInTypeDouble:
		if need(8) {
			return math.Float64frombits(binary.LittleEndian.Uint64(b)), 8, true
		}
		return
	case tdhInTypeBoolean:
		if need(4) {
			return binary.LittleEndian.Uint32(b) != 0, 4, true
		}
		return
	case tdhInTypePointer:
		sz := int(p.ptrSize)
		if need(sz) {
			var u uint64
			if sz == 4 {
				u = uint64(binary.LittleEndian.Uint32(b))
			} else {
				u = binary.LittleEndian.Uint64(b)
			}
			return fmt.Sprintf("0x%X", u), sz, true
		}
		return
	case tdhInTypeGUID:
		if need(16) {
			return *(*GUID)(unsafe.Pointer(&b[0])), 16, true
		}
		return
	case tdhInTypeFiletime:
		if need(8) {
			return filetimeToTime(int64(binary.LittleEndian.Uint64(b))), 8, true
		}
		return
	case tdhInTypeSystemtime:
		if need(16) {
			st := (*systemTime)(unsafe.Pointer(&b[0]))
			return time.Date(int(st.Year), time.Month(st.Month), int(st.Day), int(st.Hour), int(st.Minute), int(st.Second),
				int(st.Milliseconds)*int(time.Millisecond), time.UTC), 16, true
		}
		return
	case tdhInTypeSID:
		return p.sid(b)
	default:
		return
	}
	if !ok {
		return
	}
	// integers: remember for length/count references, honor hex out types
	if raw, rok := rawUint(in, b); rok {
		p.ints[idx] = raw
		if kind == intOutHex {
			v = fmt.Sprintf("0x%X", raw)
		}
	}
	return
}

func (p *propDecoder) sid(b []byte) (any, int, bool) {
	// SID: Revision, SubAuthorityCount, IdentifierAuthority[6], SubAuthority[count]
	if len(b) < 8 {
		return nil, 0, false
	}
	n := 8 + 4*int(b[1])
	if len(b) < n || b[0] != 1 {
		return nil, 0, false
	}
	sid := (*windows.SID)(unsafe.Pointer(&b[0]))
	if !sid.IsValid() {
		return nil, 0, false
	}
	str := sid.String()
	if acct := lookupAccount(sid, str); acct != `` {
		return []Property{{Name: `SID`, Value: str}, {Name: `Account`, Value: acct}}, n, true
	}
	return str, n, true
}

func (p *propDecoder) format(epi *eventPropertyInfo, mapBuf []byte, length uint16, rest []byte) (string, uint16, error) {
	var consumed uint16
	for tries := 0; tries < 4; tries++ {
		size := uint32(len(p.d.fmtBuf) * 2)
		var dataPtr uintptr
		if len(rest) > 0 {
			dataPtr = uintptr(unsafe.Pointer(&rest[0]))
		}
		r, _, _ := procTdhFormatProperty.Call(
			uintptr(unsafe.Pointer(p.tei)),
			bufPtr(mapBuf),
			uintptr(p.ptrSize),
			uintptr(epi.InType),
			uintptr(epi.OutType),
			uintptr(length),
			uintptr(len(rest)),
			dataPtr,
			uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&p.d.fmtBuf[0])),
			uintptr(unsafe.Pointer(&consumed)),
		)
		switch {
		case r == 0:
			return windows.UTF16ToString(p.d.fmtBuf), consumed, nil
		case windows.Errno(r) == windows.ERROR_INSUFFICIENT_BUFFER:
			p.d.fmtBuf = make([]uint16, size/2+1)
		case r == errorEvtInvalidEventData && len(rest) == 0:
			// trailing optional property with no data
			return ``, 0, nil
		default:
			return ``, 0, fmt.Errorf("TdhFormatProperty: %w", windows.Errno(r))
		}
	}
	return ``, 0, windows.ERROR_INSUFFICIENT_BUFFER
}
