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
	"testing"
	"unsafe"
)

// Sizes and offsets of the 64-bit Windows SDK structures.  If any of these
// fail the Go declarations no longer match the C layout.
func TestStructLayouts(t *testing.T) {
	sizes := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{`WNODE_HEADER`, unsafe.Sizeof(wnodeHeader{}), 48},
		{`EVENT_TRACE_PROPERTIES`, unsafe.Sizeof(eventTraceProperties{}), 120},
		{`EVENT_TRACE_HEADER`, unsafe.Sizeof(eventTraceHeader{}), 48},
		{`EVENT_TRACE`, unsafe.Sizeof(eventTrace{}), 88},
		{`TIME_ZONE_INFORMATION`, unsafe.Sizeof(timeZoneInformation{}), 172},
		{`TRACE_LOGFILE_HEADER`, unsafe.Sizeof(traceLogfileHeader{}), 280},
		{`EVENT_TRACE_LOGFILEW`, unsafe.Sizeof(eventTraceLogfile{}), 448},
		{`EVENT_DESCRIPTOR`, unsafe.Sizeof(eventDescriptor{}), 16},
		{`EVENT_HEADER`, unsafe.Sizeof(eventHeader{}), 80},
		{`EVENT_HEADER_EXTENDED_DATA_ITEM`, unsafe.Sizeof(eventHeaderExtendedDataItem{}), 16},
		{`EVENT_RECORD`, unsafe.Sizeof(eventRecord{}), 112},
		{`EVENT_FILTER_DESCRIPTOR`, unsafe.Sizeof(eventFilterDescriptor{}), 16},
		{`ENABLE_TRACE_PARAMETERS`, unsafe.Sizeof(enableTraceParameters{}), 48},
		{`TRACE_EVENT_INFO (fixed part)`, unsafe.Sizeof(traceEventInfo{}), 112},
		{`EVENT_PROPERTY_INFO`, unsafe.Sizeof(eventPropertyInfo{}), 24},
		{`TRACE_PROVIDER_INFO`, unsafe.Sizeof(traceProviderInfo{}), 24},
		{`PROVIDER_FIELD_INFO`, unsafe.Sizeof(providerFieldInfo{}), 16},
		{`SYSTEMTIME`, unsafe.Sizeof(systemTime{}), 16},
		{`GUID`, unsafe.Sizeof(GUID{}), 16},
	}
	for _, s := range sizes {
		if s.got != s.want {
			t.Errorf("sizeof(%s) = %d, want %d", s.name, s.got, s.want)
		}
	}

	var lf eventTraceLogfile
	var props eventTraceProperties
	var rec eventRecord
	var tei traceEventInfo
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{`EVENT_TRACE_LOGFILEW.ProcessTraceMode`, unsafe.Offsetof(lf.ProcessTraceMode), 28},
		{`EVENT_TRACE_LOGFILEW.LogfileHeader`, unsafe.Offsetof(lf.LogfileHeader), 120},
		{`EVENT_TRACE_LOGFILEW.EventRecordCallback`, unsafe.Offsetof(lf.EventRecordCallback), 424},
		{`EVENT_TRACE_LOGFILEW.Context`, unsafe.Offsetof(lf.Context), 440},
		{`EVENT_TRACE_PROPERTIES.LoggerThreadId`, unsafe.Offsetof(props.LoggerThreadID), 104},
		{`EVENT_TRACE_PROPERTIES.LoggerNameOffset`, unsafe.Offsetof(props.LoggerNameOffset), 116},
		{`EVENT_RECORD.BufferContext`, unsafe.Offsetof(rec.BufferContext), 80},
		{`EVENT_RECORD.UserDataLength`, unsafe.Offsetof(rec.UserDataLength), 86},
		{`EVENT_RECORD.UserData`, unsafe.Offsetof(rec.UserData), 96},
		{`EVENT_RECORD.UserContext`, unsafe.Offsetof(rec.UserContext), 104},
		{`TRACE_EVENT_INFO.DecodingSource`, unsafe.Offsetof(tei.DecodingSource), 48},
		{`TRACE_EVENT_INFO.PropertyCount`, unsafe.Offsetof(tei.PropertyCount), 100},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("offsetof(%s) = %d, want %d", o.name, o.got, o.want)
		}
	}
}

func TestFiletimeToTime(t *testing.T) {
	// 2026-01-01T00:00:00Z
	ft := int64(filetimeEpochDelta) + 1767225600*10000000
	if got := filetimeToTime(ft); got.Unix() != 1767225600 {
		t.Fatalf("filetimeToTime = %v", got)
	}
	if !filetimeToTime(0).IsZero() {
		t.Fatal("zero filetime should be the zero time")
	}
}

func TestMultiString(t *testing.T) {
	// "AB\0C\0\0" in UTF-16LE, preceded by 2 bytes of padding
	buf := []byte{0, 0, 'A', 0, 'B', 0, 0, 0, 'C', 0, 0, 0, 0, 0}
	got := multiString(buf, 2)
	if len(got) != 2 || got[0] != `AB` || got[1] != `C` {
		t.Fatalf("multiString = %v", got)
	}
	if multiString(buf, 0) != nil {
		t.Fatal("zero offset should be empty")
	}
}

func TestSplitBitmap(t *testing.T) {
	got := splitBitmap(`PAGE_READWRITE | PAGE_GUARD |`).([]any)
	if len(got) != 2 || got[0] != `PAGE_READWRITE` || got[1] != `PAGE_GUARD` {
		t.Fatalf("splitBitmap = %v", got)
	}
}

func TestIntOutKind(t *testing.T) {
	for out, want := range map[uint16]intOutKind{
		tdhOutTypeNull:        intOutNumber,
		8:                     intOutNumber, // UNSIGNEDINT
		tdhOutTypePID:         intOutNumber,
		tdhOutTypeHexInt32:    intOutHex,
		tdhOutTypeNTStatus:    intOutHex,
		tdhOutTypeCodePointer: intOutHex,
		22:                    intOutFormat, // PORT, network byte order
		23:                    intOutFormat, // IPV4
		1:                     intOutFormat, // STRING (char)
		2:                     intOutFormat, // DATETIME
	} {
		if got := intOut(out); got != want {
			t.Errorf("intOut(%d) = %d, want %d", out, got, want)
		}
	}
}
