/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 11, 24, 12, 0, 0, 123456700, time.UTC)

func tiEvent() *Event {
	return &Event{
		Timestamp:      testTime,
		ProviderName:   `Microsoft-Windows-Threat-Intelligence`,
		ProviderGUID:   ThreatIntelligenceGUID,
		EventID:        1,
		Level:          LevelInformation,
		LevelName:      `Information`,
		Task:           1,
		TaskName:       `KERNEL_THREATINT_TASK_ALLOCVM`,
		Opcode:         0,
		OpcodeName:     `Info`,
		Keywords:       0x4,
		KeywordNames:   []string{`KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE`},
		ChannelName:    `Microsoft-Windows-Threat-Intelligence/Analytic`,
		ProcessID:      1234,
		ThreadID:       5678,
		DecodingSource: DecodingSourceXMLFile,
		Properties: []Property{
			{Name: `CallingProcessId`, Value: uint64(1234)},
			{Name: `TargetProcessId`, Value: uint64(4321)},
			{Name: `BaseAddress`, Value: `0x7FF600000000`},
			{Name: `ProtectionMask`, Value: []any{`PAGE_EXECUTE_READWRITE`}},
			{Name: `CallingProcessCreateTime`, Value: testTime},
		},
	}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var mp map[string]any
	if err := json.Unmarshal(b, &mp); err != nil {
		t.Fatalf("invalid JSON %v:\n%s", err, b)
	}
	return mp
}

func TestRenderEvent(t *testing.T) {
	b, err := tiEvent().MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mp := decode(t, b)
	checks := map[string]any{
		`Timestamp`:      `2026-11-24T12:00:00.1234567Z`,
		`EventID`:        float64(1),
		`Level`:          `Information`,
		`LevelValue`:     float64(4),
		`Task`:           `KERNEL_THREATINT_TASK_ALLOCVM`,
		`Opcode`:         `Info`,
		`KeywordsMask`:   `0x4`,
		`ProcessID`:      float64(1234),
		`DecodingSource`: `Manifest`,
		`Channel`:        `Microsoft-Windows-Threat-Intelligence/Analytic`,
	}
	for k, want := range checks {
		if mp[k] != want {
			t.Fatalf("%s = %#v, want %#v", k, mp[k], want)
		}
	}
	prov := mp[`Provider`].(map[string]any)
	if prov[`Name`] != `Microsoft-Windows-Threat-Intelligence` || prov[`GUID`] != `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` {
		t.Fatalf("bad provider %v", prov)
	}
	if kw := mp[`Keywords`].([]any); len(kw) != 1 || kw[0] != `KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE` {
		t.Fatalf("bad keywords %v", kw)
	}
	ed := mp[`EventData`].(map[string]any)
	if ed[`CallingProcessId`] != float64(1234) || ed[`BaseAddress`] != `0x7FF600000000` {
		t.Fatalf("bad event data %v", ed)
	}
	if pm := ed[`ProtectionMask`].([]any); pm[0] != `PAGE_EXECUTE_READWRITE` {
		t.Fatalf("bad bitmap %v", pm)
	}
	if ed[`CallingProcessCreateTime`] != `2026-11-24T12:00:00.1234567Z` {
		t.Fatalf("bad time %v", ed[`CallingProcessCreateTime`])
	}
	// zero activity IDs and empty optional fields are omitted
	for _, k := range []string{`ActivityID`, `RelatedActivityID`, `EventName`, `Message`, `DecodingError`, `RawUserData`} {
		if _, ok := mp[k]; ok {
			t.Fatalf("%s should be omitted", k)
		}
	}
}

func TestRenderFieldOrderStable(t *testing.T) {
	b1, _ := tiEvent().MarshalJSON()
	b2, _ := tiEvent().MarshalJSON()
	if string(b1) != string(b2) {
		t.Fatal("rendering is not deterministic")
	}
	s := string(b1)
	// schema order is preserved inside EventData
	if strings.Index(s, `CallingProcessId`) > strings.Index(s, `TargetProcessId`) {
		t.Fatal("property order not preserved")
	}
	if !strings.HasPrefix(s, `{"Timestamp":`) {
		t.Fatalf("Timestamp should be first: %s", s[:40])
	}
}

func TestRenderNestedAndTypes(t *testing.T) {
	ev := &Event{
		Timestamp:         testTime,
		ProviderGUID:      GUID{Data1: 1},
		ActivityID:        GUID{Data1: 2},
		RelatedActivityID: GUID{Data1: 3},
		EventName:         `TlgEvent`,
		DecodingSource:    DecodingSourceTlg,
		Message:           `hello "world"`,
		Properties: []Property{
			{Name: `Bool`, Value: true},
			{Name: `Neg`, Value: int64(-5)},
			{Name: `Float`, Value: 1.5},
			{Name: `NaN`, Value: math.NaN()},
			{Name: `Nil`, Value: nil},
			{Name: `Guid`, Value: GUID{Data1: 0xabc}},
			{Name: `Bytes`, Value: []byte{0xde, 0xad}},
			{Name: `User`, Value: []Property{{Name: `SID`, Value: `S-1-5-18`}, {Name: `Account`, Value: `NT AUTHORITY\SYSTEM`}}},
			{Name: `Structs`, Value: []any{
				[]Property{{Name: `Port`, Value: uint64(80)}},
				[]Property{{Name: `Port`, Value: uint64(443)}},
			}},
		},
	}
	b, err := ev.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mp := decode(t, b)
	ed := mp[`EventData`].(map[string]any)
	if ed[`Bool`] != true || ed[`Neg`] != float64(-5) || ed[`Float`] != 1.5 || ed[`NaN`] != `NaN` || ed[`Nil`] != nil {
		t.Fatalf("bad scalars %v", ed)
	}
	if ed[`Guid`] != `{00000abc-0000-0000-0000-000000000000}` || ed[`Bytes`] != `0xDEAD` {
		t.Fatalf("bad guid/bytes %v %v", ed[`Guid`], ed[`Bytes`])
	}
	if u := ed[`User`].(map[string]any); u[`Account`] != `NT AUTHORITY\SYSTEM` {
		t.Fatalf("bad nested object %v", u)
	}
	if s := ed[`Structs`].([]any); s[1].(map[string]any)[`Port`] != float64(443) {
		t.Fatalf("bad struct array %v", s)
	}
	if mp[`ActivityID`] == nil || mp[`RelatedActivityID`] == nil || mp[`EventName`] != `TlgEvent` {
		t.Fatal("missing activity IDs or event name")
	}
	if mp[`Message`] != `hello "world"` || mp[`DecodingSource`] != `TraceLogging` {
		t.Fatalf("bad message/source %v %v", mp[`Message`], mp[`DecodingSource`])
	}
	// level falls back to the standard name
	if mp[`Level`] != `LogAlways` {
		t.Fatalf("bad fallback level %v", mp[`Level`])
	}
}

func TestRenderDecodeError(t *testing.T) {
	ev := &Event{
		Timestamp:      testTime,
		ProviderGUID:   GUID{Data1: 9},
		DecodingSource: DecodingSourceUnavailable,
		DecodingError:  `no schema available`,
		RawUserData:    []byte{1, 2, 3},
	}
	b, err := ev.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mp := decode(t, b)
	if mp[`DecodingError`] != `no schema available` || mp[`RawUserData`] != `AQID` || mp[`DecodingSource`] != `Unavailable` {
		t.Fatalf("bad decode error rendering %s", b)
	}
	if ed := mp[`EventData`].(map[string]any); len(ed) != 0 {
		t.Fatalf("expected empty EventData, got %v", ed)
	}
}

func TestRenderUnsupportedType(t *testing.T) {
	ev := &Event{Properties: []Property{{Name: `x`, Value: struct{}{}}}}
	if _, err := ev.MarshalJSON(); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestAppendJSON(t *testing.T) {
	prefix := []byte(`prefix`)
	b, err := tiEvent().AppendJSON(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `prefix{`) {
		t.Fatal("AppendJSON did not append")
	}
	decode(t, b[len(prefix):])
}

func TestFormatMessage(t *testing.T) {
	cases := []struct {
		tmpl string
		args []string
		want string
	}{
		{`Process %1 started by %2.`, []string{`cmd.exe`, `1234`}, `Process cmd.exe started by 1234.`},
		{`%1!s! and %2!d!`, []string{`a`, `7`}, `a and 7`},
		{`100%% done%n`, nil, `100% done`},
		{`a%tb`, nil, "a\tb"},
		{`missing %3 arg`, []string{`x`}, `missing %3 arg`},
		{`stop%0ignored`, nil, `stop`},
		{`%10 is ten`, []string{`1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9`, `ten`}, `ten is ten`},
		{`no inserts  `, nil, `no inserts`},
		{`trailing %`, nil, `trailing %`},
	}
	for _, c := range cases {
		if got := FormatMessage(c.tmpl, c.args); got != c.want {
			t.Fatalf("FormatMessage(%q) = %q, want %q", c.tmpl, got, c.want)
		}
	}
}

func TestMessageArgs(t *testing.T) {
	ev := tiEvent()
	args := ev.MessageArgs()
	if args[0] != `1234` || args[3] != `PAGE_EXECUTE_READWRITE` {
		t.Fatalf("bad args %v", args)
	}
	if v, ok := ev.Property(`TargetProcessId`); !ok || v != uint64(4321) {
		t.Fatal("Property lookup failed")
	}
	if _, ok := ev.Property(`nope`); ok {
		t.Fatal("unexpected property")
	}
}
