/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"errors"
	"slices"
	"testing"
)

func TestParseGUID(t *testing.T) {
	for _, s := range []string{
		`{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`,
		`f4e1897c-bb5d-5668-f1d8-040f4d8dd344`,
		`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`,
		` {f4e1897c-bb5d-5668-f1d8-040f4d8dd344} `,
	} {
		g, err := ParseGUID(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if g != ThreatIntelligenceGUID {
			t.Fatalf("%q parsed to %s", s, g)
		}
		if g.String() != `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` {
			t.Fatalf("bad round trip %s", g)
		}
	}
	for _, s := range []string{``, `{}`, `f4e1897c-bb5d-5668-f1d8-040f4d8dd34`, `f4e1897cxbb5d-5668-f1d8-040f4d8dd344`, `g4e1897c-bb5d-5668-f1d8-040f4d8dd344`} {
		if _, err := ParseGUID(s); !errors.Is(err, ErrInvalidGUID) {
			t.Fatalf("%q: expected ErrInvalidGUID, got %v", s, err)
		}
	}
	if b, _ := ThreatIntelligenceGUID.MarshalText(); string(b) != `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` {
		t.Fatalf("bad text marshal %s", b)
	}
}

func TestParseLevel(t *testing.T) {
	good := map[string]uint8{
		``: LevelVerbose, `verbose`: LevelVerbose, `Critical`: LevelCritical, `error`: LevelError,
		`WARNING`: LevelWarning, `warn`: LevelWarning, `information`: LevelInformation, `info`: LevelInformation,
		`0`: 0, `5`: 5, `0x10`: 16, `255`: 255,
	}
	for s, want := range good {
		if got, err := ParseLevel(s); err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{`loud`, `256`, `-1`} {
		if _, err := ParseLevel(s); !errors.Is(err, ErrInvalidLevel) {
			t.Fatalf("ParseLevel(%q) expected error, got %v", s, err)
		}
	}
	if LevelName(LevelWarning) != `Warning` || LevelName(42) != `42` {
		t.Fatal("bad level names")
	}
}

func TestParseKeywords(t *testing.T) {
	ks, err := ParseKeywords([]string{`0x10`, `32, KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE`, ``, `Some-Keyword`})
	if err != nil {
		t.Fatal(err)
	}
	if ks.Mask != 0x30 {
		t.Fatalf("mask = %#x", ks.Mask)
	}
	if !slices.Equal(ks.Names, []string{`KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE`, `Some-Keyword`}) {
		t.Fatalf("names = %v", ks.Names)
	}
	if _, err := ParseKeywords([]string{`bad keyword!`}); !errors.Is(err, ErrInvalidKeyword) {
		t.Fatalf("expected ErrInvalidKeyword, got %v", err)
	}
	if ks, err := ParseKeywords(nil); err != nil || ks.Mask != 0 || ks.Names != nil {
		t.Fatalf("empty keywords %+v %v", ks, err)
	}
}

func TestParseEventIDs(t *testing.T) {
	ids, err := ParseEventIDs([]string{`1`, `3-5`, `4688, 4689`, `5`})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []uint16{1, 3, 4, 5, 4688, 4689}) {
		t.Fatalf("ids = %v", ids)
	}
	for _, bad := range [][]string{{`x`}, {`5-3`}, {`-1`}, {`70000`}, {`1-100`}} {
		if _, err := ParseEventIDs(bad); !errors.Is(err, ErrInvalidEventID) {
			t.Fatalf("%v: expected ErrInvalidEventID, got %v", bad, err)
		}
	}
	var many []string
	for i := 0; i < 65; i++ {
		many = append(many, string(rune('0'+i%10))+string(rune('0'+i/10)))
	}
	if _, err := ParseEventIDs(many); !errors.Is(err, ErrInvalidEventID) {
		t.Fatalf("expected too many IDs error, got %v", err)
	}
}

func TestParseProvider(t *testing.T) {
	ps, err := ParseProvider(`{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`)
	if err != nil || !ps.Resolved() || ps.GUID != ThreatIntelligenceGUID {
		t.Fatalf("guid provider: %+v %v", ps, err)
	}
	ps, err = ParseProvider(` Microsoft-Windows-Kernel-Process `)
	if err != nil || ps.Resolved() || ps.Name != `Microsoft-Windows-Kernel-Process` {
		t.Fatalf("named provider: %+v %v", ps, err)
	}
	if ps.String() != `Microsoft-Windows-Kernel-Process` {
		t.Fatalf("bad String %q", ps.String())
	}
	for _, bad := range []string{``, `   `, `{not-a-guid}`} {
		if _, err := ParseProvider(bad); !errors.Is(err, ErrInvalidProvider) {
			t.Fatalf("%q: expected ErrInvalidProvider, got %v", bad, err)
		}
	}
}

func TestValidSessionName(t *testing.T) {
	if ValidSessionName(`Gravwell-test`) != nil {
		t.Fatal("valid name rejected")
	}
	if ValidSessionName(``) == nil {
		t.Fatal("empty name accepted")
	}
	long := make([]byte, 1024)
	for i := range long {
		long[i] = 'a'
	}
	if ValidSessionName(string(long)) == nil {
		t.Fatal("long name accepted")
	}
}
