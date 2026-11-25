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
	"strings"
	"testing"
)

type fakeProtection struct {
	level uint32
	err   error
	calls int
}

func (f *fakeProtection) ProtectionLevel() (uint32, error) {
	f.calls++
	return f.level, f.err
}

func tiParams() SessionParams {
	return SessionParams{
		SessionName: `Gravwell-ti`,
		Providers: []ProviderParams{
			{Provider: ProviderSpec{Name: `microsoft-windows-threat-intelligence`}},
			{Provider: ProviderSpec{Name: `Microsoft-Windows-Kernel-Process`}},
		},
	}
}

func TestRequiresPPL(t *testing.T) {
	cases := map[ProviderSpec]bool{
		{GUID: ThreatIntelligenceGUID}:                           true,
		{Name: `Microsoft-Windows-Threat-Intelligence`}:          true,
		{Name: `MICROSOFT-WINDOWS-THREAT-INTELLIGENCE`}:          true,
		{Name: `Microsoft-Windows-Kernel-Process`}:               false,
		{GUID: GUID{Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 1}}: false,
	}
	for ps, want := range cases {
		if got := RequiresPPL(ps); got != want {
			t.Fatalf("RequiresPPL(%v) = %v", ps, got)
		}
	}
}

func TestCheckSensitiveNotProtected(t *testing.T) {
	fp := &fakeProtection{level: ProtectionLevelNone}
	err := CheckSensitive(tiParams(), fp)
	if !errors.Is(err, ErrRequiresPPL) {
		t.Fatalf("expected ErrRequiresPPL, got %v", err)
	}
	// the message must name the provider and the actual protection level
	for _, want := range []string{`threat-intelligence`, `None`} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `Kernel-Process`) {
		t.Fatalf("non-sensitive provider named in error: %v", err)
	}
}

func TestCheckSensitiveLevels(t *testing.T) {
	for lvl, ok := range map[uint32]bool{
		ProtectionLevelAntimalwareLight: true,
		ProtectionLevelWinTCB:           true,
		ProtectionLevelWinTCBLight:      true,
		ProtectionLevelWindows:          true,
		ProtectionLevelWindowsLight:     false,
		ProtectionLevelLSALight:         false,
		ProtectionLevelAuthenticode:     false,
		ProtectionLevelNone:             false,
	} {
		err := CheckSensitive(tiParams(), &fakeProtection{level: lvl})
		if (err == nil) != ok {
			t.Fatalf("level %s: err = %v", ProtectionLevelName(lvl), err)
		}
	}
}

func TestCheckSensitiveQueryFailure(t *testing.T) {
	err := CheckSensitive(tiParams(), &fakeProtection{err: errors.New("boom")})
	if !errors.Is(err, ErrRequiresPPL) || !strings.Contains(err.Error(), `boom`) {
		t.Fatalf("unexpected error %v", err)
	}
	if err := CheckSensitive(tiParams(), nil); !errors.Is(err, ErrRequiresPPL) {
		t.Fatalf("nil checker should fail closed, got %v", err)
	}
}

func TestCheckSensitiveSkipsQueryWhenNotNeeded(t *testing.T) {
	fp := &fakeProtection{level: ProtectionLevelNone}
	sp := SessionParams{Providers: []ProviderParams{{Provider: ProviderSpec{Name: `Microsoft-Windows-DNS-Client`}}}}
	if err := CheckSensitive(sp, fp); err != nil {
		t.Fatal(err)
	}
	if fp.calls != 0 {
		t.Fatal("protection level queried for non-sensitive session")
	}
}

func TestProtectionLevelName(t *testing.T) {
	if ProtectionLevelName(ProtectionLevelAntimalwareLight) != `Antimalware-Light` {
		t.Fatal("bad name")
	}
	if !strings.HasPrefix(ProtectionLevelName(99), `Unknown`) {
		t.Fatal("bad unknown name")
	}
}
