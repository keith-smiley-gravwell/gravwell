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
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const kernelProcessProvider = `Microsoft-Windows-Kernel-Process`

// requireElevated skips tests that need an administrator token to control ETW sessions.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires an elevated (administrator) token")
	}
}

func kernelProcessParams(name string) SessionParams {
	return SessionParams{
		Name:         name,
		SessionName:  `Gravwell-test-` + name,
		BufferSizeKB: 64,
		Providers: []ProviderParams{{
			Provider: ProviderSpec{Name: kernelProcessProvider},
			Level:    LevelInformation,
			MatchAny: KeywordSpec{Names: []string{`WINEVENT_KEYWORD_PROCESS`}},
			EventIDs: []uint16{1}, // ProcessStart
		}},
	}
}

func TestResolveProviderAndKeywords(t *testing.T) {
	g, err := ResolveProvider(ProviderSpec{Name: strings.ToLower(kernelProcessProvider)})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ParseGUID(`{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`)
	if g != want {
		t.Fatalf("resolved %s, want %s", g, want)
	}
	mask, err := ResolveKeywords(g, KeywordSpec{Names: []string{`WINEVENT_KEYWORD_PROCESS`}, Mask: 0x100}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if mask != 0x110 {
		t.Fatalf("mask = %#x, want 0x110", mask)
	}
	if _, err := ResolveKeywords(g, KeywordSpec{Names: []string{`NOT_A_KEYWORD`}}, 0); !errors.Is(err, ErrInvalidKeyword) {
		t.Fatalf("expected ErrInvalidKeyword, got %v", err)
	}
	if _, err := ResolveProvider(ProviderSpec{Name: `Gravwell-Not-A-Real-Provider`}); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("expected ErrProviderNotFound, got %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	requireElevated(t)
	sp := kernelProcessParams(`lifecycle`)

	// leave a stale session behind, as a crash would
	stale, err := startSession(sp)
	if err != nil {
		t.Fatal(err)
	}
	_ = stale // intentionally not closed

	c, err := NewConsumer(sp, ConsumerConfig{})
	if err != nil {
		t.Fatalf("consumer should replace the stale session: %v", err)
	}
	c.Start()
	if _, err := c.Stats(); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// events channel must be closed after Close
	select {
	case _, ok := <-c.Events():
		for ok {
			_, ok = <-c.Events()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("events channel not closed")
	}
	// the session must be gone
	name, _ := windows.UTF16PtrFromString(sp.SessionName)
	props, buf := newPropertiesBuffer()
	if err := controlTrace(0, name, props, eventTraceControlQuery); err == nil {
		t.Fatal("session still exists after Close")
	}
	runtime.KeepAlive(buf)
	// closing twice is harmless
	if err := c.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestSensitiveProviderRejected(t *testing.T) {
	sp := SessionParams{
		SessionName: `Gravwell-test-ti`,
		Providers:   []ProviderParams{{Provider: ProviderSpec{GUID: ThreatIntelligenceGUID}}},
	}
	lvl, err := CurrentProcess{}.ProtectionLevel()
	if err != nil {
		t.Fatalf("ProtectionLevel: %v", err)
	}
	if protectionSatisfiesPPL(lvl) {
		t.Skip("test process is protected")
	}
	if _, err := NewConsumer(sp, ConsumerConfig{}); !errors.Is(err, ErrRequiresPPL) {
		t.Fatalf("expected ErrRequiresPPL, got %v", err)
	}
}

// startProcesses spawns short lived processes until stop is closed.
func startProcesses(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(200 * time.Millisecond):
			exec.Command(`cmd.exe`, `/c`, `exit`).Run()
		}
	}
}
