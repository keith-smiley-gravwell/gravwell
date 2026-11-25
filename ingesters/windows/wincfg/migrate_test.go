/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package wincfg

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(`testdata`, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMergeShippedLegacyConfigs(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	out, warnings, err := MergeLegacyConfigs(readTestdata(t, `legacy_eventlog.cfg`), readTestdata(t, `legacy_filefollow.cfg`))
	if err != nil {
		t.Fatal(err)
	}
	c := mustParse(t, string(out))
	if len(c.EventChannel) != 4 || len(c.Follower) != 1 {
		t.Fatalf("expected 4 channels and 1 follower, got %d and %d", len(c.EventChannel), len(c.Follower))
	}
	// Cleartext-Backend-Target differs between the shipped configs, event log wins
	if !slices.Equal(c.Global.Cleartext_Backend_Target, []string{`127.0.1.1:4023`}) {
		t.Fatalf("unexpected targets %v", c.Global.Cleartext_Backend_Target)
	}
	if !hasWarning(warnings, `cleartext-backend-target`) {
		t.Fatalf("expected a target conflict warning, got %v", warnings)
	}
	// State-Store-Location only exists in the follower config, so it is carried
	if !strings.Contains(c.Global.State_Store_Location, `file_follow.state`) {
		t.Fatalf("state store not carried: %q", c.Global.State_Store_Location)
	}
	// Verify-Remote-Certificates only in file follow, must be carried
	if !bytes.Contains(out, []byte(`Verify-Remote-Certificates`)) {
		t.Fatal("follower-only global key dropped")
	}
}

func TestMergeDropsUUIDAndRenamesCollisions(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	ev := []byte(`[Global]
Ingest-Secret=abc
Cleartext-Backend-Target=10.0.0.1:4023
Ingester-UUID="11111111-1111-1111-1111-111111111111"

[EventChannel "system"]
	Channel=System
	Preprocessor=gz

[Preprocessor "gz"]
	Type=gzip
`)
	ff := []byte(`[Global]
Ingest-Secret=different
Cleartext-Backend-Target=10.0.0.1:4023
Ingester-UUID="22222222-2222-2222-2222-222222222222"
Max-Files-Watched=10

[Follower "logs"]
	Base-Directory="C:\\logs"
	Preprocessor=gz

[Preprocessor "gz"]
	Type=gzip
`)
	out, warnings, err := MergeLegacyConfigs(ev, ff)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(`Ingester-UUID`)) {
		t.Fatalf("Ingester-UUID not stripped:\n%s", out)
	}
	c := mustParse(t, string(out))
	if c.Global.Ingest_Secret != `abc` {
		t.Fatalf("event log secret should win, got %q", c.Global.Ingest_Secret)
	}
	if !hasWarning(warnings, `ingest-secret`) {
		t.Fatalf("expected secret conflict warning: %v", warnings)
	}
	if hasWarning(warnings, `cleartext-backend-target`) {
		t.Fatalf("identical targets should not warn: %v", warnings)
	}
	if c.Global.Max_Files_Watched != 10 {
		t.Fatalf("Max-Files-Watched not carried: %d", c.Global.Max_Files_Watched)
	}
	if !slices.Equal(c.Follower[`logs`].Preprocessor, []string{`gz-filefollow`}) {
		t.Fatalf("follower preprocessor ref not rewritten: %v", c.Follower[`logs`].Preprocessor)
	}
	if !slices.Equal(c.EventChannel[`system`].Preprocessor, []string{`gz`}) {
		t.Fatalf("event channel preprocessor ref changed: %v", c.EventChannel[`system`].Preprocessor)
	}
	if !hasWarning(warnings, `gz-filefollow`) {
		t.Fatalf("expected rename warning: %v", warnings)
	}
}

func TestMergeSingleSource(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	if _, _, err := MergeLegacyConfigs(nil, nil); !errors.Is(err, ErrNothingToMigrate) {
		t.Fatalf("expected ErrNothingToMigrate, got %v", err)
	}
	out, _, err := MergeLegacyConfigs(nil, readTestdata(t, `legacy_filefollow.cfg`))
	if err != nil {
		t.Fatal(err)
	}
	if c := mustParse(t, string(out)); len(c.Follower) != 1 || len(c.EventChannel) != 0 {
		t.Fatal("bad single source merge")
	}
}

func TestMigrateLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(`PROGRAMDATA`, dir)
	mp, err := DefaultMigrationPaths()
	if err != nil {
		t.Fatal(err)
	}
	write := func(p string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(mp.EventLogConfig, readTestdata(t, `legacy_eventlog.cfg`))
	write(mp.EventLogBookmark, []byte(`bookmark-data`))
	// no State-Store-Location so the default state is copied
	ff := bytes.ReplaceAll(readTestdata(t, `legacy_filefollow.cfg`), []byte(`State-Store-Location`), []byte(`#State-Store-Location`))
	write(mp.FollowConfig, ff)
	write(mp.FollowState, []byte(`state-data`))

	done, _, err := MigrateLegacy(mp)
	if err != nil || !done {
		t.Fatalf("migration failed: %v %v", done, err)
	}
	for p, want := range map[string]string{mp.Bookmark: `bookmark-data`, mp.State: `state-data`} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Fatalf("%s not copied: %v %q", p, err, b)
		}
	}
	c, err := GetConfig(mp.Config, ``)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.EventChannel) != 4 || len(c.Follower) != 1 {
		t.Fatal("migrated config incomplete")
	}

	// second run is a no-op
	if done, _, err = MigrateLegacy(mp); err != nil || done {
		t.Fatalf("second migration should be a no-op: %v %v", done, err)
	}
}

func TestMigrateKeepsExplicitStatePaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(`PROGRAMDATA`, dir)
	mp, err := DefaultMigrationPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(mp.FollowConfig), 0700); err != nil {
		t.Fatal(err)
	}
	// shipped follower config sets State-Store-Location explicitly
	if err := os.WriteFile(mp.FollowConfig, readTestdata(t, `legacy_filefollow.cfg`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp.FollowState, []byte(`x`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigrateLegacy(mp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mp.State); !os.IsNotExist(err) {
		t.Fatalf("state should not be copied when explicitly configured: %v", err)
	}
}

func hasWarning(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(strings.ToLower(w), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
