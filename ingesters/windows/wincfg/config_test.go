/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package wincfg

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gravwell/gravwell/v3/etw"
)

const testGlobal = `
[Global]
Ingest-Secret = IngestSecrets
Connection-Timeout = 0
Cleartext-Backend-Target=127.0.0.1:4023
Log-Level=INFO
`

func mustParse(t *testing.T, s string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(s))
	if err != nil {
		t.Fatalf("failed to parse config: %v\n%s", err, s)
	}
	return c
}

func TestLegacyConfigsParseUnchanged(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	for _, f := range []string{`legacy_eventlog.cfg`, `legacy_filefollow.cfg`} {
		t.Run(f, func(t *testing.T) {
			c, err := GetConfig(filepath.Join(`testdata`, f), ``)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.EventChannel)+len(c.Follower) == 0 {
				t.Fatal("no inputs parsed")
			}
		})
	}
}

func TestCombinedConfig(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	c := mustParse(t, testGlobal+`
[EventChannel "system"]
	Tag-Name=windows
	Channel=System
	EventID=1000-2000
	Level=Error

[Follower "cbs"]
	Base-Directory="C:\\Windows\\Logs\\CBS"
	File-Filter="*.log"
	Tag-Name=auth

[ETW "kproc"]
	Tag-Name=etw
	Provider=Microsoft-Windows-Kernel-Process
	Provider={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
	Level=information
	Match-Any-Keyword=0x10
	Event-ID=1,2
`)
	tags, err := c.Tags()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{`auth`, `etw`, `windows`}; !slices.Equal(tags, want) {
		t.Fatalf("tags = %v, want %v", tags, want)
	}
	ec := c.EventChannel[`system`]
	if ec.Request_Size != defaultHandleRequest || ec.Request_Buffer != defaultBuffSize {
		t.Fatalf("event channel defaults not applied: %+v", ec)
	}
	if c.Global.Bookmark_Location == `` || c.Global.State_Store_Location == `` {
		t.Fatal("state defaults not applied")
	}
	if c.Global.Max_Files_Watched != defaultMaxWatchedFiles {
		t.Fatalf("Max-Files-Watched default not applied: %d", c.Global.Max_Files_Watched)
	}
	sp := c.ETW[`kproc`].Params(`kproc`)
	if sp.SessionName != `Gravwell-kproc` {
		t.Fatalf("bad session name %q", sp.SessionName)
	}
	if len(sp.Providers) != 2 || sp.Providers[0].Provider.Name != `Microsoft-Windows-Kernel-Process` || !sp.Providers[1].Provider.Resolved() {
		t.Fatalf("bad providers %+v", sp.Providers)
	}
	if sp.Providers[0].Level != etw.LevelInformation || sp.Providers[0].MatchAny.Mask != 0x10 {
		t.Fatalf("bad level/keyword %+v", sp.Providers[0])
	}
	if !slices.Equal(sp.Providers[0].EventIDs, []uint16{1, 2}) {
		t.Fatalf("bad event ids %v", sp.Providers[0].EventIDs)
	}
	if sp.BufferSizeKB != defaultETWBufferKB {
		t.Fatalf("bad buffer size %d", sp.BufferSizeKB)
	}
	// Followers attaches time formats and copies
	if f := c.Followers(); len(f) != 1 || f[`cbs`].Tag_Name != `auth` {
		t.Fatalf("bad followers %+v", f)
	}
}

func TestConfigVerifyFailures(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	tests := map[string]string{
		`no inputs`:          testGlobal,
		`bad channel level`:  testGlobal + "[EventChannel \"x\"]\nChannel=System\nLevel=bogus\n",
		`missing channel`:    testGlobal + "[EventChannel \"x\"]\nTag-Name=foo\n",
		`bad event id`:       testGlobal + "[EventChannel \"x\"]\nChannel=System\nEventID=abc\n",
		`follower no dir`:    testGlobal + "[Follower \"x\"]\nFile-Filter=*.log\n",
		`follower tz clash`:  testGlobal + "[Follower \"x\"]\nBase-Directory=/tmp\nTimezone-Override=UTC\nAssume-Local-Timezone=true\n",
		`etw no provider`:    testGlobal + "[ETW \"x\"]\nTag-Name=etw\n",
		`etw bad guid`:       testGlobal + "[ETW \"x\"]\nProvider={not-a-guid}\n",
		`etw bad level`:      testGlobal + "[ETW \"x\"]\nProvider=Foo\nLevel=loud\n",
		`etw dup provider`:   testGlobal + "[ETW \"x\"]\nProvider=Foo\nProvider=foo\n",
		`etw names multi`:    testGlobal + "[ETW \"x\"]\nProvider=Foo\nProvider=Bar\nMatch-Any-Keyword=SOME_KEYWORD\n",
		`etw bad buffers`:    testGlobal + "[ETW \"x\"]\nProvider=Foo\nMin-Buffers=10\nMax-Buffers=2\n",
		`etw bad buffersize`: testGlobal + "[ETW \"x\"]\nProvider=Foo\nBuffer-Size-KB=1\n",
		`missing preproc`:    testGlobal + "[ETW \"x\"]\nProvider=Foo\nPreprocessor=nope\n",
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(cfg)); err == nil {
				t.Fatalf("expected error for config:\n%s", cfg)
			}
		})
	}
	if _, err := ParseConfig([]byte(testGlobal)); !errors.Is(err, ErrNoInputs) {
		t.Fatalf("expected ErrNoInputs, got %v", err)
	}
}

func TestSensitiveProviders(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	c := mustParse(t, testGlobal+`
[ETW "ti"]
	Tag-Name=ti
	Provider=Microsoft-Windows-Threat-Intelligence
	Match-Any-Keyword=KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE

[ETW "plain"]
	Provider=Microsoft-Windows-DNS-Client
`)
	if sp := c.ETW[`ti`].SensitiveProviders(); len(sp) != 1 {
		t.Fatalf("expected TI to be sensitive: %v", sp)
	}
	if sp := c.ETW[`plain`].SensitiveProviders(); len(sp) != 0 {
		t.Fatalf("expected DNS client to not be sensitive: %v", sp)
	}
	p := c.ETW[`ti`].Params(`ti`)
	if names := p.Providers[0].MatchAny.Names; len(names) != 1 || names[0] != `KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE` {
		t.Fatalf("keyword names not carried: %+v", p.Providers[0].MatchAny)
	}
}

func TestConfigOverlay(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(`PROGRAMDATA`, dir)
	main := filepath.Join(dir, `windows.cfg`)
	od := filepath.Join(dir, `windows.conf.d`)
	if err := os.WriteFile(main, []byte(testGlobal), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(od, 0700); err != nil {
		t.Fatal(err)
	}
	overlay := "[ETW \"dns\"]\nProvider=Microsoft-Windows-DNS-Client\nTag-Name=dns\n"
	if err := os.WriteFile(filepath.Join(od, `dns.conf`), []byte(overlay), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := GetConfig(main, od)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.ETW[`dns`]; !ok {
		t.Fatal("overlay section not loaded")
	}
	if tags, _ := c.Tags(); !slices.Contains(tags, `dns`) {
		t.Fatalf("overlay tag missing: %v", tags)
	}
	// make sure RawConfig does not panic and contains the ETW section
	if rc, ok := c.RawConfig().(Config); !ok || len(rc.ETW) != 1 {
		t.Fatal("bad raw config")
	}
}

func TestShippedSampleConfig(t *testing.T) {
	t.Setenv(`PROGRAMDATA`, t.TempDir())
	c, err := GetConfig(filepath.Join(`..`, `windows.cfg`), ``)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.EventChannel) != 3 || len(c.ETW) != 1 {
		t.Fatalf("unexpected sample config contents: %d channels, %d etw", len(c.EventChannel), len(c.ETW))
	}
}
