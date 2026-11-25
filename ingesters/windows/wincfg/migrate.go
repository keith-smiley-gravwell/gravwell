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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	// LegacyEventLogConfigPath is the Windows Events ingester config, relative to %PROGRAMDATA%.
	LegacyEventLogConfigPath = filepath.Join(`gravwell`, `eventlog`, `config.cfg`)
	// LegacyEventLogBookmarkPath is the Windows Events ingester default bookmark, relative to %PROGRAMDATA%.
	LegacyEventLogBookmarkPath = filepath.Join(`gravwell`, `eventlog`, `bookmark`)
	// LegacyFileFollowConfigPath is the Windows File Follow ingester config, relative to %PROGRAMDATA%.
	LegacyFileFollowConfigPath = filepath.Join(`gravwell`, `filefollow`, `file_follow.cfg`)
	// LegacyFileFollowStatePath is the Windows File Follow ingester default state file, relative to %PROGRAMDATA%.
	LegacyFileFollowStatePath = filepath.Join(`gravwell`, `filefollow`, `file_follow.state`)

	ErrNothingToMigrate = errors.New("no legacy configuration found to migrate")

	headerRegex = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9_-]+)\s*(?:"((?:[^"\\]|\\.)*)")?\s*\]\s*(?:[#;].*)?$`)
)

const (
	migratedSuffix = `-filefollow`
)

// singleton sections are merged key by key; everything else is a named section.
var singletonSections = []string{`global`, `attach`}

type iniSection struct {
	typ   string // normalized section type, e.g. "preprocessor"
	name  string // subsection name, empty for singletons
	lines []string
}

type iniFile struct {
	preamble []string
	sections []*iniSection
}

func normalizeKey(k string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), `_`, `-`)
}

func parseINI(b []byte) (f iniFile) {
	var cur *iniSection
	for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if m := headerRegex.FindStringSubmatch(ln); m != nil {
			cur = &iniSection{typ: normalizeKey(m[1]), name: m[2]}
			f.sections = append(f.sections, cur)
			continue
		}
		if cur == nil {
			f.preamble = append(f.preamble, ln)
		} else {
			cur.lines = append(cur.lines, ln)
		}
	}
	return
}

// lineKV returns the normalized key and raw value of a config line, ok is false for comments and blanks.
func lineKV(ln string) (key, val string, ok bool) {
	t := strings.TrimSpace(ln)
	if t == `` || t[0] == '#' || t[0] == ';' {
		return
	}
	k, v, found := strings.Cut(t, `=`)
	if !found {
		// gcfg allows bare boolean keys
		return normalizeKey(stripComment(t)), `true`, true
	}
	return normalizeKey(k), strings.TrimSpace(stripComment(v)), true
}

// stripComment removes a trailing unquoted comment.
func stripComment(v string) string {
	inQuote := false
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '"':
			inQuote = !inQuote
		case '#', ';':
			if !inQuote {
				return strings.TrimSpace(v[:i])
			}
		}
	}
	return v
}

func (s *iniSection) header() string {
	typ := s.typ
	switch typ {
	case `global`:
		typ = `Global`
	case `attach`:
		typ = `Attach`
	case `eventchannel`:
		typ = `EventChannel`
	case `follower`:
		typ = `Follower`
	case `preprocessor`:
		typ = `Preprocessor`
	case `timeformat`:
		typ = `TimeFormat`
	case `etw`:
		typ = `ETW`
	}
	if s.name == `` && slices.Contains(singletonSections, s.typ) {
		return `[` + typ + `]`
	}
	return fmt.Sprintf(`[%s "%s"]`, typ, s.name)
}

func (s *iniSection) values() map[string][]string {
	mp := map[string][]string{}
	for _, ln := range s.lines {
		if k, v, ok := lineKV(ln); ok {
			mp[k] = append(mp[k], v)
		}
	}
	return mp
}

// dropKeys removes every line whose key is in keys.
func (s *iniSection) dropKeys(keys ...string) {
	out := s.lines[:0]
	for _, ln := range s.lines {
		if k, _, ok := lineKV(ln); ok && slices.Contains(keys, k) {
			continue
		}
		out = append(out, ln)
	}
	s.lines = out
}

// renameRefs rewrites "key=old" values to "key=new" for the given key.
func (s *iniSection) renameRefs(key, old, nw string) {
	for i, ln := range s.lines {
		k, v, ok := lineKV(ln)
		if !ok || k != key {
			continue
		}
		if strings.Trim(v, `"`) == old {
			indent := ln[:len(ln)-len(strings.TrimLeft(ln, " \t"))]
			kraw, _, _ := strings.Cut(strings.TrimSpace(ln), `=`)
			s.lines[i] = fmt.Sprintf(`%s%s=%s`, indent, strings.TrimSpace(kraw), nw)
		}
	}
}

func trimTrailingBlank(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == `` {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (f *iniFile) find(typ, name string) *iniSection {
	for _, s := range f.sections {
		if s.typ == typ && strings.EqualFold(s.name, name) {
			return s
		}
	}
	return nil
}

// MergeLegacyConfigs merges the legacy Windows Events config and the legacy
// Windows File Follow config into a single unified config.  Either may be nil.
//
//   - Global and Attach are merged key by key; the event log config wins on
//     conflict and a warning is returned for every conflicting key.
//   - Ingester-UUID is dropped so the unified ingester generates a new identity.
//   - Named sections are concatenated.  A File Follow section that collides
//     with an event log section of the same type is renamed with a
//     "-filefollow" suffix and, for preprocessors, references are rewritten.
//
// The result is parsed and verified before it is returned.
func MergeLegacyConfigs(eventCfg, followCfg []byte) (out []byte, warnings []string, err error) {
	if eventCfg == nil && followCfg == nil {
		return nil, nil, ErrNothingToMigrate
	}
	ev := parseINI(eventCfg)
	ff := parseINI(followCfg)

	// strip identity from both
	for _, f := range []*iniFile{&ev, &ff} {
		for _, s := range f.sections {
			if s.typ == `global` {
				s.dropKeys(`ingester-uuid`)
			}
		}
	}

	// rename colliding named sections in the file follow config
	for _, s := range ff.sections {
		if slices.Contains(singletonSections, s.typ) {
			continue
		}
		if ev.find(s.typ, s.name) == nil {
			continue
		}
		old := s.name
		nw := old + migratedSuffix
		for i := 2; ev.find(s.typ, nw) != nil || ff.find(s.typ, nw) != nil; i++ {
			nw = fmt.Sprintf("%s%s%d", old, migratedSuffix, i)
		}
		s.name = nw
		warnings = append(warnings, fmt.Sprintf("renamed File Follow section %s to %q to avoid a collision", (&iniSection{typ: s.typ, name: old}).header(), nw))
		if s.typ == `preprocessor` {
			for _, fs := range ff.sections {
				if fs.typ == `follower` {
					fs.renameRefs(`preprocessor`, old, nw)
				}
			}
		}
	}

	var bb bytes.Buffer
	fmt.Fprintln(&bb, `# Gravwell Windows ingester configuration`)
	fmt.Fprintln(&bb, `# Migrated from the legacy Windows Events and Windows File Follow ingesters`)
	fmt.Fprintln(&bb)

	// singletons first
	for _, typ := range singletonSections {
		es, fs := ev.find(typ, ``), ff.find(typ, ``)
		if es == nil && fs == nil {
			continue
		}
		merged := &iniSection{typ: typ}
		if es != nil {
			merged.lines = append(merged.lines, trimTrailingBlank(es.lines)...)
		}
		if fs != nil {
			var have map[string][]string
			if es != nil {
				have = es.values()
			}
			var extra []string
			for k, vals := range fs.values() {
				if hv, ok := have[k]; ok {
					if !slices.Equal(hv, vals) {
						warnings = append(warnings, fmt.Sprintf("%s %s differs between legacy configs, keeping the Windows Events value", merged.header(), k))
					}
					continue
				}
				extra = append(extra, k)
			}
			if len(extra) > 0 {
				merged.lines = append(merged.lines, `# migrated from the File Follow ingester`)
				for _, ln := range fs.lines {
					if k, _, ok := lineKV(ln); ok && slices.Contains(extra, k) {
						merged.lines = append(merged.lines, ln)
					}
				}
			}
		}
		fmt.Fprintln(&bb, merged.header())
		for _, ln := range merged.lines {
			fmt.Fprintln(&bb, ln)
		}
		fmt.Fprintln(&bb)
	}

	// then named sections, event log first
	for _, f := range []*iniFile{&ev, &ff} {
		for _, s := range f.sections {
			if slices.Contains(singletonSections, s.typ) {
				continue
			}
			fmt.Fprintln(&bb, s.header())
			for _, ln := range trimTrailingBlank(s.lines) {
				fmt.Fprintln(&bb, ln)
			}
			fmt.Fprintln(&bb)
		}
	}

	out = bb.Bytes()
	if _, err = ParseConfig(out); err != nil {
		err = fmt.Errorf("merged configuration is invalid: %w", err)
		out = nil
	}
	return
}

// MigrationPaths holds the absolute paths used by MigrateLegacy.
type MigrationPaths struct {
	EventLogConfig   string
	EventLogBookmark string
	FollowConfig     string
	FollowState      string
	Config           string
	Bookmark         string
	State            string
}

// DefaultMigrationPaths returns the standard %PROGRAMDATA% locations.
func DefaultMigrationPaths() (mp MigrationPaths, err error) {
	for _, p := range []struct {
		dst *string
		rel string
	}{
		{&mp.EventLogConfig, LegacyEventLogConfigPath},
		{&mp.EventLogBookmark, LegacyEventLogBookmarkPath},
		{&mp.FollowConfig, LegacyFileFollowConfigPath},
		{&mp.FollowState, LegacyFileFollowStatePath},
		{&mp.Config, DefaultConfigPath},
		{&mp.Bookmark, DefaultBookmarkPath},
		{&mp.State, DefaultStatePath},
	} {
		if *p.dst, err = ProgramDataPath(p.rel); err != nil {
			return
		}
	}
	return
}

// MigrateLegacy merges the legacy configs into mp.Config and copies the
// default-location bookmark and state files so no data is re-ingested.  It is
// idempotent: if mp.Config already exists nothing is changed and done is false.
func MigrateLegacy(mp MigrationPaths) (done bool, warnings []string, err error) {
	if _, err = os.Stat(mp.Config); err == nil {
		return false, nil, nil
	} else if !os.IsNotExist(err) {
		return
	}
	var evb, ffb []byte
	if evb, err = readOptional(mp.EventLogConfig); err != nil {
		return
	} else if ffb, err = readOptional(mp.FollowConfig); err != nil {
		return
	}
	var out []byte
	if out, warnings, err = MergeLegacyConfigs(evb, ffb); err != nil {
		return
	}
	merged, err := ParseConfig(out)
	if err != nil {
		return
	}
	// copy state that lived at the legacy default locations, only when the
	// legacy config did not explicitly point somewhere else
	if evb != nil && !hasGlobalKey(evb, `bookmark-location`) && merged.Global.Bookmark_Location == mp.Bookmark {
		if err = copyIfMissing(mp.EventLogBookmark, mp.Bookmark); err != nil {
			return
		}
	}
	if ffb != nil && !hasGlobalKey(ffb, `state-store-location`) && merged.Global.State_Store_Location == mp.State {
		if err = copyIfMissing(mp.FollowState, mp.State); err != nil {
			return
		}
	}
	if err = os.MkdirAll(filepath.Dir(mp.Config), 0750); err != nil {
		return
	}
	if err = os.WriteFile(mp.Config, out, 0640); err != nil {
		return
	}
	done = true
	return
}

func hasGlobalKey(b []byte, key string) bool {
	f := parseINI(b)
	if s := f.find(`global`, ``); s != nil {
		_, ok := s.values()[key]
		return ok
	}
	return false
}

func readOptional(p string) ([]byte, error) {
	if p == `` {
		return nil, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

// copyIfMissing copies src to dst if src exists and dst does not.
func copyIfMissing(src, dst string) (err error) {
	if _, err = os.Stat(dst); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return
	}
	var in *os.File
	if in, err = os.Open(src); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return
	}
	var out *os.File
	if out, err = os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640); err != nil {
		return
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return
	}
	return out.Close()
}
