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
	"fmt"
	"strings"

	"github.com/gravwell/gravwell/v3/etw"
	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/entry"
)

const (
	defaultETWBufferKB = 64
	minETWBufferKB     = 4
	maxETWBufferKB     = 16 * 1024
	maxETWBuffers      = 4096

	// ETWSessionPrefix is prepended to the section name when no Session-Name is given.
	ETWSessionPrefix = `Gravwell-`
)

// ETWConfig is an [ETW "name"] section.  Each section is one real-time ETW
// session with one or more providers enabled on it.
type ETWConfig struct {
	Tag_Name          string
	Provider          []string // provider names or GUIDs
	Level             string   // critical, error, warning, information, verbose or 0-255
	Match_Any_Keyword []string // hex/decimal masks or keyword names
	Match_All_Keyword []string // hex/decimal masks or keyword names
	Event_ID          []string // event IDs to accept: 4688, 1-10, or CSV
	Session_Name      string
	Buffer_Size_KB    int
	Min_Buffers       int
	Max_Buffers       int
	Preprocessor      []string

	providers []etw.ProviderSpec
	level     uint8
	anyKW     etw.KeywordSpec
	allKW     etw.KeywordSpec
	eventIDs  []uint16
}

// Validate parses the section and applies defaults.
func (e *ETWConfig) Validate(name string) (err error) {
	e.Tag_Name = strings.TrimSpace(e.Tag_Name)
	if e.Tag_Name == `` {
		e.Tag_Name = entry.DefaultTagName
	}
	if ingest.CheckTag(e.Tag_Name) != nil {
		return errors.New("invalid characters in Tag-Name " + e.Tag_Name)
	}
	if len(e.Provider) == 0 {
		return errors.New("no Provider specified")
	}
	e.providers = e.providers[:0]
	seen := map[string]bool{}
	for _, p := range e.Provider {
		var ps etw.ProviderSpec
		if ps, err = etw.ParseProvider(p); err != nil {
			return
		}
		key := strings.ToLower(ps.String())
		if seen[key] {
			return fmt.Errorf("duplicate Provider %q", p)
		}
		seen[key] = true
		e.providers = append(e.providers, ps)
	}
	if e.level, err = etw.ParseLevel(e.Level); err != nil {
		return
	}
	if e.anyKW, err = etw.ParseKeywords(e.Match_Any_Keyword); err != nil {
		return
	}
	if e.allKW, err = etw.ParseKeywords(e.Match_All_Keyword); err != nil {
		return
	}
	if (len(e.anyKW.Names) > 0 || len(e.allKW.Names) > 0) && len(e.providers) > 1 {
		return errors.New("keyword names may only be used with a single Provider, use numeric masks instead")
	}
	if e.eventIDs, err = etw.ParseEventIDs(e.Event_ID); err != nil {
		return
	}
	if e.Session_Name = strings.TrimSpace(e.Session_Name); e.Session_Name == `` {
		e.Session_Name = ETWSessionPrefix + name
	}
	if err = etw.ValidSessionName(e.Session_Name); err != nil {
		return
	}
	if e.Buffer_Size_KB == 0 {
		e.Buffer_Size_KB = defaultETWBufferKB
	} else if e.Buffer_Size_KB < minETWBufferKB || e.Buffer_Size_KB > maxETWBufferKB {
		return fmt.Errorf("Buffer-Size-KB must be between %d and %d", minETWBufferKB, maxETWBufferKB)
	}
	if e.Min_Buffers < 0 || e.Max_Buffers < 0 || e.Min_Buffers > maxETWBuffers || e.Max_Buffers > maxETWBuffers {
		return fmt.Errorf("Min-Buffers and Max-Buffers must be between 0 and %d", maxETWBuffers)
	} else if e.Max_Buffers != 0 && e.Min_Buffers > e.Max_Buffers {
		return errors.New("Min-Buffers is greater than Max-Buffers")
	}
	return nil
}

// Params converts a validated section into session parameters.
func (e *ETWConfig) Params(name string) etw.SessionParams {
	sp := etw.SessionParams{
		Name:         name,
		SessionName:  e.Session_Name,
		BufferSizeKB: uint32(e.Buffer_Size_KB),
		MinBuffers:   uint32(e.Min_Buffers),
		MaxBuffers:   uint32(e.Max_Buffers),
	}
	for _, p := range e.providers {
		sp.Providers = append(sp.Providers, etw.ProviderParams{
			Provider: p,
			Level:    e.level,
			MatchAny: e.anyKW,
			MatchAll: e.allKW,
			EventIDs: append([]uint16(nil), e.eventIDs...),
		})
	}
	return sp
}

// SensitiveProviders returns the configured providers that require the
// consumer to run as an antimalware protected process light.
func (e *ETWConfig) SensitiveProviders() (r []etw.ProviderSpec) {
	for _, p := range e.providers {
		if etw.RequiresPPL(p) {
			r = append(r, p)
		}
	}
	return
}
