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
	"fmt"
	"strconv"
	"strings"
)

// Trace levels, see evntrace.h
const (
	LevelAlways      uint8 = 0
	LevelCritical    uint8 = 1
	LevelError       uint8 = 2
	LevelWarning     uint8 = 3
	LevelInformation uint8 = 4
	LevelVerbose     uint8 = 5
)

var (
	ErrInvalidLevel    = errors.New("invalid ETW level")
	ErrInvalidKeyword  = errors.New("invalid ETW keyword")
	ErrInvalidEventID  = errors.New("invalid ETW event ID")
	ErrInvalidProvider = errors.New("invalid ETW provider")
)

var levelNames = map[uint8]string{
	LevelAlways:      `LogAlways`,
	LevelCritical:    `Critical`,
	LevelError:       `Error`,
	LevelWarning:     `Warning`,
	LevelInformation: `Information`,
	LevelVerbose:     `Verbose`,
}

// LevelName returns the human name of a standard level.
func LevelName(l uint8) string {
	if n, ok := levelNames[l]; ok {
		return n
	}
	return strconv.Itoa(int(l))
}

// ParseLevel accepts a level name (critical, error, warning, information/info,
// verbose) or a number 0-255.  An empty string means verbose (everything).
func ParseLevel(s string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ``, `verbose`, `all`:
		return LevelVerbose, nil
	case `always`, `logalways`:
		return LevelAlways, nil
	case `critical`:
		return LevelCritical, nil
	case `error`:
		return LevelError, nil
	case `warning`, `warn`:
		return LevelWarning, nil
	case `information`, `info`, `informational`:
		return LevelInformation, nil
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
	if err != nil {
		return 0, fmt.Errorf("%w %q", ErrInvalidLevel, s)
	}
	return uint8(v), nil
}

// KeywordSpec is a parsed keyword list: a numeric mask plus names that must be
// resolved against the provider manifest at runtime.
type KeywordSpec struct {
	Mask  uint64
	Names []string
}

// ParseKeywords parses a list of keyword values.  Each value may be a number
// (0x prefixed hex or decimal) or a keyword name, e.g.
// KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE.  Values may be comma separated.
func ParseKeywords(vals []string) (ks KeywordSpec, err error) {
	for _, val := range vals {
		for _, v := range strings.Split(val, `,`) {
			if v = strings.TrimSpace(v); v == `` {
				continue
			}
			if n, perr := strconv.ParseUint(v, 0, 64); perr == nil {
				ks.Mask |= n
				continue
			}
			if !validKeywordName(v) {
				err = fmt.Errorf("%w %q", ErrInvalidKeyword, v)
				return
			}
			ks.Names = append(ks.Names, v)
		}
	}
	return
}

func validKeywordName(v string) bool {
	if v == `` {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == ':':
		default:
			return false
		}
	}
	return true
}

// ParseEventIDs parses event IDs given as numbers, comma separated lists, or
// inclusive ranges such as 1-10.
func ParseEventIDs(vals []string) (ids []uint16, err error) {
	seen := map[uint16]bool{}
	add := func(id uint16) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, val := range vals {
		for _, v := range strings.Split(val, `,`) {
			if v = strings.TrimSpace(v); v == `` {
				continue
			}
			if lo, hi, ok := strings.Cut(v, `-`); ok {
				var l, h uint64
				if l, err = strconv.ParseUint(strings.TrimSpace(lo), 10, 16); err != nil {
					return nil, fmt.Errorf("%w %q", ErrInvalidEventID, v)
				} else if h, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil {
					return nil, fmt.Errorf("%w %q", ErrInvalidEventID, v)
				} else if l > h {
					return nil, fmt.Errorf("%w %q: range start greater than end", ErrInvalidEventID, v)
				} else if h-l > maxEventIDFilter {
					return nil, fmt.Errorf("%w %q: range too large", ErrInvalidEventID, v)
				}
				for i := l; i <= h; i++ {
					add(uint16(i))
				}
				continue
			}
			n, perr := strconv.ParseUint(v, 10, 16)
			if perr != nil {
				return nil, fmt.Errorf("%w %q", ErrInvalidEventID, v)
			}
			add(uint16(n))
		}
	}
	if len(ids) > maxEventIDFilter {
		return nil, fmt.Errorf("%w: at most %d event IDs may be filtered", ErrInvalidEventID, maxEventIDFilter)
	}
	return
}

// MAX_EVENT_FILTER_EVENT_ID_COUNT from evntprov.h
const maxEventIDFilter = 64

// ProviderSpec identifies a provider either by GUID or by registered name.
type ProviderSpec struct {
	Name string
	GUID GUID
}

// ParseProvider accepts a provider GUID or registered provider name.
func ParseProvider(s string) (ps ProviderSpec, err error) {
	s = strings.TrimSpace(s)
	if s == `` {
		err = fmt.Errorf("%w: empty provider", ErrInvalidProvider)
		return
	}
	if g, gerr := ParseGUID(s); gerr == nil {
		ps.GUID = g
		return
	}
	if strings.ContainsAny(s, "{}") {
		err = fmt.Errorf("%w %q", ErrInvalidProvider, s)
		return
	}
	ps.Name = s
	return
}

// Resolved reports whether the provider GUID is known.
func (ps ProviderSpec) Resolved() bool {
	return !ps.GUID.IsZero()
}

func (ps ProviderSpec) String() string {
	if ps.Name != `` {
		return ps.Name
	}
	return ps.GUID.String()
}

// ValidSessionName checks the ETW session name constraints (non-empty, < 1024 chars).
func ValidSessionName(s string) error {
	if s == `` {
		return errors.New("empty ETW session name")
	} else if len(s) >= 1024 {
		return errors.New("ETW session name too long")
	}
	return nil
}
