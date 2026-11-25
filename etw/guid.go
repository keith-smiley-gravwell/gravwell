/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

// Package etw implements a pure-Go (no cgo) real-time consumer for Event Tracing
// for Windows.  Configuration parsing and JSON rendering are portable; the
// session, consumer and decoder are Windows only.
package etw

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidGUID = errors.New("invalid GUID")

// GUID has the same memory layout as the Windows GUID structure.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ParseGUID parses a GUID with or without surrounding braces, e.g.
// {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}.
func ParseGUID(s string) (g GUID, err error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `{`)
	s = strings.TrimSuffix(s, `}`)
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		err = fmt.Errorf("%w %q", ErrInvalidGUID, s)
		return
	}
	var b [16]byte
	raw := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err = hex.Decode(b[:], []byte(raw)); err != nil {
		err = fmt.Errorf("%w %q: %v", ErrInvalidGUID, s, err)
		return
	}
	g.Data1 = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	g.Data2 = uint16(b[4])<<8 | uint16(b[5])
	g.Data3 = uint16(b[6])<<8 | uint16(b[7])
	copy(g.Data4[:], b[8:])
	return
}

// IsGUID reports whether s looks like a GUID.
func IsGUID(s string) bool {
	_, err := ParseGUID(s)
	return err == nil
}

// IsZero reports whether the GUID is all zeros.
func (g GUID) IsZero() bool {
	return g == GUID{}
}

// String returns the canonical braced, lower-case representation.
func (g GUID) String() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// MarshalText implements encoding.TextMarshaler so GUIDs render as strings in JSON.
func (g GUID) MarshalText() ([]byte, error) {
	return []byte(g.String()), nil
}
