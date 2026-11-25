/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import (
	"strconv"
	"strings"
	"time"
)

// Decoding sources, see DECODING_SOURCE in tdh.h
const (
	DecodingSourceXMLFile     uint32 = 0
	DecodingSourceWbem        uint32 = 1
	DecodingSourceWPP         uint32 = 2
	DecodingSourceTlg         uint32 = 3
	DecodingSourceMax         uint32 = 4
	DecodingSourceUnavailable uint32 = 0xffffffff // no schema could be found
)

// DecodingSourceName returns a readable decoding source.
func DecodingSourceName(ds uint32) string {
	switch ds {
	case DecodingSourceXMLFile:
		return `Manifest`
	case DecodingSourceWbem:
		return `MOF`
	case DecodingSourceWPP:
		return `WPP`
	case DecodingSourceTlg:
		return `TraceLogging`
	case DecodingSourceUnavailable:
		return `Unavailable`
	}
	return strconv.FormatUint(uint64(ds), 10)
}

// Property is a named, decoded event property.  Value is one of nil, bool,
// int64, uint64, float64, string, []any, or []Property (a nested structure).
type Property struct {
	Name  string
	Value any
}

// Event is a fully decoded ETW event.  It holds only Go values so it can be
// built, tested and rendered on any platform.
type Event struct {
	Timestamp         time.Time
	ProviderName      string
	ProviderGUID      GUID
	EventID           uint16
	Version           uint8
	Level             uint8
	LevelName         string
	Opcode            uint8
	OpcodeName        string
	Task              uint16
	TaskName          string
	Keywords          uint64
	KeywordNames      []string
	Channel           uint8
	ChannelName       string
	EventName         string
	ProcessID         uint32
	ThreadID          uint32
	ProcessorNumber   uint16
	ActivityID        GUID
	RelatedActivityID GUID
	Message           string
	DecodingSource    uint32
	Properties        []Property
	DecodingError     string
	RawUserData       []byte
}

// Property returns the top level property with the given name.
func (e *Event) Property(name string) (v any, ok bool) {
	for _, p := range e.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return nil, false
}

// cleanName trims the trailing whitespace TDH leaves on some names.
func cleanName(s string) string {
	return strings.TrimSpace(s)
}
