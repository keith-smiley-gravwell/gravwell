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
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	defaultFlushTimerSec = 1
	allKeywords          = 0xffffffffffffffff
)

// Stats are the session counters reported by ETW.
type Stats struct {
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
}

// session is a real-time ETW trace session (the controller side).
type session struct {
	name    string
	namePtr *uint16
	handle  uint64
	enabled []GUID
}

// newPropertiesBuffer allocates EVENT_TRACE_PROPERTIES with room for the session name.
func newPropertiesBuffer() (*eventTraceProperties, []byte) {
	size := int(unsafe.Sizeof(eventTraceProperties{})) + maxSessionNameLen*2
	buf := make([]byte, size)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(size)
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	return props, buf
}

// startSession starts a real-time session, stopping a stale session of the
// same name (left over from a crash) if one exists.
func startSession(sp SessionParams) (*session, error) {
	if err := ValidSessionName(sp.SessionName); err != nil {
		return nil, err
	}
	namePtr, err := windows.UTF16PtrFromString(sp.SessionName)
	if err != nil {
		return nil, err
	}
	s := &session{name: sp.SessionName, namePtr: namePtr}
	for attempt := 0; attempt < 2; attempt++ {
		props, buf := newPropertiesBuffer()
		props.Wnode.Flags = wnodeFlagTracedGUID
		props.Wnode.ClientContext = 1 // QPC timestamps, converted to FILETIME by the consumer
		props.LogFileMode = eventTraceRealTimeMode
		props.BufferSize = sp.BufferSizeKB
		props.MinimumBuffers = sp.MinBuffers
		props.MaximumBuffers = sp.MaxBuffers
		props.FlushTimer = defaultFlushTimerSec
		err = startTrace(&s.handle, namePtr, props)
		runtime.KeepAlive(buf)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) || attempt > 0 {
			break
		}
		// a stale session with our name exists, stop it and retry
		if serr := stopSessionByName(namePtr); serr != nil {
			return nil, fmt.Errorf("session %q already exists and could not be stopped: %w", sp.SessionName, serr)
		}
	}
	return nil, fmt.Errorf("failed to start ETW session %q: %w", sp.SessionName, err)
}

func stopSessionByName(namePtr *uint16) error {
	props, buf := newPropertiesBuffer()
	err := controlTrace(0, namePtr, props, eventTraceControlStop)
	runtime.KeepAlive(buf)
	return err
}

// enable enables a provider on the session.
func (s *session) enable(guid GUID, pp ProviderParams, anyMask, allMask uint64) error {
	params := enableTraceParameters{Version: enableTraceParametersVersion2}
	var filter eventFilterDescriptor
	var filterBuf []byte
	if len(pp.EventIDs) > 0 {
		// EVENT_FILTER_EVENT_ID: FilterIn BOOLEAN, Reserved UCHAR, Count USHORT, Events[] USHORT
		filterBuf = make([]byte, 4+2*len(pp.EventIDs))
		filterBuf[0] = 1 // filter in
		binary.LittleEndian.PutUint16(filterBuf[2:], uint16(len(pp.EventIDs)))
		for i, id := range pp.EventIDs {
			binary.LittleEndian.PutUint16(filterBuf[4+2*i:], id)
		}
		filter = eventFilterDescriptor{
			Ptr:  uint64(uintptr(unsafe.Pointer(&filterBuf[0]))),
			Size: uint32(len(filterBuf)),
			Type: eventFilterTypeEventID,
		}
		params.EnableFilterDesc = &filter
		params.FilterDescCount = 1
	}
	g := guid
	err := enableTraceEx2(s.handle, &g, eventControlCodeEnableProvider, pp.Level, anyMask, allMask, 0, &params)
	runtime.KeepAlive(filterBuf)
	if err != nil {
		return err
	}
	s.enabled = append(s.enabled, guid)
	return nil
}

// stats queries the session counters.
func (s *session) stats() (st Stats, err error) {
	props, buf := newPropertiesBuffer()
	if err = controlTrace(s.handle, nil, props, eventTraceControlQuery); err != nil {
		return
	}
	st = Stats{
		EventsLost:          props.EventsLost,
		BuffersWritten:      props.BuffersWritten,
		LogBuffersLost:      props.LogBuffersLost,
		RealTimeBuffersLost: props.RealTimeBuffersLost,
		NumberOfBuffers:     props.NumberOfBuffers,
		FreeBuffers:         props.FreeBuffers,
	}
	runtime.KeepAlive(buf)
	return
}

// close disables every provider and stops the session.
func (s *session) close() error {
	for _, g := range s.enabled {
		gg := g
		enableTraceEx2(s.handle, &gg, eventControlCodeDisableProvider, 0, 0, 0, 0, nil)
	}
	s.enabled = nil
	props, buf := newPropertiesBuffer()
	err := controlTrace(s.handle, nil, props, eventTraceControlStop)
	runtime.KeepAlive(buf)
	return err
}
