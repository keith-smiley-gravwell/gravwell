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
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const eventKeywordInformation = 0 // EVENT_FIELD_TYPE EventKeywordInformation

var (
	ErrProviderNotFound = errors.New("ETW provider is not registered")

	providerCacheMtx sync.Mutex
	providerCache    map[string]GUID // upper case name -> guid
)

// utf16At reads a NUL terminated UTF-16 string at off bytes into buf.
func utf16At(buf []byte, off uint32) string {
	if off == 0 || int(off)+2 > len(buf) {
		return ``
	}
	n := (len(buf) - int(off)) / 2
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[off])), n)
	for i, c := range u {
		if c == 0 {
			return windows.UTF16ToString(u[:i])
		}
	}
	return windows.UTF16ToString(u)
}

// tdhBuffer calls fn with a growing buffer until it stops returning ERROR_INSUFFICIENT_BUFFER.
func tdhBuffer(initial uint32, fn func(buf []byte, size *uint32) uintptr) ([]byte, error) {
	size := initial
	for i := 0; i < 8; i++ {
		buf := make([]byte, size)
		var p []byte = buf
		if size == 0 {
			p = nil
		}
		r := fn(p, &size)
		switch tdhErr(r) {
		case nil:
			return buf[:min(int(size), len(buf))], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue
		default:
			return nil, tdhErr(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

func tdhErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

func bufPtr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func loadProviders() (map[string]GUID, error) {
	buf, err := tdhBuffer(64*1024, func(b []byte, size *uint32) uintptr {
		r, _, _ := procTdhEnumerateProviders.Call(bufPtr(b), uintptr(unsafe.Pointer(size)))
		return r
	})
	if err != nil {
		return nil, fmt.Errorf("TdhEnumerateProviders: %w", err)
	}
	hdr := (*providerEnumerationInfo)(unsafe.Pointer(&buf[0]))
	mp := make(map[string]GUID, hdr.NumberOfProviders)
	base := unsafe.Sizeof(providerEnumerationInfo{})
	stride := unsafe.Sizeof(traceProviderInfo{})
	for i := uintptr(0); i < uintptr(hdr.NumberOfProviders); i++ {
		off := base + i*stride
		if off+stride > uintptr(len(buf)) {
			break
		}
		tpi := (*traceProviderInfo)(unsafe.Pointer(&buf[off]))
		if name := utf16At(buf, tpi.ProviderNameOffset); name != `` {
			mp[strings.ToUpper(name)] = tpi.ProviderGUID
		}
	}
	return mp, nil
}

// ResolveProvider returns the GUID for a provider spec, looking registered
// provider names up through TDH.
func ResolveProvider(ps ProviderSpec) (GUID, error) {
	if ps.Resolved() {
		return ps.GUID, nil
	}
	key := strings.ToUpper(ps.Name)
	providerCacheMtx.Lock()
	defer providerCacheMtx.Unlock()
	if g, ok := providerCache[key]; ok {
		return g, nil
	}
	// refresh, providers may have been registered since the last lookup
	mp, err := loadProviders()
	if err != nil {
		return GUID{}, err
	}
	providerCache = mp
	if g, ok := providerCache[key]; ok {
		return g, nil
	}
	return GUID{}, fmt.Errorf("%w: %q (TraceLogging providers must be specified by GUID)", ErrProviderNotFound, ps.Name)
}

// ProviderKeywords returns the keyword names and masks declared by a provider manifest.
func ProviderKeywords(guid GUID) (map[string]uint64, error) {
	g := guid
	buf, err := tdhBuffer(4096, func(b []byte, size *uint32) uintptr {
		r, _, _ := procTdhEnumerateProviderFieldInformation.Call(uintptr(unsafe.Pointer(&g)), eventKeywordInformation, bufPtr(b), uintptr(unsafe.Pointer(size)))
		return r
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate keywords for %s: %w", guid, err)
	}
	hdr := (*providerFieldInfoArray)(unsafe.Pointer(&buf[0]))
	mp := make(map[string]uint64, hdr.NumberOfElements)
	base := unsafe.Sizeof(providerFieldInfoArray{})
	stride := unsafe.Sizeof(providerFieldInfo{})
	for i := uintptr(0); i < uintptr(hdr.NumberOfElements); i++ {
		off := base + i*stride
		if off+stride > uintptr(len(buf)) {
			break
		}
		fi := (*providerFieldInfo)(unsafe.Pointer(&buf[off]))
		if name := utf16At(buf, fi.NameOffset); name != `` {
			mp[strings.ToUpper(name)] = fi.Value
		}
	}
	return mp, nil
}

// ResolveKeywords turns a keyword spec into a mask, looking names up in the
// provider manifest.  An empty spec returns def.
func ResolveKeywords(guid GUID, ks KeywordSpec, def uint64) (uint64, error) {
	if ks.Mask == 0 && len(ks.Names) == 0 {
		return def, nil
	}
	mask := ks.Mask
	if len(ks.Names) == 0 {
		return mask, nil
	}
	kws, err := ProviderKeywords(guid)
	if err != nil {
		return 0, err
	}
	for _, n := range ks.Names {
		v, ok := kws[strings.ToUpper(n)]
		if !ok {
			return 0, fmt.Errorf("%w %q is not declared by provider %s", ErrInvalidKeyword, n, guid)
		}
		mask |= v
	}
	return mask, nil
}
