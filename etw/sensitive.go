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
)

// Process protection levels, see PROCESS_PROTECTION_LEVEL_INFORMATION in processthreadsapi.h.
const (
	ProtectionLevelWinTCBLight      uint32 = 0
	ProtectionLevelWindows          uint32 = 1
	ProtectionLevelWindowsLight     uint32 = 2
	ProtectionLevelAntimalwareLight uint32 = 3
	ProtectionLevelLSALight         uint32 = 4
	ProtectionLevelWinTCB           uint32 = 5
	ProtectionLevelCodegenLight     uint32 = 6
	ProtectionLevelAuthenticode     uint32 = 7
	ProtectionLevelPPLApp           uint32 = 8
	ProtectionLevelNone             uint32 = 0xfffffffe
)

// ErrRequiresPPL is returned when a sensitive provider is configured but the
// process is not running as an antimalware protected process light.
var ErrRequiresPPL = errors.New("provider requires the ingester to run as an antimalware protected process light (PPL)")

// ThreatIntelligenceGUID is the Microsoft-Windows-Threat-Intelligence provider.
var ThreatIntelligenceGUID = GUID{0xf4e1897c, 0xbb5d, 0x5668, [8]byte{0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44}}

// sensitiveProviders only deliver events to consumers running at an
// antimalware PPL protection level (or higher).
var sensitiveProviders = map[GUID]string{
	ThreatIntelligenceGUID: `Microsoft-Windows-Threat-Intelligence`,
}

// RequiresPPL reports whether the provider requires a PPL consumer.
func RequiresPPL(p ProviderSpec) bool {
	if p.Resolved() {
		_, ok := sensitiveProviders[p.GUID]
		return ok
	}
	for _, n := range sensitiveProviders {
		if strings.EqualFold(n, p.Name) {
			return true
		}
	}
	return false
}

// ProtectionLevelName returns a readable protection level.
func ProtectionLevelName(l uint32) string {
	switch l {
	case ProtectionLevelWinTCBLight:
		return `WinTCB-Light`
	case ProtectionLevelWindows:
		return `Windows`
	case ProtectionLevelWindowsLight:
		return `Windows-Light`
	case ProtectionLevelAntimalwareLight:
		return `Antimalware-Light`
	case ProtectionLevelLSALight:
		return `LSA-Light`
	case ProtectionLevelWinTCB:
		return `WinTCB`
	case ProtectionLevelCodegenLight:
		return `CodeGen-Light`
	case ProtectionLevelAuthenticode:
		return `Authenticode`
	case ProtectionLevelPPLApp:
		return `PPL-App`
	case ProtectionLevelNone:
		return `None`
	}
	return fmt.Sprintf("Unknown(%d)", l)
}

// protectionSatisfiesPPL reports whether level can consume antimalware-only providers.
// Antimalware-Light and the full protected levels qualify.
func protectionSatisfiesPPL(level uint32) bool {
	switch level {
	case ProtectionLevelAntimalwareLight, ProtectionLevelWinTCB, ProtectionLevelWinTCBLight, ProtectionLevelWindows:
		return true
	}
	return false
}

// ProtectionChecker reports the protection level of the running process.  It
// is an interface so the gating logic can be tested off Windows.
type ProtectionChecker interface {
	ProtectionLevel() (uint32, error)
}

// CheckSensitive verifies that every sensitive provider in sp can be consumed
// at the current protection level.  The returned error wraps ErrRequiresPPL and
// names the offending providers and the current protection level.
func CheckSensitive(sp SessionParams, pc ProtectionChecker) error {
	var names []string
	for _, p := range sp.Providers {
		if RequiresPPL(p.Provider) {
			names = append(names, p.Provider.String())
		}
	}
	if len(names) == 0 {
		return nil
	}
	if pc == nil {
		return fmt.Errorf("%w: %s; protection level unknown", ErrRequiresPPL, strings.Join(names, ", "))
	}
	lvl, err := pc.ProtectionLevel()
	if err != nil {
		return fmt.Errorf("%w: %s; failed to query protection level: %v", ErrRequiresPPL, strings.Join(names, ", "), err)
	}
	if protectionSatisfiesPPL(lvl) {
		return nil
	}
	return fmt.Errorf("%w: %s; service is running at protection level %s",
		ErrRequiresPPL, strings.Join(names, ", "), ProtectionLevelName(lvl))
}
