/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

// ProviderParams describes how a single provider is enabled on a session.
type ProviderParams struct {
	Provider ProviderSpec
	Level    uint8
	MatchAny KeywordSpec
	MatchAll KeywordSpec
	EventIDs []uint16
}

// SessionParams describes a real-time ETW session.
type SessionParams struct {
	Name         string // config name, used for logging
	SessionName  string // ETW session name
	BufferSizeKB uint32
	MinBuffers   uint32
	MaxBuffers   uint32
	Providers    []ProviderParams
}
