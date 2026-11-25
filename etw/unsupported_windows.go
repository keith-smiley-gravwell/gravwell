//go:build windows && !(amd64 || arm64)

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package etw

import "errors"

// ErrUnsupportedArch is returned on 32-bit Windows, where the ETW structure
// layouts are not declared.
var ErrUnsupportedArch = errors.New("ETW consumption is only supported on 64-bit Windows")

type Stats struct {
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
}

type ConsumerConfig struct {
	EventBuffer int
	Protection  ProtectionChecker
}

type Consumer struct{}

func NewConsumer(SessionParams, ConsumerConfig) (*Consumer, error) { return nil, ErrUnsupportedArch }
func (c *Consumer) Start()                                         {}
func (c *Consumer) Events() <-chan *Event                          { return nil }
func (c *Consumer) Err() error                                     { return ErrUnsupportedArch }
func (c *Consumer) Name() string                                   { return `` }
func (c *Consumer) Stats() (Stats, error)                          { return Stats{}, ErrUnsupportedArch }
func (c *Consumer) Close() error                                   { return nil }

type CurrentProcess struct{}

func (CurrentProcess) ProtectionLevel() (uint32, error) { return 0, ErrUnsupportedArch }

func InstallELAMCertificateInfo(string) error      { return ErrUnsupportedArch }
func SetServiceLaunchProtected(string, bool) error { return ErrUnsupportedArch }
