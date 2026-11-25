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
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modtdh      = windows.NewLazySystemDLL("tdh.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procStartTraceW     = modadvapi32.NewProc("StartTraceW")
	procControlTraceW   = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2  = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW      = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace    = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace      = modadvapi32.NewProc("CloseTrace")
	procChangeSvcConfg2 = modadvapi32.NewProc("ChangeServiceConfig2W")

	procTdhEnumerateProviders                = modtdh.NewProc("TdhEnumerateProviders")
	procTdhEnumerateProviderFieldInformation = modtdh.NewProc("TdhEnumerateProviderFieldInformation")
	procTdhGetEventInformation               = modtdh.NewProc("TdhGetEventInformation")
	procTdhGetEventMapInformation            = modtdh.NewProc("TdhGetEventMapInformation")
	procTdhFormatProperty                    = modtdh.NewProc("TdhFormatProperty")

	procGetProcessInformation      = modkernel32.NewProc("GetProcessInformation")
	procInstallELAMCertificateInfo = modkernel32.NewProc("InstallELAMCertificateInfo")
)

// errno converts a Win32 status code into an error, nil on success.
func errno(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

func startTrace(handle *uint64, name *uint16, props *eventTraceProperties) error {
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)))
	return errno(r)
}

func controlTrace(handle uint64, name *uint16, props *eventTraceProperties, code uint32) error {
	r, _, _ := procControlTraceW.Call(uintptr(handle), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)), uintptr(code))
	return errno(r)
}

func enableTraceEx2(handle uint64, provider *GUID, code uint32, level uint8, anyKW, allKW uint64, timeout uint32, params *enableTraceParameters) error {
	r, _, _ := procEnableTraceEx2.Call(uintptr(handle), uintptr(unsafe.Pointer(provider)), uintptr(code), uintptr(level),
		uintptr(anyKW), uintptr(allKW), uintptr(timeout), uintptr(unsafe.Pointer(params)))
	return errno(r)
}

func openTrace(lf *eventTraceLogfile) (uint64, error) {
	r, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	if uint64(r) == invalidProcessTraceHandle {
		return 0, err
	}
	return uint64(r), nil
}

func processTrace(handle *uint64) error {
	r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(handle)), 1, 0, 0)
	return errno(r)
}

func closeTrace(handle uint64) error {
	r, _, _ := procCloseTrace.Call(uintptr(handle))
	return errno(r)
}
