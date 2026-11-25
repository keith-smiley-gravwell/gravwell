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
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	processProtectionLevelInfo = 7 // PROCESS_INFORMATION_CLASS ProcessProtectionLevelInfo

	serviceConfigLaunchProtected           = 12 // SERVICE_CONFIG_LAUNCH_PROTECTED
	serviceLaunchProtectedNone             = 0
	serviceLaunchProtectedAntimalwareLight = 3
)

// CurrentProcess reports the protection level of the running process.
type CurrentProcess struct{}

// ProtectionLevel implements ProtectionChecker.
func (CurrentProcess) ProtectionLevel() (uint32, error) {
	var lvl uint32
	if err := procGetProcessInformation.Find(); err != nil {
		return 0, err
	}
	r, _, err := procGetProcessInformation.Call(uintptr(windows.CurrentProcess()), processProtectionLevelInfo,
		uintptr(unsafe.Pointer(&lvl)), unsafe.Sizeof(lvl))
	if r == 0 {
		return 0, fmt.Errorf("GetProcessInformation: %w", err)
	}
	return lvl, nil
}

// InstallELAMCertificateInfo registers the certificate information embedded
// in an ELAM driver (its MicrosoftElamCertificateInfo resource) so services
// signed with those certificates may launch as antimalware PPL.  The driver
// must be signed by Microsoft through the Microsoft Virus Initiative.
func InstallELAMCertificateInfo(driverPath string) error {
	if err := procInstallELAMCertificateInfo.Find(); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(driverPath)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_DATA, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("failed to open ELAM driver %s: %w", driverPath, err)
	}
	defer windows.CloseHandle(h)
	r, _, err := procInstallELAMCertificateInfo.Call(uintptr(h))
	if r == 0 {
		return fmt.Errorf("InstallELAMCertificateInfo: %w", err)
	}
	return nil
}

type serviceLaunchProtectedInfo struct {
	LaunchProtected uint32
}

// SetServiceLaunchProtected configures the named service to launch as an
// antimalware protected process light (protected=true) or unprotected.
// Enabling protection only succeeds once InstallELAMCertificateInfo has
// registered the certificate the service binary is signed with.  Removing
// protection requires the caller to be running as a protected process; see
// docs for the troubleshooting procedure.
func SetServiceLaunchProtected(serviceName string, protected bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open service %s: %w", serviceName, err)
	}
	defer s.Close()
	info := serviceLaunchProtectedInfo{LaunchProtected: serviceLaunchProtectedNone}
	if protected {
		info.LaunchProtected = serviceLaunchProtectedAntimalwareLight
	}
	r, _, err := procChangeSvcConfg2.Call(uintptr(s.Handle), serviceConfigLaunchProtected, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return fmt.Errorf("ChangeServiceConfig2(SERVICE_CONFIG_LAUNCH_PROTECTED): %w", err)
	}
	return nil
}
