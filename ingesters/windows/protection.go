//go:build windows

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package main

import (
	"fmt"
	"os"

	"github.com/gravwell/gravwell/v3/etw"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
)

// runInstallELAM registers the certificate information of an MVI-signed ELAM
// driver; used by the installer when it ships an ELAM driver.
func runInstallELAM(driver string) int {
	if err := etw.InstallELAMCertificateInfo(driver); err != nil {
		fmt.Fprintf(os.Stderr, "failed to install ELAM certificate info: %v\n", err)
		return 1
	}
	fmt.Println("installed ELAM certificate information")
	return 0
}

// runSetProtected marks the service to launch as an antimalware protected process light.
func runSetProtected() int {
	if err := etw.SetServiceLaunchProtected(wincfg.ServiceName, true); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set service launch protection: %v\n", err)
		return 1
	}
	fmt.Printf("%s will launch as an antimalware protected process light\n", wincfg.ServiceName)
	return 0
}
