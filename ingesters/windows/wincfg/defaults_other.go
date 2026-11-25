//go:build !windows

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package wincfg

import (
	"os"
	"path/filepath"
)

// ProgramDataPath mirrors the Windows implementation so the configuration
// logic can be exercised by tests on non-Windows hosts.  PROGRAMDATA is
// honored if set, otherwise the OS temp directory is used.
func ProgramDataPath(name string) (string, error) {
	r := os.Getenv(`PROGRAMDATA`)
	if r == `` {
		r = os.TempDir()
	}
	return filepath.Join(r, filepath.FromSlash(name)), nil
}
