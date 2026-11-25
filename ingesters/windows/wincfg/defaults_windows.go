//go:build windows

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

// ProgramDataPath returns name rooted at %PROGRAMDATA%, falling back to the
// directory of the running executable when PROGRAMDATA is not set.
func ProgramDataPath(name string) (string, error) {
	if r := os.Getenv(`PROGRAMDATA`); r != `` {
		return filepath.Join(r, name), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return ``, err
	}
	dir, err := filepath.Abs(filepath.Dir(exe))
	if err != nil {
		return ``, err
	}
	return filepath.Join(dir, name), nil
}
