/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package wincfg

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/config"
	"github.com/gravwell/gravwell/v3/ingest/entry"
	"github.com/gravwell/gravwell/v3/timegrinder"
)

var (
	ErrTimestampDelimiterMissingOverride = errors.New("Timestamp delimiting requires a defined timestamp override")
)

// FollowerConfig is a [Follower "name"] section.  It is identical to the section
// used by the legacy File Follow ingester.
type FollowerConfig struct {
	Base_Directory            string // the base directory we will be watching
	File_Filter               string // the glob for pattern matching
	Tag_Name                  string
	Ignore_Timestamps         bool //Just apply the current timestamp to lines as we get them
	Assume_Local_Timezone     bool
	Recursive                 bool // Should we descend into child directories?
	Attach_Filename           bool // attach the full path of the file to each entry
	Ignore_Line_Prefix        []string
	Ignore_Glob               []string
	Trim                      bool
	Timestamp_Format_Override string //override the timestamp format
	Timestamp_Delimited       bool
	Timezone_Override         string
	Regex_Delimiter           string
	Preprocessor              []string
	// these two must be used together
	Timestamp_Regex         string
	Timestamp_Format_String string

	timeFormats config.CustomTimeFormat
}

// Validate checks the follower and applies defaults.
func (f *FollowerConfig) Validate(name string) error {
	if len(f.Base_Directory) == 0 {
		return errors.New("No Base-Directory provided for " + name)
	}
	if len(f.Tag_Name) == 0 {
		f.Tag_Name = entry.DefaultTagName
	}
	if f.Timestamp_Delimited && f.Timestamp_Format_Override == `` {
		return ErrTimestampDelimiterMissingOverride
	}
	if (f.Timestamp_Regex != `` && f.Timestamp_Format_String == ``) || (f.Timestamp_Regex == `` && f.Timestamp_Format_String != ``) {
		return errors.New("Timestamp-Regex and Timestamp-Format-String must both be specified, or both left unset")
	}
	if f.Timestamp_Regex != `` {
		if _, err := timegrinder.NewUserProcessor("user", f.Timestamp_Regex, f.Timestamp_Format_String); err != nil {
			return fmt.Errorf("Failed to parse Timestamp-Regex and Timestamp-Format-String defs: %v", err)
		}
	}
	if ingest.CheckTag(f.Tag_Name) != nil {
		return errors.New("Invalid characters in the Tag-Name for " + name)
	}
	f.Base_Directory = filepath.Clean(f.Base_Directory)
	if f.Timezone_Override != `` {
		if f.Assume_Local_Timezone {
			return fmt.Errorf("Cannot specify Assume-Local-Timezone and Timezone-Override in the same follower %v", name)
		}
		if _, err := time.LoadLocation(f.Timezone_Override); err != nil {
			return fmt.Errorf("Invalid timezone override %v in follower %v: %v", f.Timezone_Override, name, err)
		}
	}
	return nil
}

// TimeFormats returns the custom time formats attached by Config.Followers.
func (f FollowerConfig) TimeFormats() config.CustomTimeFormat {
	return f.timeFormats
}

// TimestampOverride returns the trimmed timestamp format override.
func (f FollowerConfig) TimestampOverride() string {
	return strings.TrimSpace(f.Timestamp_Format_Override)
}

// TimestampDelimited returns the regex used to split entries on timestamps, if enabled.
func (f FollowerConfig) TimestampDelimited() (rex string, ok bool, err error) {
	if !f.Timestamp_Delimited {
		return
	}
	if f.Timestamp_Format_Override == `` {
		err = ErrTimestampDelimiterMissingOverride
		return
	}
	cfg := timegrinder.Config{
		FormatOverride: f.Timestamp_Format_Override,
	}
	var tg *timegrinder.TimeGrinder
	var proc timegrinder.Processor
	if tg, err = timegrinder.New(cfg); err != nil {
		return
	} else if err = f.timeFormats.LoadFormats(tg); err != nil {
		return
	}
	if proc, err = tg.OverrideProcessor(); err != nil {
		return
	}
	if rex = proc.ExtractionRegex(); rex == `` {
		err = errors.New("Missing timestamp processor extraction string")
		return
	}
	//fixup the regex string to fit on line breaks
	if strings.HasPrefix(rex, `\A`) {
		rex = `\n` + strings.TrimPrefix(rex, `\A`)
	}
	if strings.HasPrefix(rex, `^`) {
		rex = `\n` + strings.TrimPrefix(rex, `^`)
	}
	if _, err = regexp.Compile(rex); err != nil {
		return
	}
	ok = true
	return
}
