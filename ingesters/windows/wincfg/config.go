/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

// Package wincfg contains the configuration for the unified Gravwell Windows
// ingester, which hosts Windows Event Log channels, file followers and ETW
// sessions in a single process.  The package is intentionally portable so that
// configuration parsing and migration can be tested on any platform.
package wincfg

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/gravwell/gravwell/v3/ingest/attach"
	"github.com/gravwell/gravwell/v3/ingest/config"
	"github.com/gravwell/gravwell/v3/ingest/entry"
	"github.com/gravwell/gravwell/v3/ingest/processors"
)

const (
	// ServiceName is the Windows service name of the unified ingester.
	ServiceName = `GravwellWindows`
	// IngesterName is the name reported to the indexers.
	IngesterName = `Windows`
	// AppName is used as the syslog appname for log messages.
	AppName = `gravwell_windows`

	defaultMaxWatchedFiles = 1024
)

var (
	// DefaultDir is the directory, relative to %PROGRAMDATA%, holding config and state.
	DefaultDir = filepath.Join(`gravwell`, `windows`)
	// DefaultConfigPath is the config file location, relative to %PROGRAMDATA%.
	DefaultConfigPath = filepath.Join(DefaultDir, `windows.cfg`)
	// DefaultConfigOverlayPath is the conf.d style overlay directory, relative to %PROGRAMDATA%.
	DefaultConfigOverlayPath = filepath.Join(DefaultDir, `windows.conf.d`)
	// DefaultBookmarkPath is the event log bookmark location, relative to %PROGRAMDATA%.
	DefaultBookmarkPath = filepath.Join(DefaultDir, `bookmark`)
	// DefaultStatePath is the file follower state location, relative to %PROGRAMDATA%.
	DefaultStatePath = filepath.Join(DefaultDir, `file_follow.state`)

	ErrNoInputs = errors.New("no EventChannel, Follower, or ETW sections specified")
	ErrNoTags   = errors.New("no tags specified")
)

// Global is the union of the [Global] sections of the legacy Windows Events and
// Windows File Follow ingesters, so either legacy config parses unchanged.
type Global struct {
	config.IngestConfig
	// event log
	Bookmark_Location string
	Ignore_Timestamps bool
	// file follower
	Max_Files_Watched    int
	State_Store_Location string
}

// Config is the full unified ingester configuration.
type Config struct {
	Global       Global
	Attach       attach.AttachConfig
	EventChannel map[string]*EventStreamConfig
	Follower     map[string]*FollowerConfig
	ETW          map[string]*ETWConfig
	Preprocessor processors.ProcessorConfig
	TimeFormat   config.CustomTimeFormat
}

// GetConfig loads, overlays and verifies the configuration.  overlayPath may be empty.
func GetConfig(path, overlayPath string) (*Config, error) {
	var c Config
	if err := config.LoadConfigFile(&c, path); err != nil {
		return nil, err
	} else if err = config.LoadConfigOverlays(&c, overlayPath); err != nil {
		return nil, err
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ParseConfig parses and verifies a configuration held in memory.
func ParseConfig(b []byte) (*Config, error) {
	var c Config
	if err := config.LoadConfigBytes(&c, b); err != nil {
		return nil, err
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Verify validates the configuration and fills in defaults.
func (c *Config) Verify() (err error) {
	if err = c.Global.IngestConfig.Verify(); err != nil {
		return
	} else if err = c.Attach.Verify(); err != nil {
		return
	} else if err = c.Preprocessor.Validate(); err != nil {
		return
	} else if err = c.TimeFormat.Validate(); err != nil {
		return
	}
	if len(c.EventChannel) == 0 && len(c.Follower) == 0 && len(c.ETW) == 0 {
		return ErrNoInputs
	}
	if c.Global.Bookmark_Location == `` {
		if c.Global.Bookmark_Location, err = ProgramDataPath(DefaultBookmarkPath); err != nil {
			return
		}
	}
	if c.Global.State_Store_Location == `` {
		if c.Global.State_Store_Location, err = ProgramDataPath(DefaultStatePath); err != nil {
			return
		}
	}
	if c.Global.Max_Files_Watched <= 0 {
		c.Global.Max_Files_Watched = defaultMaxWatchedFiles
	}

	for k, v := range c.EventChannel {
		if v == nil {
			return fmt.Errorf("EventChannel %q is empty", k)
		}
		v.normalize()
		if err = v.Validate(); err != nil {
			return fmt.Errorf("EventChannel %q: %w", k, err)
		} else if err = c.Preprocessor.CheckProcessors(v.Preprocessor); err != nil {
			return fmt.Errorf("EventChannel %q preprocessor invalid: %w", k, err)
		}
	}
	for k, v := range c.Follower {
		if v == nil {
			return fmt.Errorf("Follower %q is empty", k)
		}
		if err = v.Validate(k); err != nil {
			return
		} else if err = c.Preprocessor.CheckProcessors(v.Preprocessor); err != nil {
			return fmt.Errorf("Follower %q preprocessor invalid: %w", k, err)
		}
	}
	for k, v := range c.ETW {
		if v == nil {
			return fmt.Errorf("ETW %q is empty", k)
		}
		if err = v.Validate(k); err != nil {
			return fmt.Errorf("ETW %q: %w", k, err)
		} else if err = c.Preprocessor.CheckProcessors(v.Preprocessor); err != nil {
			return fmt.Errorf("ETW %q preprocessor invalid: %w", k, err)
		}
	}
	return nil
}

// Tags returns the sorted, de-duplicated set of tags used across every input type.
func (c *Config) Tags() ([]string, error) {
	mp := map[string]struct{}{}
	add := func(t string) {
		if t == `` {
			t = entry.DefaultTagName
		}
		mp[t] = struct{}{}
	}
	for _, v := range c.EventChannel {
		add(v.Tag_Name)
	}
	for _, v := range c.Follower {
		add(v.Tag_Name)
	}
	for _, v := range c.ETW {
		add(v.Tag_Name)
	}
	if len(mp) == 0 {
		return nil, ErrNoTags
	}
	tags := make([]string, 0, len(mp))
	for k := range mp {
		tags = append(tags, k)
	}
	sort.Strings(tags)
	return tags, nil
}

// Followers returns copies of the follower configs with the global time formats attached.
func (c *Config) Followers() map[string]FollowerConfig {
	mp := make(map[string]FollowerConfig, len(c.Follower))
	for k, v := range c.Follower {
		if v != nil {
			f := *v
			f.timeFormats = c.TimeFormat
			mp[k] = f
		}
	}
	return mp
}

// IngestBaseConfig and AttachConfig satisfy the helper interfaces used across ingesters.
func (c *Config) IngestBaseConfig() config.IngestConfig { return c.Global.IngestConfig }
func (c *Config) AttachConfig() attach.AttachConfig     { return c.Attach }

// RawConfig returns an object suitable for IngestMuxer.SetRawConfiguration.
func (c *Config) RawConfig() interface{} {
	if c == nil {
		return nil
	}
	return *c
}
