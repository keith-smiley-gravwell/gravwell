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
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/gravwell/gravwell/v3/filewatch"
	"github.com/gravwell/gravwell/v3/ingest/log"
	"github.com/gravwell/gravwell/v3/ingest/processors"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
)

// fileFollowInput consumes [Follower] sections.
type fileFollowInput struct {
	cfg   *wincfg.Config
	wtchr *filewatch.WatchManager
	procs []*processors.ProcessorSet
	wg    sync.WaitGroup
}

func newFileFollowInput(cfg *wincfg.Config) (*fileFollowInput, error) {
	wtchr, err := filewatch.NewWatcher(cfg.Global.State_Store_Location)
	if err != nil {
		return nil, fmt.Errorf("failed to open file follower state %s: %w", cfg.Global.State_Store_Location, err)
	}
	wtchr.SetMaxFilesWatched(cfg.Global.Max_Files_Watched)
	return &fileFollowInput{cfg: cfg, wtchr: wtchr}, nil
}

func (f *fileFollowInput) Name() string { return `filefollow` }

func (f *fileFollowInput) Start(ctx context.Context, rt *runtimeEnv, errs chan<- error) error {
	igst := rt.igst
	window, err := f.cfg.Global.GlobalTimestampWindow()
	if err != nil {
		return fmt.Errorf("failed to get global timestamp window: %w", err)
	}
	for k, val := range f.cfg.Followers() {
		pproc, err := f.cfg.Preprocessor.ProcessorSet(igst, val.Preprocessor)
		if err != nil {
			return fmt.Errorf("preprocessor construction error for %s: %w", k, err)
		}
		f.procs = append(f.procs, pproc)
		tag, err := igst.GetTag(val.Tag_Name)
		if err != nil {
			return fmt.Errorf("failed to resolve tag %q for %s: %w", val.Tag_Name, k, err)
		}
		lh, err := filewatch.NewLogHandler(filewatch.LogHandlerConfig{
			TagName:                 val.Tag_Name,
			Tag:                     tag,
			Src:                     rt.src,
			IgnoreTS:                val.Ignore_Timestamps,
			AssumeLocalTZ:           val.Assume_Local_Timezone,
			IgnorePrefixes:          val.Ignore_Line_Prefix,
			IgnoreGlobs:             val.Ignore_Glob,
			TimestampFormatOverride: val.TimestampOverride(),
			Logger:                  lg,
			TimezoneOverride:        val.Timezone_Override,
			UserTimeRegex:           val.Timestamp_Regex,
			UserTimeFormat:          val.Timestamp_Format_String,
			Ctx:                     ctx,
			TimeFormat:              val.TimeFormats(),
			AttachFilename:          val.Attach_Filename,
			Trim:                    val.Trim,
			TimestampWindow:         window,
		}, pproc)
		if err != nil {
			return fmt.Errorf("failed to create handler for %s: %w", k, err)
		}
		c := filewatch.WatchConfig{
			ConfigName: k,
			BaseDir:    val.Base_Directory,
			FileFilter: val.File_Filter,
			Hnd:        lh,
			Recursive:  val.Recursive,
		}
		if rex, ok, err := val.TimestampDelimited(); err != nil {
			return fmt.Errorf("invalid timestamp delimiter for %s: %w", k, err)
		} else if ok {
			c.Engine = filewatch.RegexEngine
			c.EngineArgs = rex
		} else if val.Regex_Delimiter != `` {
			c.Engine = filewatch.RegexEngine
			c.EngineArgs = val.Regex_Delimiter
		} else {
			c.Engine = filewatch.LineEngine
		}
		if err := f.wtchr.Add(c); err != nil {
			return fmt.Errorf("failed to add watch directory %s (%s): %w", val.Base_Directory, val.File_Filter, err)
		}
	}
	f.wtchr.SetLogger(igst)

	// catchup can take a long time on large directories, do it in the
	// background so the other inputs are not held up
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		qc := make(chan os.Signal)
		go func() {
			<-ctx.Done()
			close(qc)
		}()
		debugout("Performing catchup scan\n")
		quit, err := f.wtchr.Catchup(qc)
		if err != nil {
			lg.Error("failed to perform file follower catchup", log.KVErr(err))
			sendErr(errs, err)
			return
		} else if quit || ctx.Err() != nil {
			return
		}
		if err = f.wtchr.Start(); err != nil {
			lg.Error("failed to start file watcher", log.KVErr(err))
			sendErr(errs, err)
			return
		}
		debugout("File watcher started\n")
	}()
	return nil
}

func (f *fileFollowInput) Close() (err error) {
	f.wg.Wait()
	err = f.wtchr.Close()
	for _, p := range f.procs {
		if p != nil {
			if perr := p.Close(); perr != nil {
				lg.Error("failed to close preprocessor", log.KVErr(perr))
			}
		}
	}
	return
}
