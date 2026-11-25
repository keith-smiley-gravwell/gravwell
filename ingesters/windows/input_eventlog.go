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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/crewjam/rfc5424"
	"github.com/gravwell/gravwell/v3/ingest/entry"
	"github.com/gravwell/gravwell/v3/ingest/log"
	"github.com/gravwell/gravwell/v3/ingest/processors"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
	"github.com/gravwell/gravwell/v3/timegrinder"
	"github.com/gravwell/gravwell/v3/winevent"
)

const (
	eventSampleInterval       = 250 * time.Millisecond
	eventChannelRetryInterval = 10 * time.Second

	//this is the error number that comes back when a channel disappears (winerror.h)
	ERROR_EVT_CHANNEL_NOT_FOUND uintptr = 15007
)

type eventSrc struct {
	params winevent.EventStreamParams
	h      *winevent.EventStreamHandle
	proc   *processors.ProcessorSet
	tag    entry.EntryTag
}

// eventLogInput consumes [EventChannel] sections through wevtapi.
type eventLogInput struct {
	cfg      *wincfg.Config
	streams  []winevent.EventStreamParams
	ignoreTS bool

	rt      *runtimeEnv
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	tg      *timegrinder.TimeGrinder
	bmk     *winevent.BookmarkHandler
	evtSrcs map[string]eventSrc
	dead    map[string]winevent.EventStreamParams
}

func newEventLogInput(cfg *wincfg.Config) *eventLogInput {
	return &eventLogInput{
		cfg:      cfg,
		ignoreTS: cfg.Global.Ignore_Timestamps,
		evtSrcs:  map[string]eventSrc{},
		dead:     map[string]winevent.EventStreamParams{},
	}
}

func (e *eventLogInput) Name() string { return `eventlog` }

func streamParams(name string, ec *wincfg.EventStreamConfig) (winevent.EventStreamParams, error) {
	dur, err := ec.Reachback()
	if err != nil {
		return winevent.EventStreamParams{}, err
	}
	return winevent.EventStreamParams{
		Name:         name,
		TagName:      ec.TagName(),
		Channel:      ec.Channel,
		Levels:       strings.Join(ec.Level, ","),
		EventIDs:     strings.Join(ec.EventID, ","),
		Providers:    append([]string{}, ec.Provider...),
		ReachBack:    dur,
		Preprocessor: ec.Preprocessor,
		ReqSize:      ec.Request_Size,
		BuffSize:     ec.Request_Buffer,
	}, nil
}

func (e *eventLogInput) Start(ctx context.Context, rt *runtimeEnv, errs chan<- error) (err error) {
	e.rt = rt
	for k, v := range e.cfg.EventChannel {
		var p winevent.EventStreamParams
		if p, err = streamParams(k, v); err != nil {
			return
		}
		e.streams = append(e.streams, p)
	}
	if !e.ignoreTS {
		var window timegrinder.TimestampWindow
		if window, err = e.cfg.Global.GlobalTimestampWindow(); err != nil {
			return
		}
		if e.tg, err = timegrinder.NewTimeGrinder(timegrinder.Config{TSWindow: window}); err != nil {
			return fmt.Errorf("failed to create timegrinder: %w", err)
		}
	}
	if e.bmk, err = winevent.NewBookmark(e.cfg.Global.Bookmark_Location); err != nil {
		return fmt.Errorf("failed to open bookmark %s: %w", e.cfg.Global.Bookmark_Location, err)
	}
	for _, c := range e.streams {
		evt, fatal, serr := e.initStream(c, true)
		if serr != nil {
			if fatal {
				return serr
			}
			e.dead[c.Name] = c
			continue
		}
		e.evtSrcs[c.Name] = evt
	}
	if len(e.evtSrcs) == 0 && len(e.dead) == 0 {
		return fmt.Errorf("no event channels could be opened")
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.wg.Add(1)
	go e.consumerRoutine(errs)
	return nil
}

func (e *eventLogInput) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	var rerr error
	for name, s := range e.evtSrcs {
		last := s.h.Last()
		if err := s.h.Close(); err != nil {
			rerr = fmt.Errorf("failed to close %s: %w", name, err)
		}
		if s.proc != nil {
			s.proc.Close()
		}
		if e.bmk != nil {
			if err := e.bmk.Update(name, last); err != nil {
				rerr = fmt.Errorf("failed to update bookmark for %s: %w", name, err)
			}
		}
	}
	e.evtSrcs = nil
	if e.bmk != nil {
		if err := e.bmk.Close(); err != nil {
			rerr = fmt.Errorf("failed to close bookmark: %w", err)
		}
		e.bmk = nil
	}
	return rerr
}

func (e *eventLogInput) consumerRoutine(errs chan<- error) {
	defer e.wg.Done()
	tkr := time.NewTicker(eventSampleInterval)
	defer tkr.Stop()
	rebuildTkr := time.NewTicker(eventChannelRetryInterval)
	defer rebuildTkr.Stop()
	for {
		select {
		case <-e.ctx.Done():
			if err := e.bmk.Sync(); err != nil {
				lg.Error("failed to sync bookmark", log.KVErr(err))
			}
			return
		case <-rebuildTkr.C:
			if len(e.dead) > 0 {
				if err := e.retryDeadStreams(); err != nil {
					sendErr(errs, err)
					return
				}
			}
		case <-tkr.C:
			nev, err := e.consumeEvents()
			if err != nil {
				lg.Error("failed to consume events", log.KVErr(err))
				sendErr(errs, err)
				return
			} else if nev {
				if err := e.bmk.Sync(); err != nil {
					lg.Error("failed to sync bookmark", log.KVErr(err))
					sendErr(errs, err)
					return
				}
			}
		}
	}
}

func (e *eventLogInput) initStream(c winevent.EventStreamParams, errReport bool) (eventSrc, bool, error) {
	igst := e.rt.igst
	tag, err := igst.GetTag(c.TagName)
	if err != nil {
		return eventSrc{}, true, fmt.Errorf("failed to translate tag %s: %w", c.TagName, err)
	}
	last, err := e.bmk.Get(c.Name)
	if err != nil {
		return eventSrc{}, true, fmt.Errorf("failed to get bookmark for %s: %w", c.Name, err)
	}
	pproc, err := e.cfg.Preprocessor.ProcessorSet(igst, c.Preprocessor)
	if err != nil {
		return eventSrc{}, true, fmt.Errorf("preprocessor construction error: %w", err)
	}
	evt, err := winevent.NewStream(c, last)
	if err != nil {
		// not fatal, the channel may not exist yet (e.g. sysmon not installed); retry later
		pproc.Close()
		if errReport {
			lg.Error("failed to create new eventStream", log.KV("name", c.Name), log.KV("channel", c.Channel), log.KVErr(err))
		}
		return eventSrc{}, false, err
	}
	params := []rfc5424.SDParam{
		log.KV("stream", c.Name),
		log.KV("channel", c.Channel),
		log.KV("tag", c.TagName),
	}
	if c.ReachBack != 0 {
		params = append(params, log.KV("reachback", c.ReachBack.String()))
	}
	if len(c.Providers) != 0 {
		params = append(params, log.KV("providers", fmt.Sprintf("%v", c.Providers)))
	}
	if c.Levels != `` {
		params = append(params, log.KV("levels", c.Levels))
	}
	if c.EventIDs != `` {
		params = append(params, log.KV("eventIDs", c.EventIDs))
	}
	lg.Info("starting event channel stream", params...)
	return eventSrc{params: c, h: evt, proc: pproc, tag: tag}, false, nil
}

func (e *eventLogInput) retryDeadStreams() error {
	for k, c := range e.dead {
		evt, fatal, err := e.initStream(c, false)
		if err != nil {
			if fatal {
				return err
			}
			continue
		}
		delete(e.dead, k)
		e.evtSrcs[c.Name] = evt
		lg.Info("recovered event channel stream", log.KV("stream", c.Name), log.KV("channel", c.Channel))
	}
	return nil
}

func (e *eventLogInput) consumeEvents() (bool, error) {
	var consumed bool
	for k, eh := range e.evtSrcs {
		nev, err := e.serviceEventStream(eh)
		if err != nil {
			if isStreamDoesNotExist(err) {
				eh.h.Close()
				eh.proc.Close()
				delete(e.evtSrcs, k)
				e.dead[k] = eh.params
				continue
			}
			return consumed, err
		} else if nev {
			consumed = true
		}
	}
	return consumed, nil
}

func (e *eventLogInput) serviceEventStream(eh eventSrc) (nev bool, err error) {
	var hit bool
	full := true
	for full {
		if hit, full, err = e.serviceEventStreamChunk(eh); err != nil {
			lg.Error("failed to service event stream", log.KV("name", eh.h.Name()), log.KVErr(err))
			if err = eh.h.Reset(); err != nil {
				lg.Error("failed to reset event stream", log.KV("name", eh.h.Name()), log.KVErr(err))
			} else {
				lg.Warn("reset event stream", log.KV("name", eh.h.Name()))
			}
			return
		} else if hit {
			nev = true
		}
		if e.ctx.Err() != nil {
			return
		}
	}
	return
}

func (e *eventLogInput) serviceEventStreamChunk(eh eventSrc) (hit, fullRead bool, err error) {
	var ents []winevent.RenderedEvent
	var warn error
	if ents, fullRead, warn, err = eh.h.Read(); err != nil {
		return
	} else if warn != nil {
		lg.Warn("event stream warning", log.KV("name", eh.h.Name()), log.KV("warning", warn))
	}
	for _, ev := range ents {
		var ts entry.Timestamp
		var ok bool
		if e.tg != nil {
			var lts time.Time
			if lts, ok, err = e.tg.Extract(ev.Buff); err != nil {
				lg.Error("failed to extract TS", log.KVErr(err))
				return
			}
			ts = entry.FromStandard(lts)
		}
		if !ok {
			ts = entry.Now()
		}
		ent := &entry.Entry{
			SRC:  e.rt.src,
			TS:   ts,
			Tag:  eh.tag,
			Data: ev.Buff,
		}
		if err = eh.proc.ProcessContext(ent, e.ctx); err != nil {
			lg.Warn("failed to process event", log.KVErr(err))
			return
		}
		if err = e.bmk.Update(eh.h.Name(), ev.ID); err != nil {
			lg.Error("failed to update bookmark", log.KV("name", eh.h.Name()), log.KVErr(err))
			return
		}
	}
	if len(ents) > 0 {
		hit = true
		debugout("Pulled %d events from %s\n", len(ents), eh.h.Name())
	}
	return
}

// isStreamDoesNotExist looks for the errno indicating that a channel disappeared.
func isStreamDoesNotExist(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return uintptr(errno) == ERROR_EVT_CHANNEL_NOT_FOUND
	}
	return false
}
