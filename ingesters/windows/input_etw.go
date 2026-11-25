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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gravwell/gravwell/v3/etw"
	"github.com/gravwell/gravwell/v3/ingest/entry"
	"github.com/gravwell/gravwell/v3/ingest/log"
	"github.com/gravwell/gravwell/v3/ingest/processors"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
)

const (
	etwRetryInterval = 30 * time.Second
	etwStatsInterval = time.Minute
)

type etwStream struct {
	name     string
	params   etw.SessionParams
	tag      entry.EntryTag
	proc     *processors.ProcessorSet
	consumer *etw.Consumer
	lastLost etw.Stats
}

// etwInput consumes [ETW] sections; every section is its own real-time session.
type etwInput struct {
	cfg *wincfg.Config
	rt  *runtimeEnv
	ctx context.Context

	cancel context.CancelFunc
	wg     sync.WaitGroup
	mtx    sync.Mutex
	live   map[string]*etwStream
	retry  map[string]*etwStream
	procs  []*processors.ProcessorSet
}

func newETWInput(cfg *wincfg.Config) *etwInput {
	return &etwInput{
		cfg:   cfg,
		live:  map[string]*etwStream{},
		retry: map[string]*etwStream{},
	}
}

func (e *etwInput) Name() string { return `etw` }

func (e *etwInput) Start(ctx context.Context, rt *runtimeEnv, errs chan<- error) error {
	e.rt = rt
	e.ctx, e.cancel = context.WithCancel(ctx)
	for name, c := range e.cfg.ETW {
		tag, err := rt.igst.GetTag(c.Tag_Name)
		if err != nil {
			return fmt.Errorf("failed to resolve tag %q for ETW %s: %w", c.Tag_Name, name, err)
		}
		proc, err := e.cfg.Preprocessor.ProcessorSet(rt.igst, c.Preprocessor)
		if err != nil {
			return fmt.Errorf("preprocessor construction error for ETW %s: %w", name, err)
		}
		e.procs = append(e.procs, proc)
		st := &etwStream{name: name, params: c.Params(name), tag: tag, proc: proc}
		e.open(st, true)
	}
	e.wg.Add(1)
	go e.maintenance()
	// a failing ETW session never takes down the other inputs, so there is
	// nothing fatal to report on errs
	return nil
}

// open starts the stream's session, placing it on the retry list if it fails
// for a reason that may resolve itself.
func (e *etwInput) open(st *etwStream, report bool) {
	c, err := etw.NewConsumer(st.params, etw.ConsumerConfig{})
	if err != nil {
		if errors.Is(err, etw.ErrRequiresPPL) {
			// permanent for the life of the process, do not retry
			lg.Error("ETW session disabled", log.KV("etw", st.name), log.KV("session", st.params.SessionName), log.KVErr(err))
			return
		}
		if report {
			lg.Error("failed to start ETW session, will retry", log.KV("etw", st.name), log.KV("session", st.params.SessionName), log.KVErr(err))
		}
		e.mtx.Lock()
		e.retry[st.name] = st
		e.mtx.Unlock()
		return
	}
	st.consumer = c
	st.lastLost = etw.Stats{}
	e.mtx.Lock()
	delete(e.retry, st.name)
	e.live[st.name] = st
	e.mtx.Unlock()
	c.Start()
	e.wg.Add(1)
	go e.consume(st, c)
	providers := make([]string, 0, len(st.params.Providers))
	for _, p := range st.params.Providers {
		providers = append(providers, p.Provider.String())
	}
	lg.Info("started ETW session", log.KV("etw", st.name), log.KV("session", st.params.SessionName),
		log.KV("providers", fmt.Sprintf("%v", providers)))
}

func (e *etwInput) consume(st *etwStream, c *etw.Consumer) {
	defer e.wg.Done()
	var buf []byte
	for ev := range c.Events() {
		var err error
		if buf, err = ev.AppendJSON(buf[:0]); err != nil {
			lg.Warn("failed to render ETW event", log.KV("etw", st.name), log.KVErr(err))
			continue
		}
		ts := entry.Now()
		if !e.cfg.Global.Ignore_Timestamps && !ev.Timestamp.IsZero() {
			ts = entry.FromStandard(ev.Timestamp)
		}
		ent := &entry.Entry{
			SRC:  e.rt.src,
			TS:   ts,
			Tag:  st.tag,
			Data: append([]byte(nil), buf...),
		}
		if err = st.proc.ProcessContext(ent, e.ctx); err != nil {
			if e.ctx.Err() != nil {
				break
			}
			lg.Warn("failed to process ETW event", log.KV("etw", st.name), log.KVErr(err))
		}
	}
	if e.ctx.Err() != nil {
		return
	}
	// the session went away underneath us (e.g. stopped with logman), restart it
	lg.Error("ETW session stopped unexpectedly, will retry", log.KV("etw", st.name), log.KVErr(c.Err()))
	c.Close()
	e.mtx.Lock()
	if e.live[st.name] == st {
		delete(e.live, st.name)
		st.consumer = nil
		e.retry[st.name] = st
	}
	e.mtx.Unlock()
}

func (e *etwInput) maintenance() {
	defer e.wg.Done()
	retryTkr := time.NewTicker(etwRetryInterval)
	defer retryTkr.Stop()
	statsTkr := time.NewTicker(etwStatsInterval)
	defer statsTkr.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-retryTkr.C:
			e.mtx.Lock()
			pending := make([]*etwStream, 0, len(e.retry))
			for _, st := range e.retry {
				pending = append(pending, st)
			}
			e.mtx.Unlock()
			for _, st := range pending {
				if e.ctx.Err() != nil {
					return
				}
				e.open(st, false)
			}
		case <-statsTkr.C:
			e.reportStats()
		}
	}
}

func (e *etwInput) reportStats() {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	for _, st := range e.live {
		s, err := st.consumer.Stats()
		if err != nil {
			continue
		}
		if s.EventsLost > st.lastLost.EventsLost || s.RealTimeBuffersLost > st.lastLost.RealTimeBuffersLost {
			lg.Warn("ETW session is losing events, consider increasing Buffer-Size-KB or Max-Buffers",
				log.KV("etw", st.name),
				log.KV("events-lost", s.EventsLost-st.lastLost.EventsLost),
				log.KV("realtime-buffers-lost", s.RealTimeBuffersLost-st.lastLost.RealTimeBuffersLost))
		}
		st.lastLost = s
	}
}

func (e *etwInput) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	e.mtx.Lock()
	live := make([]*etwStream, 0, len(e.live))
	for _, st := range e.live {
		live = append(live, st)
	}
	e.mtx.Unlock()
	var rerr error
	for _, st := range live {
		if err := st.consumer.Close(); err != nil {
			rerr = fmt.Errorf("failed to close ETW session %s: %w", st.params.SessionName, err)
		}
	}
	e.wg.Wait()
	for _, p := range e.procs {
		if err := p.Close(); err != nil {
			lg.Error("failed to close preprocessor", log.KVErr(err))
		}
	}
	return rerr
}
