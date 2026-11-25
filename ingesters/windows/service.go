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
	"net"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/log"
	"github.com/gravwell/gravwell/v3/ingesters/utils"
	"github.com/gravwell/gravwell/v3/ingesters/version"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
)

const (
	// the service control manager gets confused if a service dies immediately
	minServiceLiveTime = 2 * time.Second
	inputCloseTimeout  = 5 * time.Second
)

// input is one class of data source hosted by the service.
type input interface {
	// Name is used for logging.
	Name() string
	// Start begins consuming.  It must not block for long; long running work
	// belongs in goroutines.  Fatal runtime errors are sent to errs.
	Start(ctx context.Context, rt *runtimeEnv, errs chan<- error) error
	// Close stops consuming and releases resources.
	Close() error
}

// runtimeEnv is the shared state handed to every input.
type runtimeEnv struct {
	cfg  *wincfg.Config
	igst *ingest.IngestMuxer
	lg   *log.Logger
	src  net.IP
}

type service struct {
	cfg    *wincfg.Config
	inputs []input
}

func newService(cfg *wincfg.Config) (*service, error) {
	s := &service{cfg: cfg}
	if len(cfg.EventChannel) > 0 {
		s.inputs = append(s.inputs, newEventLogInput(cfg))
	}
	if len(cfg.Follower) > 0 {
		fi, err := newFileFollowInput(cfg)
		if err != nil {
			return nil, err
		}
		s.inputs = append(s.inputs, fi)
	}
	if len(cfg.ETW) > 0 {
		s.inputs = append(s.inputs, newETWInput(cfg))
	}
	if len(s.inputs) == 0 {
		return nil, wincfg.ErrNoInputs
	}
	return s, nil
}

func (s *service) newMuxer() (*ingest.IngestMuxer, error) {
	tags, err := s.cfg.Tags()
	if err != nil {
		return nil, err
	}
	conns, err := s.cfg.Global.Targets()
	if err != nil {
		return nil, err
	}
	lmt, err := s.cfg.Global.RateLimit()
	if err != nil {
		return nil, err
	}
	id, ok := s.cfg.Global.IngesterUUID()
	if !ok {
		return nil, errors.New("couldn't read ingester UUID")
	}
	g := s.cfg.Global
	mcfg := ingest.UniformMuxerConfig{
		Destinations:    conns,
		Tags:            tags,
		Auth:            g.Secret(),
		LogLevel:        g.LogLevel(),
		IngesterName:    wincfg.IngesterName,
		IngesterVersion: version.GetVersion(),
		IngesterUUID:    id.String(),
		IngesterLabel:   g.Label,
		RateLimitBps:    lmt,
		CacheDepth:      g.Cache_Depth,
		CachePath:       g.Ingest_Cache_Path,
		CacheSize:       g.Max_Ingest_Cache,
		CacheMode:       g.Cache_Mode,
		Attach:          s.cfg.Attach,
	}
	return ingest.NewUniformMuxer(mcfg)
}

// Execute implements svc.Handler.
func (s *service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()

	errs := make(chan error, len(s.inputs)+1)
	var rt *runtimeEnv
	initDone := make(chan error, 1)
	go func() {
		var err error
		rt, err = s.start(ctx, errs)
		initDone <- err
	}()

	var runErr error
	initPending := true
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				lg.Info("service stopping")
				break loop
			default:
				lg.Error("got invalid control request", log.KV("request", c.Cmd))
			}
		case err := <-initDone:
			initPending = false
			if err != nil {
				runErr = err
				break loop
			}
		case err := <-errs:
			runErr = err
			break loop
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	cancel()
	if initPending {
		<-initDone
	}
	// keep the SCM happy if we failed very quickly
	if d := time.Since(start); d < minServiceLiveTime && runErr != nil {
		time.Sleep(minServiceLiveTime - d)
	}
	s.stop(rt)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		lg.Error("service exiting with error", log.KVErr(runErr))
		ssec, errno = true, 1000
	}
	changes <- svc.Status{State: svc.Stopped}
	return
}

func (s *service) start(ctx context.Context, errs chan<- error) (*runtimeEnv, error) {
	igst, err := s.newMuxer()
	if err != nil {
		return nil, fmt.Errorf("failed to build ingest muxer: %w", err)
	}
	if err = igst.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ingest muxer: %w", err)
	}
	rt := &runtimeEnv{cfg: s.cfg, igst: igst, lg: lg}
	if err = igst.WaitForHotContext(ctx, s.cfg.Global.Timeout()); err != nil {
		return rt, err
	}
	if s.cfg.Global.SelfIngest() {
		lg.AddRelay(igst)
	}
	if err = igst.SetRawConfiguration(s.cfg.RawConfig()); err != nil {
		return rt, fmt.Errorf("failed to set raw configuration: %w", err)
	}
	if s.cfg.Global.Source_Override != `` {
		if rt.src = net.ParseIP(s.cfg.Global.Source_Override); rt.src == nil {
			return rt, errors.New("Global Source-Override is invalid")
		}
	} else {
		rt.src, _ = igst.SourceIP()
	}
	hot, _ := igst.Hot()
	lg.Info("ingester connections established", log.KV("hot-connections", hot))

	for _, in := range s.inputs {
		if err = in.Start(ctx, rt, errs); err != nil {
			return rt, fmt.Errorf("failed to start %s input: %w", in.Name(), err)
		}
		lg.Info("input started", log.KV("input", in.Name()))
	}
	return rt, nil
}

// stop closes inputs in reverse order and then flushes the muxer.
func (s *service) stop(rt *runtimeEnv) {
	for i := len(s.inputs) - 1; i >= 0; i-- {
		in := s.inputs[i]
		if err := closeTimeout(in, inputCloseTimeout); err != nil {
			lg.Error("failed to close input", log.KV("input", in.Name()), log.KVErr(err))
		}
	}
	if rt == nil || rt.igst == nil {
		return
	}
	if err := rt.igst.Sync(utils.ExitSyncTimeout); err != nil {
		lg.Error("failed to sync ingest muxer", log.KVErr(err))
	}
	if err := rt.igst.Close(); err != nil {
		lg.Error("failed to close ingest muxer", log.KVErr(err))
	}
	rt.igst = nil
}

func closeTimeout(in input, to time.Duration) error {
	var wg sync.WaitGroup
	var err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = in.Close()
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return err
	case <-time.After(to):
		return errors.New("timed out waiting for input to close")
	}
}

// sendErr delivers a fatal input error without blocking.
func sendErr(errs chan<- error, err error) {
	select {
	case errs <- err:
	default:
	}
}
