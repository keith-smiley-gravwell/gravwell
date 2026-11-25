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
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/windows"
)

const defaultEventBuffer = 4096

var (
	// Go callbacks are never freed and are limited in number, so a single
	// callback is shared by every consumer and dispatches on UserContext.
	callbackOnce sync.Once
	callbackPtr  uintptr

	registryMtx sync.RWMutex
	registry    = map[uintptr]*Consumer{}
	nextID      uintptr
)

func eventRecordCallback(r *eventRecord) uintptr {
	registryMtx.RLock()
	c := registry[r.UserContext]
	registryMtx.RUnlock()
	if c != nil {
		c.handle(r)
	}
	return 0
}

// ConsumerConfig controls a Consumer.
type ConsumerConfig struct {
	// EventBuffer is the depth of the decoded event channel.
	EventBuffer int
	// Protection is used to gate sensitive providers, nil uses the current process.
	Protection ProtectionChecker
}

// Consumer owns a real-time ETW session and delivers decoded events.
type Consumer struct {
	params  SessionParams
	sess    *session
	trace   uint64
	id      uintptr
	dec     *decoder
	out     chan *Event
	closing chan struct{}
	done    chan struct{}
	err     error

	closeOnce sync.Once
	started   atomic.Bool
}

// NewConsumer starts the session, enables its providers and opens it for
// real-time consumption.  Call Start to begin delivering events.
func NewConsumer(sp SessionParams, cc ConsumerConfig) (c *Consumer, err error) {
	if len(sp.Providers) == 0 {
		return nil, errors.New("no providers specified")
	}
	pc := cc.Protection
	if pc == nil {
		pc = CurrentProcess{}
	}
	if err = CheckSensitive(sp, pc); err != nil {
		return nil, err
	}
	// resolve everything before creating any system state
	type enableReq struct {
		guid         GUID
		pp           ProviderParams
		anyKW, allKW uint64
	}
	var reqs []enableReq
	for _, pp := range sp.Providers {
		var er enableReq
		er.pp = pp
		if er.guid, err = ResolveProvider(pp.Provider); err != nil {
			return nil, err
		}
		if er.anyKW, err = ResolveKeywords(er.guid, pp.MatchAny, allKeywords); err != nil {
			return nil, err
		}
		if er.allKW, err = ResolveKeywords(er.guid, pp.MatchAll, 0); err != nil {
			return nil, err
		}
		reqs = append(reqs, er)
	}

	sess, err := startSession(sp)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			sess.close()
		}
	}()
	for _, er := range reqs {
		if err = sess.enable(er.guid, er.pp, er.anyKW, er.allKW); err != nil {
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) && RequiresPPL(ProviderSpec{GUID: er.guid}) {
				err = fmt.Errorf("%w: %s", ErrRequiresPPL, er.pp.Provider)
			}
			err = fmt.Errorf("failed to enable provider %s: %w", er.pp.Provider, err)
			return nil, err
		}
	}

	bufSize := cc.EventBuffer
	if bufSize <= 0 {
		bufSize = defaultEventBuffer
	}
	c = &Consumer{
		params:  sp,
		sess:    sess,
		dec:     newDecoder(),
		out:     make(chan *Event, bufSize),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
	callbackOnce.Do(func() {
		callbackPtr = syscall.NewCallback(eventRecordCallback)
	})
	registryMtx.Lock()
	nextID++
	c.id = nextID
	registry[c.id] = c
	registryMtx.Unlock()

	lf := eventTraceLogfile{
		LoggerName:          sess.namePtr,
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: callbackPtr,
		Context:             c.id,
	}
	if c.trace, err = openTrace(&lf); err != nil {
		c.unregister()
		err = fmt.Errorf("OpenTrace %q: %w", sp.SessionName, err)
		return nil, err
	}
	return c, nil
}

// Start begins processing events on a dedicated OS thread.
func (c *Consumer) Start() {
	if !c.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(c.done)
		defer close(c.out)
		h := c.trace
		err := processTrace(&h)
		if err != nil && !errors.Is(err, windows.ERROR_CANCELLED) {
			select {
			case <-c.closing:
			default:
				c.err = fmt.Errorf("ProcessTrace %q: %w", c.params.SessionName, err)
			}
		}
	}()
}

// Events returns the decoded event channel; it is closed when processing stops.
func (c *Consumer) Events() <-chan *Event { return c.out }

// Err returns the error that stopped processing, if any.  Only valid after Events is closed.
func (c *Consumer) Err() error { return c.err }

// Name returns the ETW session name.
func (c *Consumer) Name() string { return c.params.SessionName }

// Stats returns the session counters.
func (c *Consumer) Stats() (Stats, error) { return c.sess.stats() }

func (c *Consumer) handle(r *eventRecord) {
	select {
	case <-c.closing:
		return
	default:
	}
	ev := c.safeDecode(r)
	// block to apply back pressure, ETW counts what it has to drop
	select {
	case c.out <- ev:
	case <-c.closing:
	}
}

// safeDecode never lets a decoder panic unwind through ProcessTrace, which
// would take down the whole process.
func (c *Consumer) safeDecode(r *eventRecord) (ev *Event) {
	defer func() {
		if p := recover(); p != nil {
			h := &r.EventHeader
			ev = &Event{
				Timestamp:      filetimeToTime(h.TimeStamp),
				ProviderGUID:   h.ProviderID,
				EventID:        h.EventDescriptor.ID,
				Version:        h.EventDescriptor.Version,
				Level:          h.EventDescriptor.Level,
				ProcessID:      h.ProcessID,
				ThreadID:       h.ThreadID,
				DecodingSource: DecodingSourceUnavailable,
				DecodingError:  fmt.Sprintf("decoder panic: %v", p),
			}
		}
	}()
	return c.dec.decode(r)
}

func (c *Consumer) unregister() {
	registryMtx.Lock()
	delete(registry, c.id)
	registryMtx.Unlock()
}

// Close stops the session and waits for processing to finish.
func (c *Consumer) Close() (err error) {
	c.closeOnce.Do(func() {
		close(c.closing)
		// stopping the session ends ProcessTrace once buffers drain
		err = c.sess.close()
		if cerr := closeTrace(c.trace); cerr != nil && err == nil && !errors.Is(cerr, windows.ERROR_CTX_CLOSE_PENDING) {
			err = cerr
		}
		if c.started.Load() {
			<-c.done
		} else {
			close(c.out)
		}
		c.unregister()
	})
	return
}
