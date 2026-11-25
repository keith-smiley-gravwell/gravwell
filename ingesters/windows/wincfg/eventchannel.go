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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/entry"
)

const (
	mb = 1024 * 1024

	// DefaultReachback is used when an EventChannel has no Max-Reachback.
	DefaultReachback = 168 * time.Hour //1 week

	defaultBuffSize = 2 * mb
	minBuffSize     = 1 * mb
	maxBuffSize     = 32 * mb

	defaultHandleRequest = 128
	maxHandleRequest     = 1024
	// MinHandleRequest mirrors winevent.MinHandleRequest.
	MinHandleRequest = 2
)

var (
	defaultLevels = []string{`verbose`, `information`, `warning`, `error`, `critical`}

	ErrInvalidName              = errors.New("Event channel name is invalid")
	ErrInvalidReachbackDuration = errors.New("Invalid event reachback duration")
	ErrInvalidLevel             = errors.New("Invalid level")
	ErrInvalidEventIds          = errors.New("Invalid Event IDs, must be of the form 100 or -100 or 100-200")

	evRangeRegex = regexp.MustCompile(`\A([0-9]+)\s*-\s*([0-9]+)\z`)
)

// EventStreamConfig is an [EventChannel "name"] section.  It is identical to the
// section used by the legacy Windows Events ingester.
type EventStreamConfig struct {
	Tag_Name       string   //which tag are we applying to this event channel
	Channel        string   //Names like: System, Application, Security...
	Max_Reachback  string   //duration like: 72h
	Level          []string //levels include: verbose,information,warning,error,critical
	Provider       []string //list of providers to filter on
	EventID        []string //list of eventID filters: 1000-2000 or -1000
	Request_Size   int      //number of entries to request per cycle
	Request_Buffer int      //request buffer size in MB
	Preprocessor   []string

	normalized bool
}

func (ec *EventStreamConfig) normalize() {
	if ec.normalized {
		return
	}
	ec.normalized = true
	ec.Channel = strings.TrimSpace(ec.Channel)
	ec.Max_Reachback = strings.TrimSpace(ec.Max_Reachback)
	ec.Tag_Name = strings.TrimSpace(ec.Tag_Name)
	for i := range ec.Level {
		ec.Level[i] = strings.ToLower(strings.TrimSpace(ec.Level[i]))
	}
	for i := range ec.Provider {
		ec.Provider[i] = strings.TrimSpace(ec.Provider[i])
	}
	for i := range ec.EventID {
		ec.EventID[i] = strings.TrimSpace(ec.EventID[i])
	}
	if ec.Request_Size == 0 {
		ec.Request_Size = defaultHandleRequest
	} else if ec.Request_Size > maxHandleRequest {
		ec.Request_Size = maxHandleRequest
	} else if ec.Request_Size < MinHandleRequest {
		ec.Request_Size = MinHandleRequest
	}

	ec.Request_Buffer *= mb
	if ec.Request_Buffer == 0 {
		ec.Request_Buffer = defaultBuffSize
	} else if ec.Request_Buffer > maxBuffSize {
		ec.Request_Buffer = maxBuffSize
	} else if ec.Request_Buffer < minBuffSize {
		ec.Request_Buffer = minBuffSize
	}
}

// Validate checks the event stream configuration, normalize must have been called.
func (ec *EventStreamConfig) Validate() error {
	if len(ec.Channel) == 0 {
		return ErrInvalidName
	}
	if len(ec.Max_Reachback) != 0 {
		dur, err := time.ParseDuration(ec.Max_Reachback)
		if err != nil {
			return err
		}
		if dur < 0 {
			return ErrInvalidReachbackDuration
		}
	}
	if len(ec.Level) == 0 {
		ec.Level = append([]string(nil), defaultLevels...)
	}
	if ingest.CheckTag(ec.TagName()) != nil {
		return errors.New("Invalid characters in the Tag-Name for " + ec.Tag_Name)
	}
	for i := range ec.Level {
		if !inStringSet(ec.Level[i], defaultLevels) {
			return ErrInvalidLevel
		}
	}
	for i := range ec.EventID {
		if err := validateEventIDs(ec.EventID[i]); err != nil {
			return err
		}
	}
	return nil
}

// TagName returns the tag for this stream, applying the default.
func (ec *EventStreamConfig) TagName() string {
	if ec.Tag_Name == `` {
		return entry.DefaultTagName
	}
	return ec.Tag_Name
}

// Reachback returns the configured reachback, applying the default.
func (ec *EventStreamConfig) Reachback() (time.Duration, error) {
	if len(ec.Max_Reachback) == 0 {
		return DefaultReachback, nil
	}
	return time.ParseDuration(ec.Max_Reachback)
}

func inStringSet(needle string, haystack []string) bool {
	for i := range haystack {
		if needle == haystack[i] {
			return true
		}
	}
	return false
}

func validateEventIDs(ev string) error {
	ev = strings.TrimSpace(ev)
	//event IDs MUST be of the form (num, -num, num-num, or a CSV of nums)
	subs := evRangeRegex.FindAllStringSubmatch(ev, -1)
	if len(subs) > 1 {
		return ErrInvalidEventIds
	}
	if len(subs) == 1 {
		s := subs[0]
		if len(s) != 3 {
			return ErrInvalidEventIds
		}
		v1, err := strconv.ParseInt(s[1], 10, 16)
		if err != nil {
			return ErrInvalidEventIds
		}
		v2, err := strconv.ParseInt(s[2], 10, 16)
		if err != nil {
			return ErrInvalidEventIds
		}
		if v1 >= v2 {
			return ErrInvalidEventIds
		}
		return nil
	}
	if err := parseCSVInts(ev); err == nil {
		return nil
	}
	if _, err := strconv.ParseInt(ev, 10, 16); err != nil {
		return ErrInvalidEventIds
	}
	return nil
}

func parseCSVInts(val string) error {
	for _, ev := range strings.Split(val, ",") {
		ev = strings.TrimSpace(ev)
		if _, err := strconv.ParseInt(ev, 10, 16); err != nil {
			return fmt.Errorf("%w %s is not a valid EventID", ErrInvalidEventIds, ev)
		}
	}
	return nil
}
