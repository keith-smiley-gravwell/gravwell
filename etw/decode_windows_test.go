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
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDecodeKernelProcess consumes live ProcessStart events and checks that
// they decode into readable JSON.
func TestDecodeKernelProcess(t *testing.T) {
	requireElevated(t)
	c, err := NewConsumer(kernelProcessParams(`decode`), ConsumerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Start()

	stop := make(chan struct{})
	defer close(stop)
	go startProcesses(stop)

	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no ProcessStart events received")
		case ev, ok := <-c.Events():
			if !ok {
				t.Fatalf("consumer stopped: %v", c.Err())
			}
			if ev.EventID != 1 {
				continue
			}
			if ev.DecodingError != `` {
				t.Fatalf("decoding error: %s", ev.DecodingError)
			}
			if ev.ProviderName != kernelProcessProvider || ev.DecodingSource != DecodingSourceXMLFile {
				t.Fatalf("bad provider/source %q %d", ev.ProviderName, ev.DecodingSource)
			}
			img, ok := ev.Property(`ImageName`)
			if !ok {
				t.Fatalf("no ImageName in %+v", ev.Properties)
			}
			if !strings.HasSuffix(strings.ToLower(img.(string)), `.exe`) {
				t.Fatalf("unexpected ImageName %v", img)
			}
			if pid, ok := ev.Property(`ProcessID`); !ok {
				t.Fatal("no ProcessID property")
			} else if _, isNum := pid.(uint64); !isNum {
				t.Fatalf("ProcessID should be numeric, got %T", pid)
			}
			if time.Since(ev.Timestamp) > time.Minute || ev.Timestamp.After(time.Now().Add(time.Minute)) {
				t.Fatalf("implausible timestamp %v", ev.Timestamp)
			}
			if ev.TaskName == `` || ev.LevelName == `` || len(ev.KeywordNames) == 0 {
				t.Fatalf("schema names missing: task %q level %q keywords %v", ev.TaskName, ev.LevelName, ev.KeywordNames)
			}
			b, err := ev.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var mp map[string]any
			if err := json.Unmarshal(b, &mp); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, b)
			}
			t.Logf("%s", b)
			return
		}
	}
}
