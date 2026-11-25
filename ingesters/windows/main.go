//go:build windows

/*************************************************************************
 * Copyright 2026 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

// The Gravwell Windows ingester consumes Windows Event Log channels, follows
// files and consumes real-time ETW sessions from a single service.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	dbg "runtime/debug"
	"syscall"
	"time"

	// Embed tzdata so that we don't rely on potentially broken timezone DBs on the host
	_ "time/tzdata"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/google/uuid"
	"github.com/gravwell/gravwell/v3/filewatch"
	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/config/validate"
	"github.com/gravwell/gravwell/v3/ingest/log"
	"github.com/gravwell/gravwell/v3/ingesters/version"
	"github.com/gravwell/gravwell/v3/ingesters/windows/wincfg"
)

var (
	configOverride  = flag.String("config-file-override", "", "Override location for configuration file")
	overlayOverride = flag.String("config-overlays", "", "Override location for configuration overlay directory")
	verboseF        = flag.Bool("v", false, "Verbose mode, do not run as a service and output status to stdout")
	ver             = flag.Bool("version", false, "Print the version information and exit")
	dumpState       = flag.Bool("dump-state", false, "Dump the file follower state file in a human format and exit")
	migrate         = flag.Bool("migrate-config", false, "Merge the legacy Windows Events and File Follow configs into the unified config and exit")
	installELAM     = flag.String("install-elam", "", "Install the ELAM certificate information from the given driver and exit")
	setProtected    = flag.Bool("set-protected", false, "Configure the service to launch as an antimalware protected process light and exit")

	confLoc    string
	overlayLoc string
	debugOn    bool
	lg         *log.Logger
)

func main() {
	dbg.SetTraceback("all")
	flag.Parse()
	if *ver {
		version.PrintVersion(os.Stdout)
		ingest.PrintVersion(os.Stdout)
		return
	}
	debugOn = *verboseF
	var err error
	if confLoc = *configOverride; confLoc == `` {
		if confLoc, err = wincfg.ProgramDataPath(wincfg.DefaultConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get config file path: %v\n", err)
			os.Exit(-1)
		}
	}
	if overlayLoc = *overlayOverride; overlayLoc == `` && *configOverride == `` {
		if overlayLoc, err = wincfg.ProgramDataPath(wincfg.DefaultConfigOverlayPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get config overlay path: %v\n", err)
			os.Exit(-1)
		}
	}

	// one shot administrative commands, used by the installer
	switch {
	case *migrate:
		os.Exit(runMigration())
	case *installELAM != ``:
		os.Exit(runInstallELAM(*installELAM))
	case *setProtected:
		os.Exit(runSetProtected())
	}

	validate.ValidateIngesterConfig(wincfg.GetConfig, confLoc, overlayLoc)

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get interactive session status: %v\n", err)
		return
	}
	if isService {
		e, err := eventlog.Open(wincfg.ServiceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get event log handle: %v\n", err)
			return
		}
		lg = log.NewLevelRelay(levelLogger{elog: e})
	} else {
		lg = log.New(os.Stdout)
	}
	lg.SetAppname(wincfg.AppName)

	cfg, err := wincfg.GetConfig(confLoc, overlayLoc)
	if err != nil {
		lg.Error("failed to get configuration", log.KVErr(err))
		return
	}
	if *dumpState {
		dumpStateFile(cfg.Global.State_Store_Location)
		return
	}
	//check if we have a UUID, if not try to write one back
	if _, ok := cfg.Global.IngestConfig.IngesterUUID(); !ok {
		id := uuid.New()
		if err := cfg.Global.IngestConfig.SetIngesterUUID(id, confLoc); err != nil {
			lg.Error("failed to set ingester UUID at startup", log.KVErr(err))
			return
		}
	}
	if len(cfg.Global.Log_Level) > 0 {
		if err = lg.SetLevelString(cfg.Global.Log_Level); err != nil {
			lg.FatalCode(0, "invalid Log Level", log.KV("loglevel", cfg.Global.Log_Level), log.KVErr(err))
		}
	}
	lg.Info("service started", log.KV("name", wincfg.ServiceName),
		log.KV("eventchannels", len(cfg.EventChannel)),
		log.KV("followers", len(cfg.Follower)),
		log.KV("etw", len(cfg.ETW)))

	s, err := newService(cfg)
	if err != nil {
		lg.Error("failed to create gravwell service", log.KVErr(err))
		return
	}
	if isService {
		lg.Info("starting as service")
		if err := svc.Run(wincfg.ServiceName, s); err != nil {
			lg.Error("failed to run service", log.KVErr(err))
		}
	} else {
		lg.Info("starting in interactive mode")
		runInteractive(s)
	}
	lg.Info("service stopped")
}

func runMigration() int {
	mp, err := wincfg.DefaultMigrationPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve migration paths: %v\n", err)
		return 1
	}
	if *configOverride != `` {
		mp.Config = *configOverride
	}
	done, warnings, err := wincfg.MigrateLegacy(mp)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if errors.Is(err, wincfg.ErrNothingToMigrate) {
		fmt.Println("no legacy configuration found")
		return 0
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		return 1
	}
	if done {
		fmt.Printf("migrated legacy configuration to %s\n", mp.Config)
	} else {
		fmt.Printf("%s already exists, not migrating\n", mp.Config)
	}
	return 0
}

func runInteractive(s *service) {
	closer := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 4)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Execute(nil, closer, status)
	}()
	for {
		select {
		case <-sigChan:
			debugout("Caught close signal\n")
			select {
			case closer <- svc.ChangeRequest{Cmd: svc.Shutdown}:
			case <-time.After(time.Second):
				lg.Error("failed to send shutdown command")
			}
		case st := <-status:
			lg.Debug("service state change", log.KV("state", st.State))
		case <-done:
			return
		}
	}
}

func dumpStateFile(pth string) {
	states, err := filewatch.DecodeStateFile(pth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load state file: %v\n", err)
		return
	}
	fmt.Printf("%-24s %-16s %s\n", "Listener Name", "File Offset", "File Path")
	for _, state := range states {
		fmt.Printf("%-24s %-16d %s\n", state.BaseName, state.State, state.FilePath)
	}
}

func debugout(format string, args ...interface{}) {
	if debugOn {
		fmt.Printf(format, args...)
	}
}

// levelLogger implements the log.LevelRelay interface, writing to the Windows event log.
type levelLogger struct {
	elog debug.Log
}

func (l levelLogger) WriteLog(lvl log.Level, ts time.Time, msg, rawMsg string) error {
	switch lvl {
	case log.DEBUG:
		if debugOn {
			fmt.Fprintln(os.Stdout, rawMsg)
		}
	case log.INFO:
		return l.elog.Info(1, rawMsg)
	case log.WARN:
		return l.elog.Warning(1, rawMsg)
	case log.ERROR, log.CRITICAL, log.FATAL:
		return l.elog.Error(1, rawMsg)
	}
	return nil
}

func (l levelLogger) Close() error {
	return l.elog.Close()
}
