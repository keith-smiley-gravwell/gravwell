# Gravwell Windows Ingester

The Gravwell Windows ingester runs as a single Windows service
(`GravwellWindows`) and collects:

- **Windows Event Log channels** (`[EventChannel]`). This replaces the
  Windows Events ingester.
- **Files** (`[Follower]`), including `.evtx` files. This replaces the
  Windows File Follow ingester.
- **ETW (Event Tracing for Windows) real-time sessions** (`[ETW]`). Every
  ETW event is rendered as human-readable JSON.

| | |
|---|---|
| Binary | `C:\Program Files\gravwell\windows\gravwell_windows.exe` |
| Config | `C:\ProgramData\gravwell\windows\windows.cfg` (overlays in `windows.conf.d\*.conf`) |
| Event log bookmark | `C:\ProgramData\gravwell\windows\bookmark` |
| File follower state | `C:\ProgramData\gravwell\windows\file_follow.state` |

See [windows.cfg](windows.cfg) for an annotated example.

## Migrating from the legacy ingesters

Installing the MSI:

1. Stops the `GravwellEvents` and `GravwellFileFollower` services.
2. Runs `gravwell_windows.exe -migrate-config`. This merges
   `ProgramData\gravwell\eventlog\config.cfg` and
   `ProgramData\gravwell\filefollow\file_follow.cfg` into `windows.cfg`. It
   also copies the event log bookmark and the file follower state, so nothing
   is re-ingested.
3. Removes both legacy products.

Merge rules:

- **`[Global]` and `[Attach]`** are merged key by key. When a key conflicts,
  the Windows Events value wins and a warning is printed.
- **`Ingester-UUID`** is dropped. The unified ingester generates a new
  identity.
- **Name collisions:** a File Follow section whose name collides with a Windows
  Events section of the same type gets a `-filefollow` suffix. For
  preprocessors, the references to it are rewritten.

Migration does nothing if `windows.cfg` already exists. You can run it by hand:

```bat
gravwell_windows.exe -migrate-config
```

## ETW

Each `[ETW "name"]` section is one real-time session named `Gravwell-<name>`,
unless `Session-Name` is set.

| Parameter | Description |
|---|---|
| `Tag-Name` | Tag for the session's events. |
| `Provider` | Registered provider name or `{GUID}`, repeatable. TraceLogging providers must be given by GUID. |
| `Level` | `critical`, `error`, `warning`, `information`, `verbose` (default) or `0`-`255`. |
| `Match-Any-Keyword` / `Match-All-Keyword` | Numeric masks or manifest keyword names, repeatable. Names require a single `Provider`. If unset, any-keyword defaults to all keywords. |
| `Event-ID` | IDs to accept, e.g. `1`, `1-10`, `4688,4689`. At most 64; filtered by ETW in the kernel. |
| `Buffer-Size-KB`, `Min-Buffers`, `Max-Buffers` | Session buffer tuning. Lost-event counters are logged every minute when they grow. |
| `Preprocessor` | Preprocessors to apply. |

Sessions that fail to start, or are stopped externally, are retried every 30
seconds.

ETW is real time only: there is no bookmark or reachback. Security auditing
events cannot be enabled on a private session, so collect them with
`[EventChannel]` and `Channel=Security`.

### JSON format

An illustrative ProcessStart event:

```json
{"Timestamp":"2026-11-24T12:00:00.1234567Z",
 "Provider":{"Name":"Microsoft-Windows-Kernel-Process","GUID":"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"},
 "EventID":1,"Version":3,"Level":"Information","LevelValue":4,
 "Task":"ProcessStart","TaskValue":1,"Opcode":"Start","OpcodeValue":1,
 "Keywords":["WINEVENT_KEYWORD_PROCESS"],"KeywordsMask":"0x8000000000000010",
 "Channel":"Microsoft-Windows-Kernel-Process/Analytic",
 "ProcessID":4,"ThreadID":120,"ProcessorNumber":2,"DecodingSource":"Manifest",
 "Message":"Process 4242 started at time ...",
 "EventData":{"ProcessID":4242,"CreateTime":"2026-11-24T12:00:00.1200000Z",
              "ParentProcessID":1000,"SessionID":1,"ImageName":"\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"}}
```

How values are rendered:

| Value | Rendered as |
|---|---|
| Integers | JSON numbers, unless the schema asks for hex (`"0x..."`) |
| Pointers | `"0x..."` |
| Booleans | `true` / `false` |
| GUIDs | Braced strings |
| FILETIME and SYSTEMTIME | RFC 3339 strings |
| SIDs | `{"SID":"S-1-5-18","Account":"NT AUTHORITY\\SYSTEM"}` |
| Value maps | Names |
| Bitmaps | Arrays of names |
| Structures | Nested objects |
| Arrays | JSON arrays |

If an event has no schema (WPP, or an unregistered MOF provider), it still has
the header fields. It also gets `DecodingError` and the base64 `RawUserData`.

### Sensitive providers

`Microsoft-Windows-Threat-Intelligence` requires the ingester to run as an
antimalware protected process light. See
[THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md).

## Building

```bat
REM gravwell.ico must be present in this directory
build.bat
```

The Go code builds on any platform with
`GOOS=windows GOARCH=amd64 go build ./ingesters/windows`. ETW support needs
64-bit Windows; amd64 is the supported build.

## Command line

| Flag | Description |
|---|---|
| `-v` | Run interactively and log to stdout. |
| `-config-file-override <path>` | Use another config file. Overlays are then only loaded from `-config-overlays`. |
| `-dump-state` | Print the file follower state and exit. |
| `-migrate-config` | Merge the legacy configs and exit. |
| `-install-elam <driver>`, `-set-protected` | Used by PPL-capable installers. |
