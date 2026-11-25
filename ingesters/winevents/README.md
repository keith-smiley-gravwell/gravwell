# Gravwell Windows Events Ingester

> **Deprecated on Windows:** this ingester has been replaced by the unified
> [Gravwell Windows ingester](../windows/README.md), which hosts Event Log
> channels, file followers and ETW sessions in a single service. Installing the
> new MSI migrates this ingester's configuration, bookmark and state and removes
> this ingester. This package will be removed in a future release.

The Gravwell Windows events ingester is designed to run as a system service and collect Events from the Windows Event log.  The ingesters supports Windows 7 through Windows 10 and any modern Windows server distribution.  Both 32 and 64 bit builds are possible, but only the 64bit build is officially supported.

## Building the application

Build service using at least Go version 1.13, but we reccomend the latest go version.

`
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows go build
`

## Building the installer

The installer is built using the [WIX Toolset](https://wixtoolset.org/).  To build an MSI, first build the winevents.exe installer and then use the `build.bat` batch script to build an MSI.
