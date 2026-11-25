# Consuming Microsoft-Windows-Threat-Intelligence

`Microsoft-Windows-Threat-Intelligence` (`{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`)
is a sensitive ETW provider. Windows delivers its events only to a consumer
running as an **antimalware protected process light** (PPL,
`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`). An ordinary service cannot consume it,
even when it runs as LocalSystem.

The Gravwell Windows ingester is PPL-ready. The code paths and installer hooks
exist, but they only take effect when the package is built with a
Microsoft-signed ELAM driver.

## Prerequisites (outside this repository)

1. **Microsoft Virus Initiative (MVI) membership.** Microsoft only signs ELAM
   drivers for MVI members.
2. **An ELAM driver** (`gravwell_elam.sys`). It is built with the WDK and has a
   `MicrosoftElamCertificateInfo` resource. That resource lists the hash of the
   certificate that signs `gravwell_windows.exe`. The driver needs no runtime
   logic.
3. **The ELAM driver signed by Microsoft**, through the MVI / Hardware Dev
   Center process.
4. **`gravwell_windows.exe` Authenticode-signed** with the certificate named in
   the ELAM resource. Every image a PPL process loads must be signed. The Go
   binary is static, so no other DLLs need signing.

## Building a PPL-capable MSI

```bat
set ELAM_DRIVER=C:\path\to\gravwell_elam.sys
build.bat
```

When `ELAM_DRIVER` is set, the MSI does three extra things:

- It installs `gravwell_elam.sys` next to the ingester.
- It runs `gravwell_windows.exe -install-elam <driver>`. That calls
  `InstallELAMCertificateInfo` to register the driver's certificate
  information.
- It runs `gravwell_windows.exe -set-protected`. That calls
  `ChangeServiceConfig2(SERVICE_CONFIG_LAUNCH_PROTECTED,
  SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT)` on the `GravwellWindows` service.

When `ELAM_DRIVER` is not set, the MSI is identical to a normal build.

## Configuration

```
[ETW "threat-intel"]
	Tag-Name=etw-ti
	Provider=Microsoft-Windows-Threat-Intelligence
	Match-Any-Keyword=KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
	Match-Any-Keyword=KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
```

Keyword names are resolved from the provider manifest at startup. You can also
give numeric masks.

## Behaviour when the ingester is not protected

Before it starts a session, the ingester checks its own protection level with
`GetProcessInformation(ProcessProtectionLevelInfo)`. If a sensitive provider is
configured and the process is not running as antimalware PPL:

- One error is logged, for example: `provider requires the ingester to run as an
  antimalware protected process light (PPL): Microsoft-Windows-Threat-Intelligence;
  service is running at protection level None`.
- That `[ETW]` section is disabled for the life of the process. It is not
  retried.
- Every other `[EventChannel]`, `[Follower]` and `[ETW]` section keeps running.

Interactive mode (`gravwell_windows.exe -v`) can never receive Threat-Intelligence
events, because only the service can be launched protected.

## Constraints of running as PPL

- Debuggers and other unprotected processes cannot open or inject into the
  service. This is the intended protection, but it also makes troubleshooting
  harder.
- Unsigned helper executables or DLLs cannot be loaded.
- Only a protected process can remove launch protection. To troubleshoot,
  uninstall the MSI, which deletes the service. Then reinstall a build without
  `ELAM_DRIVER`.

Gravwell does not use, and does not support, any technique that obtains PPL
without a Microsoft-signed ELAM driver.
