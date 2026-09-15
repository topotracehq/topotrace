# Muster Windows agent

A minimal, dependency-free PowerShell agent that scans a Windows host and
reports it to a running Muster server. See `muster-agent.ps1`'s own
header comment (`Get-Help .\muster-agent.ps1 -Full` works too) for the
full parameter list and design notes -- this file is a short pointer,
not a duplicate.

## Requirements

- Windows PowerShell 5.1+ (ships with Windows 10 / Server 2016+) or
  PowerShell 7+.
- `tar.exe` on PATH. Built into Windows 10 1803+ and Windows Server
  2019+ (`System32\tar.exe`, a bsdtar/libarchive build) -- check with
  `tar.exe --version`. No install, no admin rights needed.
- Network access from the Windows host to the Muster server's ingest
  port (`9090` by default).

## Quick start

```powershell
.\muster-agent.ps1 -MusterHost <server-ip-or-hostname>
```

Reports this machine under its real computer name. Run
`Get-Help .\muster-agent.ps1 -Full` for every parameter (`-HostName` to
report under a different name, `-Platform`, `-MusterPort`, `-OutDir`,
`-KeepFiles` to inspect what was collected/sent).

If your PowerShell execution policy blocks running the script, either
run it with:

```powershell
powershell -ExecutionPolicy Bypass -File .\muster-agent.ps1 -MusterHost <server>
```

or unblock the downloaded file first (`Unblock-File .\muster-agent.ps1`),
per your organization's usual policy for one-off scripts.

## What it collects

Four flat "Key: Value" files (`cpu.txt`, `memory.txt`, `os.txt`,
`system.txt`), all sourced from `Get-CimInstance` (`Win32_Processor`,
`Win32_OperatingSystem`, `Win32_ComputerSystem`) -- the exact same
built-in WMI/CIM classes any inventory tool would use, nothing
third-party. The field names are dictated by what
`internal/cook/windows.go` on the server side parses; if you need an
extra field, add it on both sides together.

## Verification status

The server-side half of Windows support (`internal/cook/windows.go`,
its unit tests, and the whole ingest → cook → store → API → web UI
pipeline) has been fully verified end to end, including live browser
screenshots of a simulated Windows host on the dashboard, detail page,
and Kanban board.

This script itself has not been run on a real Windows machine as part
of building it -- there was no Windows host or PowerShell runtime
available in the environment it was written in. It was written and
reasoned through carefully (matching the protocol and field names
byte-for-byte against the verified Go side), but treat a first run the
way you would any new unverified script: try it against a test/dev
Muster instance before pointing it at anything that matters.
