<#
.SYNOPSIS
    Minimal Windows agent for Muster: collects basic system facts and
    pushes them to a Muster ingest daemon over the MUSTER1 wire protocol.

.DESCRIPTION
    This is the Windows counterpart to cmd/demoagent -- a small,
    dependency-free script, not a service or a scheduled-task installer.
    It exists so you can point it at a real Windows box and see real data
    show up in Muster, the same way `go run ./cmd/demoagent` does for
    Linux test fixtures.

    It collects four flat "Key: Value" capture files via Get-CimInstance
    (cpu.txt, memory.txt, os.txt, system.txt) into a temp directory,
    packages them with Windows' own built-in tar.exe (ships with Windows
    10 1803+ and Windows Server 2019+ -- no install needed), and sends the
    resulting .tar.gz to the ingest daemon over a raw TCP socket using the
    same MUSTER1 header-plus-payload protocol cmd/demoagent uses:

        MUSTER1 <platform> <host> <payload-bytes>\n
        <that many raw bytes of gzip-compressed tar>

    The capture file field names deliberately match what
    internal/cook/windows.go parses -- see that file's doc comment for the
    full field-name contract. If you change one side, change the other.

    Requirements: Windows PowerShell 5.1+ (or PowerShell 7+), and tar.exe
    on PATH (built into Windows 10 1803+ / Server 2019+; check with
    `tar.exe --version`). No admin rights, no modules to install.

.PARAMETER MusterHost
    Hostname or IP of the machine running the Muster ingest daemon.

.PARAMETER MusterPort
    TCP port the ingest daemon is listening on (see docker-compose.yml /
    -ingest-addr; the shipped default is 9090).

.PARAMETER HostName
    Name to report this host as in Muster. Defaults to the local computer
    name. Must match the server's token rules: letters, digits, '.', '_',
    '-' only, max 128 characters.

.PARAMETER Platform
    Platform tag to report. Defaults to "windows" -- only change this if
    you know internal/cook has (or will have) a matching parser, otherwise
    the server will store the host with an empty summary.

.PARAMETER OutDir
    Directory to write the capture files and archive into. Defaults to a
    fresh folder under $env:TEMP. Created if missing.

.PARAMETER KeepFiles
    Don't delete OutDir's capture files and archive after sending. Useful
    for inspecting exactly what was collected/sent.

.EXAMPLE
    .\muster-agent.ps1 -MusterHost 192.168.1.50 -MusterPort 9090

    Scans this machine and sends it to the ingest daemon at
    192.168.1.50:9090, reporting as this machine's computer name.

.EXAMPLE
    .\muster-agent.ps1 -MusterHost localhost -HostName winbox01 -KeepFiles

    Reports as "winbox01" instead of the real computer name, and leaves
    the collected capture files + archive on disk afterward for review.

.NOTES
    This script has been carefully written to match the wire protocol and
    capture-file format Muster's Go server expects, and that server-side
    contract has been verified end to end (ingest -> cook -> store -> API
    -> web UI) using a synthetic payload in this exact format. The
    PowerShell itself, however, has NOT been executed on an actual
    Windows machine as part of building this -- there was no Windows host
    or PowerShell runtime available in the environment this was written
    in. Please treat first runs with the normal caution you'd give any
    new script: try it against a test/dev Muster instance first.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MusterHost,

    [int]$MusterPort = 9090,

    [string]$HostName = $env:COMPUTERNAME,

    [string]$Platform = "windows",

    [string]$OutDir = (Join-Path $env:TEMP "muster-agent-$([guid]::NewGuid().ToString('N').Substring(0,8))"),

    [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"

function Assert-SafeToken {
    param([string]$Value, [string]$Name)
    if ($Value.Length -eq 0 -or $Value.Length -gt 128 -or ($Value -notmatch '^[a-zA-Z0-9._-]+$')) {
        throw "$Name '$Value' is not a valid Muster token -- must be 1-128 chars of letters, digits, '.', '_', '-' only (this matches the server's own validation, so a bad token would be rejected there anyway)."
    }
}

Assert-SafeToken -Value $Platform -Name "-Platform"
Assert-SafeToken -Value $HostName -Name "-HostName"

$tar = Get-Command tar.exe -ErrorAction SilentlyContinue
if (-not $tar) {
    throw "tar.exe not found on PATH. It ships with Windows 10 1803+ and Windows Server 2019+ under System32 -- if it's genuinely missing, this script can't package the capture files without it."
}

Write-Host "Collecting system info into $OutDir ..."
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# --- cpu.txt -----------------------------------------------------------
# Multi-socket boxes report one Win32_Processor instance per socket; we
# only care about a simple single-line summary here, so the first socket
# stands in for "the CPU" and NumberOfLogicalProcessors/NumberOfCores are
# that socket's own counts (not a cross-socket total). Good enough for a
# test/demo agent; a real inventory agent would want to sum these.
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
@(
    "Name: $($cpu.Name)"
    "Manufacturer: $($cpu.Manufacturer)"
    "NumberOfCores: $($cpu.NumberOfCores)"
    "NumberOfLogicalProcessors: $($cpu.NumberOfLogicalProcessors)"
    "MaxClockSpeedMHz: $($cpu.MaxClockSpeed)"
) | Set-Content -Path (Join-Path $OutDir "cpu.txt") -Encoding ascii

# --- memory.txt + os.txt ------------------------------------------------
$os = Get-CimInstance -ClassName Win32_OperatingSystem
@(
    "TotalVisibleMemoryKB: $($os.TotalVisibleMemorySize)"
    "FreePhysicalMemoryKB: $($os.FreePhysicalMemory)"
) | Set-Content -Path (Join-Path $OutDir "memory.txt") -Encoding ascii

@(
    "Caption: $($os.Caption)"
    "Version: $($os.Version)"
    "BuildNumber: $($os.BuildNumber)"
    "OSArchitecture: $($os.OSArchitecture)"
) | Set-Content -Path (Join-Path $OutDir "os.txt") -Encoding ascii

# --- system.txt ----------------------------------------------------------
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bootTime = $os.LastBootUpTime
$up = (Get-Date) - $bootTime
$uptimeStr = "{0} days, {1}:{2:D2}:{3:D2}" -f $up.Days, $up.Hours, $up.Minutes, $up.Seconds

@(
    "Hostname: $($cs.Name)"
    "Domain: $($cs.Domain)"
    "Uptime: $uptimeStr"
) | Set-Content -Path (Join-Path $OutDir "system.txt") -Encoding ascii

# --- package -------------------------------------------------------------
$archivePath = Join-Path $OutDir "payload.tar.gz"
Write-Host "Packaging capture files with tar.exe ..."
# -C changes into $OutDir before adding files, so the archive contains
# bare "cpu.txt" etc. at its root -- matching what the server's
# extractPayload() expects (flat files, no leading directory component).
& tar.exe -czf $archivePath -C $OutDir cpu.txt memory.txt os.txt system.txt
if ($LASTEXITCODE -ne 0) {
    throw "tar.exe exited with code $LASTEXITCODE"
}

$payload = [System.IO.File]::ReadAllBytes($archivePath)
Write-Host "Packaged $($payload.Length) bytes."

# --- send over MUSTER1 ----------------------------------------------------
Write-Host "Connecting to ${MusterHost}:${MusterPort} ..."
$client = [System.Net.Sockets.TcpClient]::new()
try {
    $client.Connect($MusterHost, $MusterPort)
    $stream = $client.GetStream()

    $header = "MUSTER1 $Platform $HostName $($payload.Length)`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    $stream.Write($payload, 0, $payload.Length)
    $stream.Flush()

    $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
    $reply = $reader.ReadLine()
    Write-Host "Server replied: $reply"

    if ($reply -notmatch '^OK\b') {
        throw "Muster ingest daemon did not report success: $reply"
    }
}
finally {
    $client.Close()
}

if ($KeepFiles) {
    Write-Host "Capture files kept at: $OutDir"
} else {
    Remove-Item -Path $OutDir -Recurse -Force
}

Write-Host "Done -- reported as platform='$Platform' host='$HostName'."
