################################################################################
# @file         muster-agent.ps1
# @brief        Part of the Muster windows module.
# @project      Muster
#
# @author       Michael McGinnis
# @date         2026-09-14
# @version      1.0.0
#
# Copyright (c) 2026 TopoTrace LLC. All rights reserved.
# Licensed under the MIT License -- see the LICENSE file at the repository root.
################################################################################

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

        MUSTER1 <platform> <host> <token> <payload-bytes>\n
        <that many raw bytes of gzip-compressed tar>

    If the server hands back a second reply line -- a queued remediation
    action (`ACTION <id> <verb> <arg>`) -- this script executes it if
    (and only if) the verb is one of the small set case-matched in
    Invoke-MusterAction below, then reports the outcome back over a
    second, short MUSTER1-RESULT connection. See
    internal/remediate/actions.go for the authoritative allow-list; an
    unknown or not-yet-implemented verb is reported "unsupported," never
    guessed at or passed to a shell as-is.

    The capture file field names deliberately match what
    internal/cook/windows.go parses -- see that file's doc comment for the
    full field-name contract. If you change one side, change the other.

    Requirements: Windows PowerShell 5.1+ (or PowerShell 7+), and tar.exe
    on PATH (built into Windows 10 1803+ / Server 2019+; check with
    `tar.exe --version`). No admin rights, no modules to install -- except
    that Restart-Service (used by the restart-service remediation action,
    if one is ever queued for this host) needs whatever privileges
    restarting that specific service normally requires.

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

.PARAMETER Token
    Shared secret matching the server's -auth-token, if it was started
    with one. Omit if the server has no -auth-token configured. Same
    charset restriction as -HostName applies.

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

.EXAMPLE
    .\muster-agent.ps1 -MusterHost 192.168.1.50 -Token $env:MUSTER_TOKEN

    Same, but authenticates with a shared secret -- required once the
    server is started with -auth-token.

.NOTES
    This script has been carefully written to match the wire protocol and
    capture-file format Muster's Go server expects, and that server-side
    contract has been verified end to end (ingest -> cook -> store -> API
    -> web UI) using a synthetic payload in this exact format. Treat a
    first run -- and especially the remediation path added alongside
    -Token, which has not been exercised against a live server with a
    real queued action -- with the normal caution you'd give any new
    script: try it against a test/dev Muster instance first.
#>
[CmdletBinding()]
param(
    [string]$MusterHost = "",

    [int]$MusterPort = 9090,

    [string]$HostName = $env:COMPUTERNAME,

    [string]$Platform = "windows",

    [string]$Token = "",

    [string]$OutDir = (Join-Path $env:TEMP "muster-agent-$([guid]::NewGuid().ToString('N').Substring(0,8))"),

    [switch]$KeepFiles,

    # AirgapOut, when set, skips the network send entirely and instead
    # base64-encodes the packaged archive into the JSON body
    # POST /api/airgap-report expects, written to this path ("-" for
    # stdout) -- for a host with no route to Muster at all. See
    # agent/airgap/README.md.
    [string]$AirgapOut = ""
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
if ($Token) {
    Assert-SafeToken -Value $Token -Name "-Token"
}
$AuthToken = if ($Token) { $Token } else { "-" }

if (-not $MusterHost -and -not $AirgapOut) {
    throw "-MusterHost is required (or -AirgapOut, for a host with no network route to Muster at all -- see agent/airgap/README.md)."
}

# Send-MusterActionResult opens a short second TCP connection to report
# what happened when this script executed a delivered action. Best-
# effort: a failure to report back doesn't change the outcome of the run
# that already succeeded at its actual job (submitting this host's
# report).
function Send-MusterActionResult {
    param(
        [string]$MusterHost, [int]$MusterPort, [string]$Token,
        [string]$ActionId, [string]$Status, [string]$Detail
    )
    $detailBytes = [System.Text.Encoding]::UTF8.GetBytes($Detail)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.Connect($MusterHost, $MusterPort)
        $stream = $client.GetStream()
        $header = "MUSTER1-RESULT $Token $ActionId $Status $($detailBytes.Length)`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($detailBytes, 0, $detailBytes.Length)
        $stream.Flush()
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
        $resultReply = $reader.ReadLine()
        Write-Host "  Result report acknowledged: $resultReply"
    } catch {
        Write-Warning "  (could not report the action result: $($_.Exception.Message))"
    } finally {
        $client.Close()
    }
}

# Invoke-MusterAction executes an allow-listed remediation action the
# server handed back after accepting this run's report. Only the verbs
# explicitly case-matched below ever run anything -- an unknown or
# not-yet-implemented verb (see internal/remediate/actions.go) is
# reported as unsupported, never guessed at or passed to a shell as-is.
function Invoke-MusterAction {
    param(
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][string]$MusterHost,
        [Parameter(Mandatory = $true)][int]$MusterPort,
        [Parameter(Mandatory = $true)][string]$Token
    )
    # Line is "ACTION <id> <verb> <arg>".
    $parts = $Line -split '\s+'
    $actionId = $parts[1]
    $verb = $parts[2]
    $arg = $parts[3]

    Write-Host "Received action: id=$actionId verb=$verb arg=$arg"

    $status = "fail"
    $detail = "unsupported action verb: $verb"

    switch ($verb) {
        "restart-service" {
            try {
                Restart-Service -Name $arg -Force -ErrorAction Stop
                $status = "ok"
                $detail = "restarted $arg via Restart-Service"
            } catch {
                $status = "fail"
                $detail = "Restart-Service $arg failed: $($_.Exception.Message)"
            }
        }
        "apply-updates" {
            $status = "fail"
            $detail = "apply-updates is allow-listed but not yet implemented by this agent"
        }
    }

    Write-Host "Action result: $status -- $detail"
    Send-MusterActionResult -MusterHost $MusterHost -MusterPort $MusterPort -Token $Token -ActionId $actionId -Status $status -Detail $detail
}

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

# --- extra feeds ---------------------------------------------------------
# Each is fully best-effort (wrapped so one missing cmdlet/module or one
# access-denied doesn't abort the whole run) and written as CSV via
# ConvertTo-Csv -NoTypeInformation -- internal/cook/windows_extra.go
# parses that directly, headers and all, no hand-rolled quoting on either
# side. A cmdlet that legitimately returns nothing (e.g. no listening
# TCP sockets) still produces a header-only CSV, which the cook side
# treats as "zero rows," not an error.
$extraFiles = @()

function Export-MusterExtra {
    param([string]$Name, [scriptblock]$Collect)
    try {
        & $Collect | ConvertTo-Csv -NoTypeInformation | Set-Content -Path (Join-Path $OutDir $Name) -Encoding ascii
        $script:extraFiles += $Name
    } catch {
        Write-Host "  (skipping $Name -- $($_.Exception.Message))"
    }
}

Export-MusterExtra -Name "disks.txt" -Collect {
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, Size, FreeSpace
}

Export-MusterExtra -Name "software.txt" -Collect {
    Get-ItemProperty @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion
}

Export-MusterExtra -Name "services_running.txt" -Collect {
    Get-Service | Where-Object { $_.Status -eq "Running" } |
        Select-Object Name, DisplayName, Status
}

Export-MusterExtra -Name "ports.txt" -Collect {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort
}

Export-MusterExtra -Name "users.txt" -Collect {
    Get-LocalUser | Select-Object Name, Enabled
}

Export-MusterExtra -Name "netadapters.txt" -Collect {
    Get-NetIPAddress -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, AddressFamily, IPAddress
}

Export-MusterExtra -Name "scheduledtasks.txt" -Collect {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" } |
        Select-Object TaskName, State
}

# Installed patches, not pending ones -- the real "what's outstanding"
# answer needs the Windows Update COM API, out of scope for this pass.
# See internal/cook/windows_extra.go's cookWinHotfixes doc comment.
Export-MusterExtra -Name "hotfixes.txt" -Collect {
    Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, InstalledOn
}

# Certificates in the machine's Personal store -- where IIS/RDP/
# service certs live -- with expiry, for internal/cook's tls_certificates
# category. Excludes the trusted-root stores on purpose.
Export-MusterExtra -Name "certs.txt" -Collect {
    Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Select-Object Thumbprint, Subject, Issuer, @{ Name = "NotAfter"; Expression = { $_.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } }
}

Export-MusterExtra -Name "firewall.txt" -Collect {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled
}

# --- browser extensions ------------------------------------------------
# Same tab-separated line format as the Linux/macOS agents (see
# agent/ubuntu/muster-agent.sh): browser, user/profile, id, version,
# base64 manifest.json, base64 English messages.json. Chrome, Edge and
# Brave all keep per-profile extensions under
# <User Data>\<profile>\Extensions\<id>\<version>\manifest.json.
# Best-effort: an unreadable profile is skipped; no extensions means the
# file isn't written at all.
try {
    $extLines = New-Object System.Collections.Generic.List[string]
    $browserDirs = @(
        @{ Name = "chrome"; Path = "AppData\Local\Google\Chrome\User Data" },
        @{ Name = "edge";   Path = "AppData\Local\Microsoft\Edge\User Data" },
        @{ Name = "brave";  Path = "AppData\Local\BraveSoftware\Brave-Browser\User Data" }
    )
    foreach ($userDir in Get-ChildItem -Path (Join-Path $env:SystemDrive "Users") -Directory -ErrorAction SilentlyContinue) {
        foreach ($b in $browserDirs) {
            $root = Join-Path $userDir.FullName $b.Path
            if (-not (Test-Path $root)) { continue }
            foreach ($manifest in Get-ChildItem -Path $root -Filter manifest.json -Recurse -Depth 4 -ErrorAction SilentlyContinue) {
                $verDir = $manifest.Directory
                if ($verDir.Parent.Parent.Name -ne "Extensions") { continue }
                $idDir = $verDir.Parent
                $profileDir = $idDir.Parent.Parent
                $msgs = ""
                foreach ($loc in @("en", "en_US", "en_GB")) {
                    $m = Join-Path $verDir.FullName ("_locales\" + $loc + "\messages.json")
                    if (Test-Path $m) { $msgs = [Convert]::ToBase64String([IO.File]::ReadAllBytes($m)); break }
                }
                $man = [Convert]::ToBase64String([IO.File]::ReadAllBytes($manifest.FullName))
                $extLines.Add(($b.Name, ($userDir.Name + "/" + $profileDir.Name), $idDir.Name, $verDir.Name, $man, $msgs) -join "`t")
            }
        }
    }
    if ($extLines.Count -gt 0) {
        [IO.File]::WriteAllLines((Join-Path $OutDir "browser_extensions.txt"), $extLines)
        $extraFiles += "browser_extensions.txt"
    }
} catch {
    Write-Host "  (skipping browser_extensions.txt -- $($_.Exception.Message))"
}

# --- package -------------------------------------------------------------
$archivePath = Join-Path $OutDir "payload.tar.gz"
Write-Host "Packaging capture files with tar.exe ..."
# -C changes into $OutDir before adding files, so the archive contains
# bare "cpu.txt" etc. at its root -- matching what the server's
# extractPayload() expects (flat files, no leading directory component).
$captureFiles = @("cpu.txt", "memory.txt", "os.txt", "system.txt") + $extraFiles
& tar.exe -czf $archivePath -C $OutDir @captureFiles
if ($LASTEXITCODE -ne 0) {
    throw "tar.exe exited with code $LASTEXITCODE"
}

$payload = [System.IO.File]::ReadAllBytes($archivePath)
Write-Host "Packaged $($payload.Length) bytes."

# --- air-gapped output (no network path to Muster at all) ----------------
# Same capture + tar.gz packaging as the normal path above; instead of
# opening a socket, base64-encode the archive and write it (or print it)
# as the JSON body POST /api/airgap-report expects. See
# agent/airgap/README.md for the intended workflow.
if ($AirgapOut) {
    Write-Host "Air-gapped mode: encoding the payload instead of sending it over the network."
    $payloadB64 = [System.Convert]::ToBase64String($payload)
    $json = "{`"platform`":`"$Platform`",`"host`":`"$HostName`",`"payload_b64`":`"$payloadB64`"}"
    if ($AirgapOut -eq "-") {
        Write-Output $json
    } else {
        Set-Content -Path $AirgapOut -Value $json -NoNewline -Encoding ascii
        Write-Host "Wrote air-gapped report to $AirgapOut ($((Get-Item $AirgapOut).Length) bytes)."
        Write-Host "Move this file to any machine that can reach Muster and POST it, e.g.:"
        Write-Host "  curl -sS -X POST 'http://<muster-host>:8080/api/airgap-report' -H 'Content-Type: application/json' --data '@$AirgapOut'"
    }
    if (-not $KeepFiles) {
        Remove-Item -Path $OutDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

# --- send over MUSTER1 ----------------------------------------------------
Write-Host "Connecting to ${MusterHost}:${MusterPort} ..."
$client = [System.Net.Sockets.TcpClient]::new()
$actionLine = $null
try {
    $client.Connect($MusterHost, $MusterPort)
    $stream = $client.GetStream()

    $header = "MUSTER1 $Platform $HostName $AuthToken $($payload.Length)`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    $stream.Write($payload, 0, $payload.Length)
    $stream.Flush()

    $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
    $reply = $reader.ReadLine()
    Write-Host "Server replied: $reply"

    # The server may follow "OK <n>" with one more line delivering a
    # queued remediation action for this host.
    $actionLine = $reader.ReadLine()

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

if ($actionLine -and $actionLine.StartsWith("ACTION")) {
    Invoke-MusterAction -Line $actionLine -MusterHost $MusterHost -MusterPort $MusterPort -Token $AuthToken
}
