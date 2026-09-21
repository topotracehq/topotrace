################################################################################
# @file         register-scheduled-task.ps1
# @brief        Part of the TopoTrace windows module.
# @project      TopoTrace
#
# @author       Michael McGinnis
# @date         2026-09-17
# @version      1.0.0
#
# Copyright (c) 2026 TopoTrace LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
################################################################################

<#
.SYNOPSIS
    Registers topotrace-agent.ps1 as a recurring Windows Scheduled Task --
    the bare-metal equivalent of what charts/topotrace/templates/
    cronjob-agent.yaml already does inside Kubernetes.

.DESCRIPTION
    TopoTrace's Kubernetes chart covers scheduled execution *inside* a
    cluster; a real Windows host running the script directly still needs
    a Scheduled Task wired up by hand -- this is that wiring, done once
    instead of via a handful of schtasks.exe/GUI steps that are easy to
    get subtly wrong (wrong account, wrong working directory, repetition
    that silently stops after a day).

    Requires an elevated (Administrator) PowerShell session -- creating a
    Scheduled Task that runs whether or not a user is logged in needs
    that, same as it would from Task Scheduler's GUI.

.PARAMETER TopoTraceHost
    Passed straight through to topotrace-agent.ps1 -TopoTraceHost.

.PARAMETER TopoTracePort
    Passed straight through to topotrace-agent.ps1 -TopoTracePort.

.PARAMETER Token
    Passed straight through to topotrace-agent.ps1 -Token, if the server was
    started with -auth-token.

.PARAMETER TaskName
    Scheduled Task name. Defaults to "TopoTraceAgent".

.PARAMETER IntervalMinutes
    How often to run. Defaults to 15, matching charts/topotrace/values.yaml's
    default agent.cronjob.schedule (*/15 * * * *) -- change both together
    if you want a different cadence across your Kubernetes and bare-metal
    fleets.

.EXAMPLE
    .\register-scheduled-task.ps1 -TopoTraceHost 192.168.1.50 -Token $env:TOPOTRACE_TOKEN

.NOTES
    Uninstall with: Unregister-ScheduledTask -TaskName TopoTraceAgent -Confirm:$false
    Run it once right now (without waiting for the schedule) with:
        Start-ScheduledTask -TaskName TopoTraceAgent
    Verification status: written and reasoned through carefully against
    the real Register-ScheduledTask/New-ScheduledTaskTrigger cmdlets'
    documented behavior, but -- like topotrace-agent.ps1 itself before your
    testing -- not yet run against a real Windows Task Scheduler as part
    of building it. Confirm the task actually fires on schedule
    (Get-ScheduledTaskInfo -TaskName TopoTraceAgent shows LastRunTime/
    LastTaskResult) before relying on it unattended.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TopoTraceHost,

    [int]$TopoTracePort = 9090,

    [string]$Token = "",

    [string]$TaskName = "TopoTraceAgent",

    [int]$IntervalMinutes = 15
)

$ErrorActionPreference = "Stop"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This must be run as Administrator -- Register-ScheduledTask needs it to create a task that runs whether or not a user is logged in."
}

$scriptPath = Join-Path $PSScriptRoot "topotrace-agent.ps1"
if (-not (Test-Path $scriptPath)) {
    throw "topotrace-agent.ps1 not found next to this script at $scriptPath -- keep register-scheduled-task.ps1 alongside it."
}

$argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -TopoTraceHost `"$TopoTraceHost`" -TopoTracePort $TopoTracePort"
if ($Token) {
    $argList += " -Token `"$Token`""
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argList
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBattery -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "Runs the TopoTrace agent every $IntervalMinutes minutes, reporting this host to $TopoTraceHost." `
    -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName', running every $IntervalMinutes minutes."
Write-Host "Run it once right now with: Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Check its last result with: Get-ScheduledTaskInfo -TaskName '$TaskName'"
