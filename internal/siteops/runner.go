/*******************************************************************************
 * @file         runner.go
 * @brief        Part of the Muster siteops module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package siteops

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"muster/agent"
)

// Profiles are supplied locally, never fetched from the control server.
type Profile struct {
	User         string `json:"user"`
	IdentityFile string `json:"identity_file"`
	KnownHosts   string `json:"known_hosts"`
	PasswordEnv  string `json:"password_env"`
}
type Config struct {
	Server       string             `json:"server"`
	TokenEnv     string             `json:"token_env"`
	AllowHTTP    bool               `json:"allow_http"`
	AllowedCIDRs []string           `json:"allowed_cidrs"`
	IngestHost   string             `json:"ingest_host"`
	IngestPort   int                `json:"ingest_port"`
	Profiles     map[string]Profile `json:"profiles"`
}

func (c Config) Allowed(address string) bool {
	a, e := netip.ParseAddr(address)
	if e != nil {
		return false
	}
	for _, v := range c.AllowedCIDRs {
		p, e := netip.ParsePrefix(v)
		if e == nil && p.Contains(a) {
			return true
		}
	}
	return false
}
func Run(ctx context.Context, c Config, t Task) (Result, error) {
	result := Result{Lease: t.Job.Lease}
	if e := t.Job.Validate(); e != nil {
		return result, e
	}
	if t.Job.Kind == "scan" {
		a, e := Scan(ctx, c, t.Job)
		result.Assets = a
		result.OK = e == nil
		return result, e
	}
	if !c.Allowed(t.Target.Address) || t.Job.MusterHost != c.IngestHost || t.Job.MusterPort != c.IngestPort {
		return result, fmt.Errorf("target or ingest destination outside worker configuration")
	}
	if t.Job.ActiveTarget < 0 || t.Job.ActiveTarget >= len(t.Job.Targets) || t.Target != t.Job.Targets[t.Job.ActiveTarget] {
		return result, fmt.Errorf("target mismatch")
	}
	p, ok := c.Profiles[t.Job.Profile]
	if !ok {
		return result, fmt.Errorf("local credential profile missing")
	}
	script, e := InstallScript(t)
	if e != nil {
		return result, e
	}
	var cmd *exec.Cmd
	if t.Job.Platform == "linux" {
		if !Name.MatchString(p.User) || p.IdentityFile == "" || p.KnownHosts == "" {
			return result, fmt.Errorf("SSH profile needs user, identity_file and known_hosts")
		}
		cmd = exec.CommandContext(ctx, "ssh", "-F", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile="+p.KnownHosts, "-i", p.IdentityFile, p.User+"@"+t.Target.Address, "sudo -n /bin/bash -s")
		cmd.Stdin = strings.NewReader(script)
	} else {
		if runtime.GOOS != "windows" {
			return result, fmt.Errorf("WinRM needs a Windows worker")
		}
		password := os.Getenv(p.PasswordEnv)
		if password == "" || p.User == "" {
			return result, fmt.Errorf("WinRM credential environment missing")
		}
		// Payload and password travel on stdin / inherited environment, never command arguments.
		outer := `$ErrorActionPreference='Stop'
$password=ConvertTo-SecureString $env:MUSTER_WORKER_REMOTE_PASSWORD -AsPlainText -Force
$credential=[pscredential]::new($env:MUSTER_WORKER_REMOTE_USER,$password)
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString([]byte(script)) + `'))
Invoke-Command -ComputerName '` + t.Target.Address + `' -UseSSL -Credential $credential -ScriptBlock ([scriptblock]::Create($source)) -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 300000)
`
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-")
		cmd.Stdin = strings.NewReader(outer)
		cmd.Env = append(os.Environ(), "MUSTER_WORKER_REMOTE_PASSWORD="+password, "MUSTER_WORKER_REMOTE_USER="+p.User)
	}
	// Remote output may contain secrets; only the exit outcome leaves this process.
	e = cmd.Run()
	result.OK = e == nil
	if e != nil {
		return result, fmt.Errorf("remote operation failed (%s); inspect target authentication, privilege and service logs", t.Job.Platform)
	}
	return result, nil
}
func Scan(ctx context.Context, c Config, j Job) ([]Sighting, error) {
	p, e := netip.ParsePrefix(j.CIDR)
	if e != nil {
		return nil, e
	}
	p = p.Masked()
	addresses := []string{}
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		if !c.Allowed(a.String()) {
			return nil, fmt.Errorf("range exceeds local allowlist")
		}
		addresses = append(addresses, a.String())
	}
	var mu sync.Mutex
	out := []Sighting{}
	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for address := range work {
				ports := []int{}
				for _, port := range j.Ports {
					if ctx.Err() != nil {
						return
					}
					conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
					if err == nil {
						conn.Close()
						ports = append(ports, port)
					}
				}
				if len(ports) > 0 {
					mu.Lock()
					out = append(out, Sighting{Address: address, Ports: ports})
					mu.Unlock()
				}
			}
		}()
	}
send:
	for _, a := range addresses {
		select {
		case work <- a:
		case <-ctx.Done():
			break send
		}
	}
	close(work)
	wg.Wait()
	return out, ctx.Err()
}
func InstallScript(t Task) (string, error) {
	j := t.Job
	if e := j.Validate(); e != nil {
		return "", e
	}
	if !Name.MatchString(t.Target.Host) {
		return "", fmt.Errorf("invalid host")
	}
	preflight := j.Phase == "preflight"
	if !preflight && (j.Phase != "pilot" && j.Phase != "rollout") {
		return "", fmt.Errorf("invalid install phase")
	}
	if !preflight && (len(t.Token) < 32 || len(t.Token) > 128 || strings.Trim(t.Token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-abcdef") != "") {
		return "", fmt.Errorf("invalid enrollment token")
	}
	if j.Platform == "linux" {
		check := `set -eu
test "$(id -u)" = 0
test "$(uname -s)" = Linux
command -v systemctl >/dev/null
command -v tar >/dev/null
command -v gzip >/dev/null
command -v base64 >/dev/null
test -d /run/systemd/system
test ! -e /opt/muster-site-agent
test ! -e /etc/systemd/system/muster-site-agent.service
test ! -e /etc/systemd/system/muster-site-agent.timer
timeout 5 bash -c 'exec 3<>/dev/tcp/` + j.MusterHost + `/` + strconv.Itoa(j.MusterPort) + `'
`
		if preflight {
			return check, nil
		}
		b, e := agent.Scripts.ReadFile("ubuntu/muster-agent.sh")
		if e != nil {
			return "", e
		}
		return check + `umask 077
mkdir /opt/muster-site-agent
printf '%s' '` + base64.StdEncoding.EncodeToString(b) + `' | base64 -d > /opt/muster-site-agent/agent.sh
chmod 700 /opt/muster-site-agent/agent.sh
cat > /opt/muster-site-agent/run.sh <<'MUSTER_RUN'
#!/bin/bash
exec /bin/bash /opt/muster-site-agent/agent.sh --muster-host ` + j.MusterHost + ` --muster-port ` + strconv.Itoa(j.MusterPort) + ` --host-name ` + t.Target.Host + ` --token ` + t.Token + `
MUSTER_RUN
chmod 700 /opt/muster-site-agent/run.sh
cat > /etc/systemd/system/muster-site-agent.service <<'MUSTER_SERVICE'
[Unit]
Description=Muster site agent report
After=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/muster-site-agent/run.sh
TimeoutStartSec=10min
MUSTER_SERVICE
cat > /etc/systemd/system/muster-site-agent.timer <<'MUSTER_TIMER'
[Unit]
Description=Muster report every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
MUSTER_TIMER
systemctl daemon-reload
systemctl enable --now muster-site-agent.timer
systemctl start --no-block muster-site-agent.service
`, nil
	}
	check := `$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
Get-Command tar.exe -ErrorAction Stop | Out-Null
Get-Command Register-ScheduledTask -ErrorAction Stop | Out-Null
$dir=Join-Path $env:ProgramData 'MusterSiteAgent'
if (Test-Path -LiteralPath $dir) { throw 'Existing installation requires manual review' }
if (Get-ScheduledTask -TaskName MusterSiteAgent -ErrorAction SilentlyContinue) { throw 'Existing task requires manual review' }
$client=[Net.Sockets.TcpClient]::new()
try { $pending=$client.ConnectAsync('` + j.MusterHost + `',` + strconv.Itoa(j.MusterPort) + `);if (-not $pending.Wait(5000)) {throw 'Ingest unreachable'} } finally {$client.Dispose()}
`
	if preflight {
		return check, nil
	}
	b, e := agent.Scripts.ReadFile("windows/muster-agent.ps1")
	if e != nil {
		return "", e
	}
	run := `& "$PSScriptRoot\agent.ps1" -MusterHost '` + j.MusterHost + `' -MusterPort ` + strconv.Itoa(j.MusterPort) + ` -HostName '` + t.Target.Host + `' -Token '` + t.Token + `'`
	return check + `New-Item -ItemType Directory -Path $dir | Out-Null
$acl=Get-Acl -LiteralPath $dir
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
 $identity=[Security.Principal.SecurityIdentifier]::new($sid)
 $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $dir -AclObject $acl
[IO.File]::WriteAllBytes((Join-Path $dir 'agent.ps1'),[Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(b) + `'))
[IO.File]::WriteAllBytes((Join-Path $dir 'run.ps1'),[Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString([]byte(run)) + `'))
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -File "'+(Join-Path $dir 'run.ps1')+'"')
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName MusterSiteAgent -Action $action -Trigger $trigger -Principal $principal | Out-Null
Start-ScheduledTask -TaskName MusterSiteAgent
`, nil
}
