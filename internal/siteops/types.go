// Package siteops defines bounded work sent to a site-local worker.
package siteops

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const WorkerKind = "site_worker"
const JobKind = "site_job"
const SightingKind = "site_sighting"

var Name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Worker struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TokenHash string    `json:"token_hash,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}
type Target struct {
	Address      string    `json:"address"`
	Host         string    `json:"host"`
	State        string    `json:"state"`
	Detail       string    `json:"detail"`
	EnrollmentID string    `json:"enrollment_id,omitempty"`
	StartedAt    time.Time `json:"started_at"`
}
type Job struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	WorkerID      string    `json:"worker_id"`
	Kind          string    `json:"kind"`
	CIDR          string    `json:"cidr"`
	Ports         []int     `json:"ports"`
	IntervalHours int       `json:"interval_hours"`
	NextRun       time.Time `json:"next_run"`
	Platform      string    `json:"platform"`
	Profile       string    `json:"profile"`
	MusterHost    string    `json:"muster_host"`
	MusterPort    int       `json:"muster_port"`
	Targets       []Target  `json:"targets"`
	Pilot         int       `json:"pilot"`
	Phase         string    `json:"phase"`
	Detail        string    `json:"detail"`
	Lease         string    `json:"lease,omitempty"`
	LeaseUntil    time.Time `json:"lease_until"`
	ActiveTarget  int       `json:"active_target"`
	CreatedAt     time.Time `json:"created_at"`
}
type Sighting struct {
	ID         string    `json:"id"`
	WorkerID   string    `json:"worker_id"`
	Address    string    `json:"address"`
	Ports      []int     `json:"ports"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Review     string    `json:"review"`
	Confidence string    `json:"confidence"`
}
type Task struct {
	Job    Job    `json:"job"`
	Target Target `json:"target"`
	Token  string `json:"token,omitempty"`
}
type Result struct {
	Lease  string     `json:"lease"`
	OK     bool       `json:"ok"`
	Detail string     `json:"detail"`
	Assets []Sighting `json:"assets"`
}

func (j Job) Validate() error {
	if j.Name == "" || len(j.Name) > 100 || j.WorkerID == "" {
		return fmt.Errorf("name and worker are required")
	}
	if j.Kind == "scan" {
		p, e := netip.ParsePrefix(j.CIDR)
		if e != nil || !p.Addr().Is4() || p.Bits() < 20 {
			return fmt.Errorf("use an IPv4 range /20 or smaller")
		}
		if len(j.Ports) == 0 || len(j.Ports) > 32 {
			return fmt.Errorf("select 1–32 ports")
		}
		for _, p := range j.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid port")
			}
		}
		if j.IntervalHours < 0 || j.IntervalHours > 720 {
			return fmt.Errorf("schedule must be 0–720 hours")
		}
		return nil
	}
	if j.Kind != "deploy" || (j.Platform != "linux" && j.Platform != "windows") || !Name.MatchString(j.Profile) || !Name.MatchString(j.MusterHost) || j.MusterPort < 1 || j.MusterPort > 65535 {
		return fmt.Errorf("invalid platform, credential profile or ingest destination")
	}
	if len(j.Targets) == 0 || len(j.Targets) > 100 || j.Pilot < 1 || j.Pilot > len(j.Targets) {
		return fmt.Errorf("provide 1–100 targets and a pilot count")
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	for _, t := range j.Targets {
		a, e := netip.ParseAddr(t.Address)
		if e != nil || !a.Is4() || !Name.MatchString(t.Host) || names[t.Host] || addresses[t.Address] {
			return fmt.Errorf("targets need unique IPv4 addresses and unique valid host names")
		}
		names[t.Host] = true
		addresses[t.Address] = true
	}
	return nil
}
