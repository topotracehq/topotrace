# Importing third-party scanner findings

Muster has its own vulnerability view: `internal/vuln` matches the
versions in a host's `installed_software` fact against a small curated
dataset (optionally augmented by an OSV.dev feed). That is honest about
what it is -- a demonstration that inventory plus a CVE source equals a
per-host finding list -- but nobody runs a security program on it. Any
organization that would deploy Muster already owns a scanner.

So Muster imports that scanner's output instead of pretending to
replace it. A CSV export goes in, findings come out attached to the
right host records, and from there they flow through exactly the same
paths Muster's own findings do: the host's Vulnerabilities card, the
`no-known-vulnerabilities` compliance check and its HIPAA/NIST
equivalents, the risk score's `vulnerabilities` factor, the fleet
summary counts, the vulnerabilities CSV, and the Ask Muster context.

## Supported formats

`format` is a query parameter, one of:

| `format` | Export | Columns read |
| --- | --- | --- |
| `nessus` | Tenable Nessus / Tenable.io CSV | `Host`, `Risk`, `Name`, `CVE`, `Port`, `Plugin ID`, `Synopsis`, `CVSS v3.0 Base Score` (falling back to v2.0, then `CVSS`) |
| `qualys` | Qualys VMDR scan report CSV | `DNS`/`FQDN` (falling back to `IP`), `Severity` (1-5), `Title`, `CVE ID`, `Port`, `QID`, `Threat`, `CVSS3 Base` (falling back to `CVSS Base`, then `CVSS`) |
| `generic` | anything you can shape yourself | `host`, `severity`, `title` (or `name`), `cve`, `port`, `cvss`, `description` |

Column lookup is case-insensitive and a leading UTF-8 BOM is stripped,
because both vendors' exports have one. Extra columns are ignored, so a
full unedited export works. Rows whose severity is informational, or
which have neither a title nor a CVE, are dropped -- a Nessus export is
mostly informational plugin output and none of it belongs in a findings
count.

Severity is normalized to `critical`, `high`, `medium` or `low`.
Qualys's 1-5 scale maps 5 to critical, 4 to high, 3 to medium and 2 to
low; 1 is informational and dropped.

## Host matching

Scanners identify a host however they happened to reach it: a short
hostname, an FQDN, or a bare IP. Muster tries, in order, the full name
as given, the name up to the first dot, and any IPv4 address from the
host's `network_interfaces` fact. So a Nessus row for `10.0.1.10`
lands on `web01.prod` if that is the address the agent reported, and a
Qualys row whose DNS column says `db01.prod` lands there by name.

Findings for hosts Muster does not know come back in the response's
`unmatched` map and are *not* stored. That is deliberate: the scanner
seeing something Muster has never enrolled is itself worth knowing
about (it is the same shadow-asset question `GET /api/graph` answers
from cloud discovery), and silently inventing host records from a CSV
would be worse than reporting the gap.

## The API

```
POST /api/scanner-import?format=nessus
Authorization: Bearer <admin token>
Content-Type: text/csv

<the CSV export, as the request body>
```

`admin` only, checked strictly (the endpoint refuses to run on a server
started with no `-auth-token`), and audited as `scanner-import` with
the format, the number of findings parsed, the number of hosts matched
and the number of unmatched scanner hosts. The body is capped at 2 MB;
split a larger export.

The response:

```json
{
  "format": "nessus",
  "parsed": 5,
  "matched": { "api01.prod": 1, "build01.eng": 1, "web01.prod": 2 },
  "hosts": ["api01.prod", "build01.eng", "web01.prod"],
  "unmatched": { "scanner-only-box.corp": [ { "host": "...", "cve": "...", "severity": "critical", "title": "..." } ] }
}
```

`GET /api/scanner-import/formats` lists the accepted format names, so
the dashboard's dropdown and any script stay in sync with the binary.

## How the findings are stored

Each matched host gets a `scanner_findings` fact -- the same
`model.Fact` shape every agent-collected category uses, so it is
visible in the host's raw facts, versioned by the store's change
tracking, and exported like anything else. `internal/signals.FromFacts`
reads that fact back and appends it to the host's `VulnFindings`, which
is the single place every downstream consumer already looks.

Findings carry a `source` (`nessus`, `qualys`, `generic`) that Muster's
own matches leave empty, so the two are always distinguishable. The
compliance detail line says so explicitly -- "2 known-vulnerable
package(s); 1 imported nessus finding(s)" -- the host card tags the row
"(imported from nessus)", and the vulnerabilities CSV has a `source`
column that reads `muster` for Muster's own matches.

One import replaces that host's whole `scanner_findings` fact, the same
way a fresh agent report replaces a host's `installed_software`. An
import is a snapshot of what the scanner currently says, not an
append-only log, so re-importing after a rescan is the intended way to
keep it current and importing two different scanners' exports means the
second one wins for any host they both cover.

## Dashboard

Compliance tab, "Import scanner findings": pick a format, choose the
CSV, and the browser reads the file and POSTs its contents. The result
lists matched hosts with counts and names the unmatched scanner hosts.
Each host's own page then shows the imported findings inline with
Muster's own, tagged with the scanner they came from. Screenshots of
both are in the repository README.

## What is verified

The parsers are unit tested (`internal/scanner/scanner_test.go`) and
the whole path was exercised end to end against a seeded local server:
Nessus, Qualys and generic exports imported, hosts matched by FQDN,
short name and IP, an unmatched scanner host reported and not stored,
informational rows dropped, the bad-format and no-usable-rows errors
returned as 400s, a non-admin request refused, and the resulting
findings confirmed in the host card, the compliance detail, the risk
factor, the fleet summary and the vulnerabilities CSV.

The sample CSVs used for that were hand-written to each vendor's
documented column layout. No export from a live Nessus or Qualys
console has been run through it, so a real-world export with an
unexpected column name may need the `get(row, ...)` alias list in
`internal/scanner.Parse` extended.
