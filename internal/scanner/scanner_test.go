/*******************************************************************************
 * @file         scanner_test.go
 * @brief        Tests for the Muster scanner package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package scanner

import (
	"strings"
	"testing"
)

const nessusCSV = `"Plugin ID","CVE","CVSS v2.0 Base Score","Risk","Host","Protocol","Port","Name","Synopsis","Description","Solution","See Also","Plugin Output"
"51192","CVE-2014-6271","10.0","Critical","db01.prod","tcp","22","Bash Remote Code Execution (Shellshock)","The remote host is affected by a code injection vulnerability.","...","Update bash.","",""
"10863","","0.0","None","db01.prod","tcp","443","SSL Certificate Information","This plugin displays the SSL certificate.","","","",""
"20007","CVE-2021-3156","7.2","High","10.0.2.10","tcp","0","Sudo Heap Overflow","...","","","",""
"12345","","5.0","Medium","unknown-box.corp","tcp","80","Something","...","","","",""
`

const qualysCSV = `"IP","DNS","NetBIOS","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","Date Last Fixed","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS3 Base","Threat"
"10.0.1.20","db01.prod","","Ubuntu","host scanned","38170","SSL Certificate - Signature Verification Failed","Active","Vuln","2","443","tcp","db01.prod.example.com","yes","","","","","","","","","4.3","","","The certificate could not be verified."
"10.0.1.11","","","Ubuntu","host scanned","91234","OpenSSL Multiple Vulnerabilities","Active","Vuln","5","443","tcp","","","","","","","CVE-2022-32221, CVE-2023-0464","","","","9.8","","9.8","..."
`

func TestParseAndMatch(t *testing.T) {
	nf, err := Parse("nessus", strings.NewReader(nessusCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(nf) != 3 { // the "None" risk row is dropped
		t.Fatalf("nessus: %+v", nf)
	}
	if nf[0].Severity != "critical" || nf[0].CVE != "CVE-2014-6271" || nf[0].CVSS != 10 {
		t.Fatalf("nessus row: %+v", nf[0])
	}
	qf, err := Parse("qualys", strings.NewReader(qualysCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(qf) != 2 || qf[0].Host != "db01.prod" || qf[0].Severity != "low" || qf[1].Host != "10.0.1.11" || qf[1].Severity != "critical" || qf[1].CVE != "CVE-2022-32221" {
		t.Fatalf("qualys: %+v", qf)
	}
	if _, err := Parse("nope", strings.NewReader(nessusCSV)); err == nil {
		t.Fatal("unknown format should error")
	}

	hosts := map[string][]string{"db01.prod": {"10.0.1.20"}, "build01.eng": {"10.0.2.10"}, "api01.prod": {"10.0.1.11"}}
	matched, unmatched := Match(append(nf, qf...), hosts)
	if len(matched["db01.prod"]) != 2 || len(matched["build01.eng"]) != 1 || len(matched["api01.prod"]) != 1 {
		t.Fatalf("matched: %+v", matched)
	}
	if len(unmatched) != 1 || len(unmatched["unknown-box.corp"]) != 1 {
		t.Fatalf("unmatched: %+v", unmatched)
	}
	if matched["db01.prod"][0].Severity != "critical" {
		t.Fatal("findings should sort worst first")
	}
	fact := ToFact("nessus", matched["db01.prod"])
	if fact["count"] != 2 || fact["source"] != "nessus" {
		t.Fatalf("fact: %v", fact)
	}
}
