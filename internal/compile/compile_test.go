package compile

import (
	"testing"

	"github.com/cognis-digital/detectionkit/internal/rule"
)

// goldenRule is a fixed rule used to pin compiler output. It exercises AND/OR
// nesting and all four operators (equals, contains, in, regex).
const goldenRule = `{
  "id": "ckd-gold-001",
  "title": "Golden Test Rule",
  "description": "Fixture for golden output.",
  "author": "Cognis Digital",
  "severity": "high",
  "tags": ["attack.execution"],
  "logsource": { "category": "process_creation", "product": "windows" },
  "condition": {
    "and": [
      { "selector": { "field": "Image", "operator": "contains", "value": "powershell" } },
      {
        "or": [
          { "selector": { "field": "CommandLine", "operator": "equals", "value": "-Enc" } },
          { "selector": { "field": "User", "operator": "in", "values": ["SYSTEM", "admin"] } },
          { "selector": { "field": "Hash", "operator": "regex", "value": "^[a-f0-9]{64}$" } }
        ]
      }
    ]
  }
}`

func mustParse(t *testing.T, s string) *rule.Rule {
	t.Helper()
	r, err := rule.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return r
}

func TestSigmaGolden(t *testing.T) {
	r := mustParse(t, goldenRule)
	got, err := Sigma(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `title: Golden Test Rule
id: ckd-gold-001
description: Fixture for golden output.
author: Cognis Digital
logsource:
  category: process_creation
  product: windows
detection:
  sel0:
    Image|contains: powershell
  sel1:
    CommandLine: -Enc
  sel2:
    User:
      - SYSTEM
      - admin
  sel3:
    Hash|re: "^[a-f0-9]{64}$"
  condition: (sel0 and (sel1 or sel2 or sel3))
tags:
  - attack.execution
level: high
`
	if got != want {
		t.Errorf("sigma mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestSplunkGolden(t *testing.T) {
	r := mustParse(t, goldenRule)
	got, err := Splunk(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `search sourcetype=windows (Image=*powershell* AND (CommandLine=-Enc OR User IN (SYSTEM, admin) OR | regex Hash="^[a-f0-9]{64}$")) | eval detection_id=ckd-gold-001, severity=high`
	if got != want {
		t.Errorf("splunk mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestElasticGolden(t *testing.T) {
	r := mustParse(t, goldenRule)
	got, err := Elastic(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "rule_id": "ckd-gold-001",
  "name": "Golden Test Rule",
  "description": "Fixture for golden output.",
  "severity": "high",
  "type": "query",
  "language": "kuery",
  "query": "(Image : \"*powershell*\" and (CommandLine : \"-Enc\" or User : (\"SYSTEM\" or \"admin\") or Hash : \"*^[a-f0-9]{64}$*\"))",
  "index": [
    "logs-endpoint.events.*"
  ],
  "tags": [
    "attack.execution"
  ]
}`
	if got != want {
		t.Errorf("elastic mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestCompileDispatch(t *testing.T) {
	r := mustParse(t, goldenRule)
	for _, tgt := range Targets {
		if _, err := Compile(r, tgt); err != nil {
			t.Errorf("Compile(%s): %v", tgt, err)
		}
	}
	if _, err := Compile(r, Target("nope")); err == nil {
		t.Error("expected error for unknown target")
	}
}
