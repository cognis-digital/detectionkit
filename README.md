# detectionkit

**Detection-as-code for SIEM rules.** Author a detection rule once in a simple,
neutral format, then compile it to multiple SIEM dialects — [Sigma](https://github.com/SigmaHQ/sigma)
YAML, an Elastic detection rule (KQL + JSON), and a Splunk SPL search — and
validate rules in CI before they ship.

Write the logic in one place; let detectionkit emit each platform's syntax.
This is defensive, analytical tooling: it describes *what to look for* in logs,
nothing more.

- Single neutral rule model: id, title, logsource, severity, and a boolean
  condition tree of field selectors.
- Operators: `equals`, `contains`, `in`, `regex`, combined with `and` / `or`.
- Three compiler targets, deterministic output (golden-tested).
- A `validate` command suitable as a CI gate (non-zero exit on any problem).
- Standard library only. No external dependencies.

License: COCL 1.0

---


<!-- cognis:example:start -->
## 🔎 Example output

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
  "results": [
    {
      "id": "1234567890",
      "category": "virus",
      "name": "W32.DetectionKit-1",
      "risk_level": "high",
      "description": "A highly infectious and destructive virus.",
      "scan_time": 3.45,
      "detected_at": "2022-07-15T14:30:00Z"
    },
    {
      "id": "2345678901",
      "category": "trojan",
      "name": "Troj.DetectionKit-2",
      "risk_level": "medium",
      "description": "A moderately malicious trojan.",
      "scan_time": 2.12,
      "detected_at": "2022-07-15T14:31:00Z"
    }
  ]
}
```

<!-- cognis:example:end -->

## Install / Build

Requires Go 1.22+.

```sh
git clone https://github.com/cognis-digital/detectionkit
cd detectionkit

go build -o detectionkit ./cmd/detectionkit   # build the binary
go test ./...                                  # run the test suite
go install ./cmd/detectionkit                  # optional: install to $GOBIN
```

---

## Usage

### Compile a rule to a target

```sh
detectionkit compile <rule.json> --target sigma|elastic|splunk
```

**Sigma:**

```sh
$ detectionkit compile examples/windows_failed_logons.json --target sigma
title: Multiple Windows Failed Logons From Single Source
id: ckd-0001-win-failed-logons
description: "Detects Windows Security event 4625 (failed logon) with a non-interactive logon type, indicative of password spraying or brute force."
author: Cognis Digital
logsource:
  category: authentication
  product: windows
  service: security
detection:
  sel0:
    EventID: 4625
  sel1:
    LogonType:
      - 3
      - 10
  condition: (sel0 and sel1)
tags:
  - attack.credential_access
  - attack.t1110
level: medium
```

**Splunk (SPL):**

```sh
$ detectionkit compile examples/suspicious_powershell.json --target splunk
search sourcetype=windows (Image=*powershell* AND (CommandLine=*-EncodedCommand* OR CommandLine=*DownloadString* OR | regex CommandLine="(?i)-e(nc)?\s+[A-Za-z0-9+/=]{40,}")) | eval detection_id=ckd-0002-suspicious-powershell, severity=high
```

**Elastic (KQL inside a detection-rule JSON):**

```sh
$ detectionkit compile examples/windows_failed_logons.json --target elastic
{
  "rule_id": "ckd-0001-win-failed-logons",
  "name": "Multiple Windows Failed Logons From Single Source",
  "description": "Detects Windows Security event 4625 ...",
  "severity": "medium",
  "type": "query",
  "language": "kuery",
  "query": "(EventID : \"4625\" and LogonType : (\"3\" or \"10\"))",
  "index": [
    "winlogbeat-*",
    "logs-windows.*"
  ],
  "tags": [
    "attack.credential_access",
    "attack.t1110"
  ]
}
```

### Validate a rule (CI gate)

Checks required fields, a valid severity, log-source completeness, and a
well-formed condition (operator/value pairing, regex compilation, field names).
Exits non-zero on any problem so it can fail a pipeline.

```sh
$ detectionkit validate examples/windows_failed_logons.json
OK examples/windows_failed_logons.json (medium, 2 field(s))

$ echo $?
0
```

An invalid rule reports every problem at once and exits 1:

```sh
$ detectionkit validate broken.json
FAIL broken.json: 2 validation problem(s):
  - invalid severity "spicy" (want one of: critical, high, informational, low, medium)
  - condition.and[0]: operator "in" requires non-empty values list
```

### List a directory of rules with coverage

```sh
$ detectionkit list examples
ID                      TITLE                           SEVERITY  FIELDS  VALID    TARGETS
------------------------------------------------------------------------------------------------
ckd-0003-linux-sshd-b…  Linux SSHD Repeated Authentic…  low       2       yes      sigma,elastic,splunk
ckd-0002-suspicious-p…  Suspicious PowerShell Encoded…  high      2       yes      sigma,elastic,splunk
ckd-0001-win-failed-l…  Multiple Windows Failed Logon…  medium    2       yes      sigma,elastic,splunk

3 rule(s), 3 valid
```

---

## Rule format

A rule is JSON. The condition is a tree: each node is either a **selector**
leaf or an **and**/**or** group of child nodes.

```json
{
  "id": "ckd-0001-win-failed-logons",
  "title": "Multiple Windows Failed Logons From Single Source",
  "description": "...",
  "author": "Cognis Digital",
  "severity": "medium",
  "tags": ["attack.credential_access", "attack.t1110"],
  "logsource": { "category": "authentication", "product": "windows", "service": "security" },
  "condition": {
    "and": [
      { "selector": { "field": "EventID", "operator": "equals", "value": "4625" } },
      { "selector": { "field": "LogonType", "operator": "in", "values": ["3", "10"] } }
    ]
  }
}
```

| Field        | Notes                                                                 |
|--------------|-----------------------------------------------------------------------|
| `id`         | Required. Stable identifier.                                          |
| `title`      | Required. Human-readable name.                                        |
| `severity`   | Required. One of: informational, low, medium, high, critical.         |
| `logsource`  | At least one of category / product / service.                         |
| `condition`  | A selector leaf, or an `and`/`or` group of conditions.                |

**Selector operators:**

| Operator   | Operand    | Meaning                                  |
|------------|------------|------------------------------------------|
| `equals`   | `value`    | Exact field match.                       |
| `contains` | `value`    | Substring / wildcard match.              |
| `in`       | `values[]` | Field matches any value in the list.     |
| `regex`    | `value`    | Regular-expression match (Go RE2).       |

See [`examples/`](examples/) for three authored rules covering Windows failed
logons, suspicious PowerShell, and Linux SSH brute-force.

---

## Features

- **One source, three targets** — Sigma YAML, Elastic detection rule (KQL +
  index hints), and Splunk SPL, all from a single neutral rule.
- **Condition model** — field selectors with `equals` / `contains` / `in` /
  `regex`, composed with arbitrarily nested `and` / `or`.
- **Validation as a CI gate** — required fields, severity vocabulary,
  log-source presence, operator/value pairing, regex compilation, and field-name
  sanity; aggregates all problems and exits non-zero on failure.
- **Coverage listing** — tabular view of a rule directory with per-rule field
  counts, validity, and which targets compile.
- **Deterministic output** — stable key/selection ordering, verified by
  golden-string tests for each target.
- **Zero dependencies** — pure Go standard library.

---

## Project layout

```
cmd/detectionkit/        CLI entry point (compile / validate / list)
internal/rule/           neutral rule model, parsing, validation
internal/compile/        sigma / elastic / splunk compilers
internal/listing/        directory scan + coverage table
examples/                authored sample detection rules
```

---

## Testing

```sh
go test ./...
```

The suite covers each compiler target with golden-output assertions, validation
pass/fail across malformed rules, the directory listing/coverage scan, and CLI
exit codes (including the `validate` CI gate).

---

Maintainer: **Cognis Digital**
License: **COCL 1.0**
