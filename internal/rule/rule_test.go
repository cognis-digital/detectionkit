package rule

import "testing"

const sampleRule = `{
  "id": "ckd-test-001",
  "title": "Test Rule",
  "severity": "high",
  "logsource": { "product": "windows" },
  "condition": {
    "and": [
      { "selector": { "field": "EventID", "operator": "equals", "value": "4625" } },
      { "selector": { "field": "LogonType", "operator": "in", "values": ["3", "10"] } }
    ]
  }
}`

func TestParseValidRule(t *testing.T) {
	r, err := Parse([]byte(sampleRule))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.ID != "ckd-test-001" {
		t.Errorf("id = %q", r.ID)
	}
	if got := len(r.LeafSelectors()); got != 2 {
		t.Errorf("leaf selectors = %d, want 2", got)
	}
	fields := r.Fields()
	if len(fields) != 2 || fields[0] != "EventID" || fields[1] != "LogonType" {
		t.Errorf("fields = %v, want sorted [EventID LogonType]", fields)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	_, err := Parse([]byte(`{"id":"x","title":"t","severity":"low","logsource":{"product":"p"},"bogus":1,"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidatePass(t *testing.T) {
	r, _ := Parse([]byte(sampleRule))
	if err := r.Validate(); err != nil {
		t.Fatalf("validate should pass: %v", err)
	}
}

func TestValidateFailures(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"missing id", `{"title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`},
		{"bad severity", `{"id":"i","title":"t","severity":"spicy","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`},
		{"empty logsource", `{"id":"i","title":"t","severity":"low","logsource":{},"condition":{"selector":{"field":"f","operator":"equals","value":"v"}}}`},
		{"bad operator", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"startswith","value":"v"}}}`},
		{"in without values", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"in"}}}`},
		{"equals without value", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals"}}}`},
		{"bad regex", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"regex","value":"("}}}`},
		{"empty condition", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{}}`},
		{"bad field name", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"3bad name","operator":"equals","value":"v"}}}`},
		{"both selector and and", `{"id":"i","title":"t","severity":"low","logsource":{"product":"p"},"condition":{"selector":{"field":"f","operator":"equals","value":"v"},"and":[{"selector":{"field":"g","operator":"equals","value":"w"}}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse([]byte(tc.json))
			if err != nil {
				// parse failure is itself a rejection; acceptable for this gate
				return
			}
			if err := r.Validate(); err == nil {
				t.Errorf("%s: expected validation error, got nil", tc.name)
			}
		})
	}
}
