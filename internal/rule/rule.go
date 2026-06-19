// Package rule defines the neutral detection-as-code rule model.
//
// A rule is authored once in a target-agnostic format and then compiled to
// one or more SIEM dialects. The model is deliberately small: identifying
// metadata, a log source, a severity, and a boolean condition tree built from
// field selectors.
package rule

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Operator enumerates the comparison operators a selector may use.
type Operator string

const (
	OpEquals   Operator = "equals"
	OpContains Operator = "contains"
	OpIn       Operator = "in"
	OpRegex    Operator = "regex"
)

// validOperators is the closed set of operators the condition model accepts.
var validOperators = map[Operator]bool{
	OpEquals:   true,
	OpContains: true,
	OpIn:       true,
	OpRegex:    true,
}

// Boolean combinators for a Condition node.
const (
	combAND = "and"
	combOR  = "or"
)

// Severity levels, ordered from least to most urgent.
var validSeverities = map[string]bool{
	"informational": true,
	"low":           true,
	"medium":        true,
	"high":          true,
	"critical":      true,
}

// Selector is a single field test, e.g. EventID equals 4625.
type Selector struct {
	Field    string   `json:"field"`
	Operator Operator `json:"operator"`
	// Value holds the comparison operand for equals/contains/regex.
	Value string `json:"value,omitempty"`
	// Values holds the operand list for the "in" operator.
	Values []string `json:"values,omitempty"`
}

// Condition is a node in the boolean tree. It is either a leaf (Selector set)
// or an internal node combining child conditions with AND/OR. Exactly one of
// the two forms is populated.
type Condition struct {
	// And / Or hold child conditions. Only one may be non-empty.
	And []Condition `json:"and,omitempty"`
	Or  []Condition `json:"or,omitempty"`
	// Selector is set when this node is a leaf.
	Selector *Selector `json:"selector,omitempty"`
}

// IsLeaf reports whether the condition is a single selector test.
func (c Condition) IsLeaf() bool { return c.Selector != nil }

// Combinator returns "and" or "or" for an internal node, or "" for a leaf.
func (c Condition) Combinator() string {
	switch {
	case len(c.And) > 0:
		return combAND
	case len(c.Or) > 0:
		return combOR
	default:
		return ""
	}
}

// Children returns the child conditions of an internal node.
func (c Condition) Children() []Condition {
	if len(c.And) > 0 {
		return c.And
	}
	return c.Or
}

// LogSource scopes a rule to a category of telemetry.
type LogSource struct {
	Category string `json:"category,omitempty"`
	Product  string `json:"product,omitempty"`
	Service  string `json:"service,omitempty"`
}

// Rule is the top-level authored detection.
type Rule struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Author      string    `json:"author,omitempty"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags,omitempty"`
	LogSource   LogSource `json:"logsource"`
	Condition   Condition `json:"condition"`
}

// Parse decodes a rule from JSON bytes. Unknown fields are rejected so that
// typos in authored rules surface as errors rather than silent drops.
func Parse(data []byte) (*Rule, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var r Rule
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	return &r, nil
}

// LeafSelectors returns every selector in the condition tree, in
// deterministic depth-first order. Useful for coverage reporting.
func (r *Rule) LeafSelectors() []Selector {
	var out []Selector
	var walk func(c Condition)
	walk = func(c Condition) {
		if c.IsLeaf() {
			out = append(out, *c.Selector)
			return
		}
		for _, ch := range c.Children() {
			walk(ch)
		}
	}
	walk(r.Condition)
	return out
}

// Fields returns the sorted, de-duplicated set of field names referenced by
// the rule's condition.
func (r *Rule) Fields() []string {
	seen := map[string]bool{}
	for _, s := range r.LeafSelectors() {
		if s.Field != "" {
			seen[s.Field] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
