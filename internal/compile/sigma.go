package compile

import (
	"fmt"
	"strings"

	"github.com/cognis-digital/detectionkit/internal/rule"
)

// Sigma renders the rule as a Sigma YAML document.
//
// The detection block is built by flattening every leaf selector into a
// uniquely named selection entry, then expressing the boolean tree as a Sigma
// condition string referencing those selections.
func Sigma(r *rule.Rule) (string, error) {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("title: %s\n", yamlScalar(r.Title)))
	b.WriteString(fmt.Sprintf("id: %s\n", yamlScalar(r.ID)))
	if r.Description != "" {
		b.WriteString(fmt.Sprintf("description: %s\n", yamlScalar(r.Description)))
	}
	if r.Author != "" {
		b.WriteString(fmt.Sprintf("author: %s\n", yamlScalar(r.Author)))
	}
	b.WriteString("logsource:\n")
	if r.LogSource.Category != "" {
		b.WriteString(fmt.Sprintf("  category: %s\n", yamlScalar(r.LogSource.Category)))
	}
	if r.LogSource.Product != "" {
		b.WriteString(fmt.Sprintf("  product: %s\n", yamlScalar(r.LogSource.Product)))
	}
	if r.LogSource.Service != "" {
		b.WriteString(fmt.Sprintf("  service: %s\n", yamlScalar(r.LogSource.Service)))
	}

	// Flatten leaves to numbered selections.
	leaves := r.LeafSelectors()
	names := make([]string, len(leaves))
	for i := range leaves {
		names[i] = fmt.Sprintf("sel%d", i)
	}

	b.WriteString("detection:\n")
	idx := 0
	emitSelections(&b, r.Condition, names, &idx)

	condStr := sigmaCondition(r.Condition, names, new(int))
	b.WriteString(fmt.Sprintf("  condition: %s\n", condStr))

	if len(r.Tags) > 0 {
		b.WriteString("tags:\n")
		for _, t := range r.Tags {
			b.WriteString(fmt.Sprintf("  - %s\n", yamlScalar(t)))
		}
	}
	b.WriteString(fmt.Sprintf("level: %s\n", strings.ToLower(r.Severity)))

	return b.String(), nil
}

// emitSelections walks the tree in the same order as sigmaCondition and writes
// one selection block per leaf.
func emitSelections(b *strings.Builder, c rule.Condition, names []string, idx *int) {
	if c.IsLeaf() {
		name := names[*idx]
		*idx++
		b.WriteString(fmt.Sprintf("  %s:\n", name))
		writeSigmaSelector(b, *c.Selector)
		return
	}
	for _, ch := range c.Children() {
		emitSelections(b, ch, names, idx)
	}
}

// writeSigmaSelector renders a single selector as a Sigma field mapping using
// the field|modifier: value form.
func writeSigmaSelector(b *strings.Builder, s rule.Selector) {
	switch s.Operator {
	case rule.OpEquals:
		b.WriteString(fmt.Sprintf("    %s: %s\n", s.Field, yamlScalar(s.Value)))
	case rule.OpContains:
		b.WriteString(fmt.Sprintf("    %s|contains: %s\n", s.Field, yamlScalar(s.Value)))
	case rule.OpRegex:
		b.WriteString(fmt.Sprintf("    %s|re: %s\n", s.Field, yamlScalar(s.Value)))
	case rule.OpIn:
		b.WriteString(fmt.Sprintf("    %s:\n", s.Field))
		for _, v := range s.Values {
			b.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(v)))
		}
	}
}

// sigmaCondition produces the Sigma condition expression for the tree.
func sigmaCondition(c rule.Condition, names []string, idx *int) string {
	if c.IsLeaf() {
		n := names[*idx]
		*idx++
		return n
	}
	joiner := " and "
	if c.Combinator() == "or" {
		joiner = " or "
	}
	parts := make([]string, 0, len(c.Children()))
	for _, ch := range c.Children() {
		parts = append(parts, sigmaCondition(ch, names, idx))
	}
	expr := strings.Join(parts, joiner)
	if len(parts) > 1 {
		return "(" + expr + ")"
	}
	return expr
}

// yamlScalar quotes a scalar value for YAML when needed.
func yamlScalar(s string) string {
	if s == "" {
		return `""`
	}
	if needsYAMLQuote(s) {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	return s
}

func needsYAMLQuote(s string) bool {
	if strings.ContainsAny(s, ":#{}[],&*!|>'\"%@`") {
		return true
	}
	if strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return true
	}
	// Reserved bare words that YAML would coerce to non-strings.
	switch strings.ToLower(s) {
	case "true", "false", "null", "yes", "no", "on", "off", "~":
		return true
	}
	return false
}
