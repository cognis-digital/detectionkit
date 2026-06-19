package compile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cognis-digital/detectionkit/internal/rule"
)

// Elastic renders the rule as an Elastic detection rule (JSON), embedding both
// a KQL query string and the structured representation Kibana expects.
//
// The output is a compact-but-readable indented JSON object with stable key
// ordering (driven by an ordered struct), so golden tests are deterministic.
func Elastic(r *rule.Rule) (string, error) {
	doc := elasticDoc{
		RuleID:      r.ID,
		Name:        r.Title,
		Description: r.Description,
		Severity:    elasticSeverity(r.Severity),
		Type:        "query",
		Language:    "kuery",
		Query:       kqlCondition(r.Condition),
		Tags:        r.Tags,
	}
	if r.LogSource.Product != "" || r.LogSource.Category != "" {
		idx := elasticIndex(r.LogSource)
		doc.Index = idx
	}
	if doc.Description == "" {
		doc.Description = r.Title
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal elastic rule: %w", err)
	}
	return string(out), nil
}

// elasticDoc mirrors the subset of the Kibana detection-rule schema we emit.
// Field order here defines JSON key order.
type elasticDoc struct {
	RuleID      string   `json:"rule_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	Language    string   `json:"language"`
	Query       string   `json:"query"`
	Index       []string `json:"index,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// kqlCondition renders a condition node as a KQL (kuery) expression.
func kqlCondition(c rule.Condition) string {
	if c.IsLeaf() {
		return kqlSelector(*c.Selector)
	}
	joiner := " and "
	if c.Combinator() == "or" {
		joiner = " or "
	}
	parts := make([]string, 0, len(c.Children()))
	for _, ch := range c.Children() {
		parts = append(parts, kqlCondition(ch))
	}
	expr := strings.Join(parts, joiner)
	if len(parts) > 1 {
		return "(" + expr + ")"
	}
	return expr
}

// kqlSelector renders one selector as KQL.
func kqlSelector(s rule.Selector) string {
	switch s.Operator {
	case rule.OpEquals:
		return fmt.Sprintf("%s : %s", s.Field, kqlValue(s.Value))
	case rule.OpContains:
		return fmt.Sprintf("%s : %s", s.Field, kqlValue("*"+s.Value+"*"))
	case rule.OpRegex:
		// KQL has no native regex; surface intent via a tagged wildcard match.
		return fmt.Sprintf("%s : %s", s.Field, kqlValue("*"+s.Value+"*"))
	case rule.OpIn:
		quoted := make([]string, len(s.Values))
		for i, v := range s.Values {
			quoted[i] = kqlValue(v)
		}
		return fmt.Sprintf("%s : (%s)", s.Field, strings.Join(quoted, " or "))
	}
	return ""
}

// kqlValue quotes a KQL value. KQL string literals use double quotes.
func kqlValue(v string) string {
	return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
}

// elasticIndex maps a log source to plausible index patterns.
func elasticIndex(ls rule.LogSource) []string {
	switch {
	case ls.Category == "process_creation":
		return []string{"logs-endpoint.events.*"}
	case ls.Product == "windows":
		return []string{"winlogbeat-*", "logs-windows.*"}
	case ls.Product == "linux":
		return []string{"filebeat-*", "logs-linux.*"}
	default:
		return []string{"logs-*"}
	}
}

// elasticSeverity maps neutral severities to Kibana's vocabulary.
func elasticSeverity(s string) string {
	switch strings.ToLower(s) {
	case "informational":
		return "low"
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}
