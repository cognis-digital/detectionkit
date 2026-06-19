package rule

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ValidationError aggregates all problems found in a rule so a CI gate can
// report everything at once rather than failing on the first issue.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%d validation problem(s):\n  - %s",
		len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

// fieldNameRe restricts field names to identifiers that compile cleanly to all
// targets (dotted paths are allowed, e.g. "winlog.event_id").
var fieldNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// Validate checks required fields, severity, and condition well-formedness.
// It returns a *ValidationError when any problem is found, else nil.
func (r *Rule) Validate() error {
	var probs []string
	add := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }

	if strings.TrimSpace(r.ID) == "" {
		add("missing required field: id")
	}
	if strings.TrimSpace(r.Title) == "" {
		add("missing required field: title")
	}
	if strings.TrimSpace(r.Severity) == "" {
		add("missing required field: severity")
	} else if !validSeverities[strings.ToLower(r.Severity)] {
		add("invalid severity %q (want one of: %s)", r.Severity, severityList())
	}
	if r.LogSource.Category == "" && r.LogSource.Product == "" && r.LogSource.Service == "" {
		add("logsource must set at least one of category/product/service")
	}

	validateCondition(r.Condition, "condition", add)

	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// validateCondition recursively checks a condition node.
func validateCondition(c Condition, path string, add func(string, ...any)) {
	hasAnd := len(c.And) > 0
	hasOr := len(c.Or) > 0
	hasLeaf := c.Selector != nil

	set := 0
	if hasAnd {
		set++
	}
	if hasOr {
		set++
	}
	if hasLeaf {
		set++
	}

	switch set {
	case 0:
		add("%s: empty condition node (must be a selector or and/or group)", path)
		return
	case 1:
		// well-formed shape
	default:
		add("%s: condition node sets more than one of selector/and/or", path)
		return
	}

	if hasLeaf {
		validateSelector(*c.Selector, path, add)
		return
	}

	comb := combAND
	children := c.And
	if hasOr {
		comb = combOR
		children = c.Or
	}
	for i, ch := range children {
		validateCondition(ch, fmt.Sprintf("%s.%s[%d]", path, comb, i), add)
	}
}

// validateSelector checks a single leaf selector.
func validateSelector(s Selector, path string, add func(string, ...any)) {
	if strings.TrimSpace(s.Field) == "" {
		add("%s: selector missing field", path)
	} else if !fieldNameRe.MatchString(s.Field) {
		add("%s: invalid field name %q", path, s.Field)
	}

	if !validOperators[s.Operator] {
		add("%s: invalid operator %q (want one of: equals, contains, in, regex)", path, s.Operator)
	}

	switch s.Operator {
	case OpIn:
		if len(s.Values) == 0 {
			add("%s: operator 'in' requires non-empty values list", path)
		}
		if s.Value != "" {
			add("%s: operator 'in' uses values, not value", path)
		}
	case OpEquals, OpContains, OpRegex:
		if s.Value == "" {
			add("%s: operator %q requires a value", path, s.Operator)
		}
		if len(s.Values) > 0 {
			add("%s: operator %q uses value, not values", path, s.Operator)
		}
		if s.Operator == OpRegex {
			if _, err := regexp.Compile(s.Value); err != nil {
				add("%s: invalid regex %q: %v", path, s.Value, err)
			}
		}
	}
}

func severityList() string {
	out := make([]string, 0, len(validSeverities))
	for s := range validSeverities {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
