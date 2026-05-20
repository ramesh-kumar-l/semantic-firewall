package scoring

// scoringRule is reserved for future rule-based scoring extensions.
// V1 uses severity weights from findings only; rules structure is defined
// here to support declarative rule loading in Phase 2.
type scoringRule struct {
	Name   string
	Weight float64
}

// defaultRules are unused in V1 but define the extension point.
var defaultRules = []scoringRule{
	{Name: "critical_finding_present", Weight: 0.9},
	{Name: "high_finding_present", Weight: 0.7},
	{Name: "medium_finding_present", Weight: 0.4},
	{Name: "low_finding_present", Weight: 0.2},
}
