package detection

import (
	"encoding/json"
	"strings"
)

// ExtractToolCallText extracts all string values from raw tool call JSON objects.
// The result is suitable for passing to Detect() for injection pattern matching.
func ExtractToolCallText(toolCalls []json.RawMessage) string {
	var parts []string
	for _, raw := range toolCalls {
		var obj any
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		extractStrings(obj, &parts)
	}
	return strings.Join(parts, " ")
}

func extractStrings(v any, out *[]string) {
	switch val := v.(type) {
	case string:
		if val != "" {
			*out = append(*out, val)
		}
	case map[string]any:
		for _, child := range val {
			extractStrings(child, out)
		}
	case []any:
		for _, child := range val {
			extractStrings(child, out)
		}
	}
}
