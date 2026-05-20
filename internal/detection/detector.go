package detection

import (
	"context"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Detector produces findings from a normalized prompt.
type Detector interface {
	Detect(ctx context.Context, prompt string) ([]types.Finding, error)
	Name() string
}
