package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/ramesh152/semantic-firewall/pkg/types"
)

// Logger writes immutable audit records.
type Logger interface {
	Write(ctx context.Context, record types.AuditRecord) error
	Close() error
}

// JSONLLogger is an append-only JSON-L audit logger.
type JSONLLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewJSONLLogger opens (or creates) the audit log file for append-only writing.
func NewJSONLLogger(path string) (*JSONLLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return &JSONLLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Write appends a single audit record as a JSON line.
// It is safe for concurrent use.
func (l *JSONLLogger) Write(_ context.Context, record types.AuditRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.enc.Encode(record); err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	// Flush to OS after every write — each record must be durable before returning.
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}

func (l *JSONLLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
