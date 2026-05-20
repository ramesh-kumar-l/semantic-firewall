package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// Webhooker delivers alert payloads to an HTTP endpoint.
type Webhooker struct {
	url    string
	client *http.Client
}

// New creates a Webhooker that POSTs to url with the given timeout.
func New(url string, timeoutMs int) *Webhooker {
	return &Webhooker{
		url: url,
		client: &http.Client{
			Timeout: time.Duration(timeoutMs) * time.Millisecond,
		},
	}
}

// Send fires an async HTTP POST with payload serialized as JSON.
// Errors are logged but not surfaced to the caller.
func (w *Webhooker) Send(payload any) {
	go w.post(payload)
}

func (w *Webhooker) post(payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("alert.webhook.marshal.error", "error", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		slog.Error("alert.webhook.request.error", "error", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		slog.Error("alert.webhook.send.error", "url", w.url, "error", err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		slog.Warn("alert.webhook.bad.response", "url", w.url, "status", resp.StatusCode)
	}
}
