package caep

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Sink applies a verified event (RevocationCache satisfies it).
type Sink interface{ Apply(Event) }

// Receiver is the PEP-side push endpoint. It verifies each SET and applies it to
// the sink. SSF push delivery uses content-type application/secevent+jwt; here
// the request body is the SET string.
type Receiver struct {
	signer *Signer
	sink   Sink
}

// NewReceiver builds a receiver that verifies with signer and feeds sink.
func NewReceiver(signer *Signer, sink Sink) *Receiver {
	return &Receiver{signer: signer, sink: sink}
}

// Handler ingests one pushed SET.
func (r *Receiver) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		event, err := r.signer.Verify(string(bytes.TrimSpace(body)))
		if err != nil {
			http.Error(w, "invalid SET", http.StatusUnauthorized)
			return
		}
		r.sink.Apply(event)
		w.WriteHeader(http.StatusAccepted)
	}
}

// Transmitter is the Control Plane side: it signs events and pushes them to all
// subscribed PEP receivers.
type Transmitter struct {
	signer      *Signer
	subscribers []string
	client      *http.Client
}

// NewTransmitter builds a transmitter pushing to the given receiver URLs
// (each is a full URL to a Receiver handler, e.g. https://wallet:8082/events).
func NewTransmitter(signer *Signer, subscribers []string) *Transmitter {
	return NewTransmitterWithClient(signer, subscribers, &http.Client{Timeout: 5 * time.Second})
}

// NewTransmitterWithClient is NewTransmitter with a caller-supplied HTTP client —
// used to push over mTLS to receivers that sit behind a PEP (the client presents
// the transmitter's SVID).
func NewTransmitterWithClient(signer *Signer, subscribers []string, client *http.Client) *Transmitter {
	return &Transmitter{signer: signer, subscribers: subscribers, client: client}
}

// Emit signs the event and pushes it to every subscriber. It returns the first
// delivery error (best-effort fan-out otherwise).
func (t *Transmitter) Emit(ctx context.Context, e Event) error {
	set, err := t.signer.Sign(e)
	if err != nil {
		return err
	}
	var firstErr error
	for _, url := range t.subscribers {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(set)))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		req.Header.Set("Content-Type", "application/secevent+jwt")
		resp, err := t.client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted && firstErr == nil {
			firstErr = fmt.Errorf("caep: subscriber %s returned %d", url, resp.StatusCode)
		}
	}
	return firstErr
}
