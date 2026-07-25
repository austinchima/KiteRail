package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Publisher represents a NATS JetStream event publisher.
type Publisher struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// New creates a new Publisher.
func New(ctx context.Context, url string) (*Publisher, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nats: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create jetstream: %w", err)
	}

	// Ensure streams exist
	streams := []struct {
		Name     string
		Subjects []string
	}{
		{"KITERAIL_QUARANTINE", []string{"kiterail.quarantine.>"}},
		{"KITERAIL_AUDIT", []string{"kiterail.audit.>"}},
		{"KITERAIL_TELEMETRY", []string{"kiterail.telemetry.>"}},
	}

	for _, s := range streams {
		_, err := js.CreateStream(ctx, jetstream.StreamConfig{
			Name:     s.Name,
			Subjects: s.Subjects,
		})
		if err != nil && err != jetstream.ErrStreamNameAlreadyInUse {
			nc.Close()
			return nil, fmt.Errorf("failed to create stream %s: %w", s.Name, err)
		}
	}

	return &Publisher{nc: nc, js: js}, nil
}

func (p *Publisher) publish(ctx context.Context, subject string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	_, err = p.js.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish: %w", err)
	}
	return nil
}

// PublishQuarantine publishes a quarantine event.
func (p *Publisher) PublishQuarantine(ctx context.Context, event interface{}) error {
	return p.publish(ctx, "kiterail.quarantine.new", event)
}

// PublishAudit publishes an audit event.
func (p *Publisher) PublishAudit(ctx context.Context, event interface{}) error {
	return p.publish(ctx, "kiterail.audit.log", event)
}

// PublishTelemetry publishes a telemetry event.
func (p *Publisher) PublishTelemetry(ctx context.Context, event interface{}) error {
	return p.publish(ctx, "kiterail.telemetry.metrics", event)
}

// Close closes the NATS connection.
func (p *Publisher) Close() error {
	return p.nc.Drain()
}
