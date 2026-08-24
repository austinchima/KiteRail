package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type TelemetryEvent struct {
	Source    string    `json:"source"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type Subscriber struct {
	nc *nats.Conn
	js jetstream.JetStream

	mu       sync.Mutex
	channels map[chan TelemetryEvent]struct{}
}

func NewSubscriber(ctx context.Context, url string) (*Subscriber, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nats: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to create jetstream: %w", err)
	}

	sub := &Subscriber{
		nc:       nc,
		js:       js,
		channels: make(map[chan TelemetryEvent]struct{}),
	}

	return sub, nil
}

func (s *Subscriber) Start(ctx context.Context) error {
	cons, err := s.js.CreateOrUpdateConsumer(ctx, "KITERAIL_TELEMETRY", jetstream.ConsumerConfig{
		// Use empty name for ephemeral consumer so it automatically cleans up
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
	if err != nil {
		return fmt.Errorf("failed to create consumer: %w", err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		var event TelemetryEvent
		if err := json.Unmarshal(msg.Data(), &event); err != nil {
			msg.Nak()
			return
		}
		msg.Ack()
		s.broadcast(event)
	})
	if err != nil {
		return fmt.Errorf("failed to consume: %w", err)
	}

	go func() {
		<-ctx.Done()
		cc.Stop()
	}()

	return nil
}

func (s *Subscriber) broadcast(event TelemetryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.channels {
		select {
		case ch <- event:
		default:
			// If channel is full, drop event to prevent blocking
		}
	}
}

func (s *Subscriber) Subscribe() chan TelemetryEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan TelemetryEvent, 100)
	s.channels[ch] = struct{}{}
	return ch
}

func (s *Subscriber) Unsubscribe(ch chan TelemetryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.channels[ch]; ok {
		delete(s.channels, ch)
		close(ch)
	}
}

func (s *Subscriber) Close() error {
	return s.nc.Drain()
}
