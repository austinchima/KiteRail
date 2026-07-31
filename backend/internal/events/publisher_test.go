package events

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// StartTestServer starts a new in-process NATS JetStream server.
func StartTestServer(t *testing.T) *server.Server {
	opts := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1, // random port
		JetStream: true,
		StoreDir:  t.TempDir(),
	}

	ns, err := server.NewServer(opts)
	require.NoError(t, err)

	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatalf("NATS server failed to start")
	}

	return ns
}

func TestPublisher_And_Subscriber(t *testing.T) {
	ns := StartTestServer(t)
	defer ns.Shutdown()

	clientURL := ns.ClientURL()

	nc, err := nats.Connect(clientURL)
	require.NoError(t, err)
	defer nc.Close()

	_, err = nc.JetStream()
	require.NoError(t, err)

	// Create Publisher and Subscriber
	pub, err := New(context.Background(), clientURL)
	require.NoError(t, err)

	sub, err := NewSubscriber(context.Background(), clientURL)
	require.NoError(t, err)
	
	// Create a channel and subscribe to the internal broadcaster
	ch := sub.Subscribe()
	defer sub.Unsubscribe(ch)

	// Start subscriber loop in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go func() {
		err := sub.Start(ctx)
		if err != nil && err != context.Canceled {
			t.Errorf("Subscriber failed: %v", err)
		}
	}()

	// Wait for subscriber to connect to JetStream (prevent missed messages)
	time.Sleep(500 * time.Millisecond)

	// Publish an event
	testEvent := map[string]interface{}{
		"source": "test_agent",
		"target": "test_tool",
		"status": "allow",
	}

	err = pub.PublishTelemetry(ctx, testEvent)
	require.NoError(t, err)

	// Verify receipt
	select {
	case msg := <-ch:
		assert.Equal(t, "test_agent", msg.Source)
		assert.Equal(t, "test_tool", msg.Target)
		assert.Equal(t, "allow", msg.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for telemetry event")
	}

	// Publish audit event
	testAudit := map[string]interface{}{
		"agent": "audit_agent",
	}
	err = pub.PublishAudit(ctx, testAudit)
	require.NoError(t, err)
	// Audit events shouldn't go to the telemetry channel
	select {
	case <-ch:
		t.Fatal("Received unexpected audit event on telemetry channel")
	case <-time.After(500 * time.Millisecond):
		// Expected timeout
	}
}
