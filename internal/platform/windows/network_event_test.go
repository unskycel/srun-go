package windows

import (
	"context"
	"testing"
	"time"
)

func TestListenNetworkChange_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := ListenNetworkChange(ctx)

	if ch == nil {
		t.Fatalf("expected non-nil channel")
	}

	// Cancel context to test graceful shutdown
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			// Might receive one pending event, next read should close
			<-ch
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected channel to close after context cancellation")
	}
}

