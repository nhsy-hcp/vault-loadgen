package shutdown

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestHandler_Context(t *testing.T) {
	h := NewHandler()

	// Context should not be cancelled initially
	select {
	case <-h.Context().Done():
		t.Error("Context should not be cancelled initially")
	default:
		// Expected
	}
}

func TestHandler_Shutdown(t *testing.T) {
	h := NewHandler()

	// Call Shutdown
	h.Shutdown()

	// Context should be cancelled
	select {
	case <-h.Context().Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after Shutdown")
	}
}

func TestHandler_MultipleShutdown(t *testing.T) {
	h := NewHandler()

	// Multiple calls to Shutdown should not panic
	h.Shutdown()
	h.Shutdown()
	h.Shutdown()

	// Context should still be cancelled
	select {
	case <-h.Context().Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after multiple Shutdowns")
	}
}

func TestHandler_Signal_SIGINT(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping signal test in short mode")
	}

	h := NewHandler()

	// Start listening
	h.Start()

	// Give it a moment to set up signal handler
	time.Sleep(50 * time.Millisecond)

	// Send SIGINT to ourselves
	go func() {
		time.Sleep(50 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGINT)
	}()

	// Wait for context to be cancelled
	select {
	case <-h.Context().Done():
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Context should be cancelled after SIGINT")
	}

	// Clean up
	h.Stop()
}

func TestHandler_Signal_SIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping signal test in short mode")
	}

	h := NewHandler()

	// Start listening
	h.Start()

	// Give it a moment to set up signal handler
	time.Sleep(50 * time.Millisecond)

	// Send SIGTERM to ourselves
	go func() {
		time.Sleep(50 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGTERM)
	}()

	// Wait for context to be cancelled
	select {
	case <-h.Context().Done():
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Context should be cancelled after SIGTERM")
	}

	// Clean up
	h.Stop()
}

func TestHandler_ContextPropagation(t *testing.T) {
	h := NewHandler()

	// Create a child context
	ctx := h.Context()

	done := make(chan bool)

	// Simulate work that respects context
	go func() {
		select {
		case <-ctx.Done():
			done <- true
		case <-time.After(1 * time.Second):
			done <- false
		}
	}()

	// Trigger shutdown
	time.Sleep(50 * time.Millisecond)
	h.Shutdown()

	// Wait for goroutine
	result := <-done
	if !result {
		t.Error("Child goroutine should have been cancelled")
	}
}

func TestHandler_Wait(t *testing.T) {
	h := NewHandler()

	done := make(chan bool)

	// Goroutine that waits
	go func() {
		h.Wait()
		done <- true
	}()

	// Shutdown after a delay
	time.Sleep(100 * time.Millisecond)
	h.Shutdown()

	// Wait should return
	select {
	case <-done:
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Wait should return after Shutdown")
	}
}
