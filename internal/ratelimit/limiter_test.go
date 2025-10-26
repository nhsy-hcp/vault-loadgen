package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		opsPerSecond  float64
		expectUnlimit bool
	}{
		{
			name:          "zero rate - unlimited",
			opsPerSecond:  0,
			expectUnlimit: true,
		},
		{
			name:          "negative rate - unlimited",
			opsPerSecond:  -1,
			expectUnlimit: true,
		},
		{
			name:          "positive rate - limited",
			opsPerSecond:  100,
			expectUnlimit: false,
		},
		{
			name:          "fractional rate - limited",
			opsPerSecond:  0.5,
			expectUnlimit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := New(tt.opsPerSecond)
			if limiter == nil {
				t.Fatal("expected limiter, got nil")
			}

			// For unlimited rate, Allow should always return true
			if tt.expectUnlimit {
				for i := 0; i < 100; i++ {
					if !limiter.Allow() {
						t.Errorf("expected unlimited rate limiter to allow all operations")
					}
				}
			}
		})
	}
}

func TestLimiter_Wait(t *testing.T) {
	tests := []struct {
		name         string
		opsPerSecond float64
		operations   int
		expectDelay  bool
	}{
		{
			name:         "unlimited - no delay",
			opsPerSecond: 0,
			operations:   100,
			expectDelay:  false,
		},
		{
			name:         "limited - with delay",
			opsPerSecond: 10,
			operations:   25, // Exceeds burst (2x rate = 20)
			expectDelay:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := New(tt.opsPerSecond)
			ctx := context.Background()

			start := time.Now()
			for i := 0; i < tt.operations; i++ {
				if err := limiter.Wait(ctx); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			duration := time.Since(start)

			if tt.expectDelay {
				// With rate limiting, should take at least some time
				if duration < 100*time.Millisecond {
					t.Errorf("expected delay for rate-limited operations, got %v", duration)
				}
			} else {
				// Without rate limiting, should be nearly instant
				if duration > 100*time.Millisecond {
					t.Errorf("expected no delay for unlimited operations, got %v", duration)
				}
			}
		})
	}
}

func TestLimiter_Wait_ContextCanceled(t *testing.T) {
	limiter := New(1) // 1 op per second
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	err := limiter.Wait(ctx)
	if err == nil {
		t.Error("expected error when context is canceled, got nil")
	}

	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestLimiter_Allow(t *testing.T) {
	limiter := New(100) // 100 ops per second

	ctx := context.Background()

	// First operation should be allowed
	if !limiter.Allow() {
		t.Error("expected first operation to be allowed")
	}

	// After waiting, should allow again
	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be allowed after wait
	if !limiter.Allow() {
		t.Error("expected operation to be allowed after wait")
	}
}

func TestLimiter_Burst(t *testing.T) {
	// Create limiter with rate of 10 ops/sec
	// Burst should be 2x = 20
	limiter := New(10)

	// Should allow burst of operations without delay
	for i := 0; i < 10; i++ {
		if !limiter.Allow() {
			t.Errorf("expected burst operation %d to be allowed", i)
		}
	}
}
