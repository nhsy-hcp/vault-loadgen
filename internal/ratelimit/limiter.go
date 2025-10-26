package ratelimit

import (
	"context"
	"math"

	"golang.org/x/time/rate"
)

// Limiter provides rate limiting for operations
type Limiter struct {
	limiter *rate.Limiter
}

// New creates a new rate limiter
// If opsPerSecond is 0 or negative, no rate limiting is applied
func New(opsPerSecond float64) *Limiter {
	if opsPerSecond <= 0 {
		// No limit - allow infinite rate
		return &Limiter{limiter: rate.NewLimiter(rate.Inf, 0)}
	}

	// Allow burst of 2x the rate to handle bursty workloads
	burst := int(math.Ceil(opsPerSecond * 2))
	if burst < 1 {
		burst = 1
	}

	return &Limiter{
		limiter: rate.NewLimiter(rate.Limit(opsPerSecond), burst),
	}
}

// Wait blocks until the rate limiter permits another operation
// Returns an error if the context is canceled
func (l *Limiter) Wait(ctx context.Context) error {
	return l.limiter.Wait(ctx)
}

// Allow reports whether an operation can proceed without waiting
func (l *Limiter) Allow() bool {
	return l.limiter.Allow()
}
