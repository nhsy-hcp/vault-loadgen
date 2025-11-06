package stats

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Stats tracks operation statistics for load generation
type Stats struct {
	// Namespace operations
	NamespacesCreated int64
	NamespacesSkipped int64
	NamespacesFailed  int64

	// Lease operations (PKI, AppRole)
	LeasesCreated int64
	LeasesFailed  int64

	// Secret operations (KV)
	SecretsCreated int64
	SecretsFailed  int64

	// Authenticated read operations (AppRole)
	AuthenticatedReadsSucceeded int64
	AuthenticatedReadsFailed    int64

	// Timing
	StartTime time.Time
	EndTime   time.Time
}

// New creates a new Stats instance with current time as start time
func New() *Stats {
	return &Stats{
		StartTime: time.Now(),
	}
}

// IncNamespacesCreated atomically increments the namespaces created counter
func (s *Stats) IncNamespacesCreated() {
	atomic.AddInt64(&s.NamespacesCreated, 1)
}

// IncNamespacesSkipped atomically increments the namespaces skipped counter
func (s *Stats) IncNamespacesSkipped() {
	atomic.AddInt64(&s.NamespacesSkipped, 1)
}

// IncNamespacesFailed atomically increments the namespaces failed counter
func (s *Stats) IncNamespacesFailed() {
	atomic.AddInt64(&s.NamespacesFailed, 1)
}

// IncLeasesCreated atomically increments the leases created counter
func (s *Stats) IncLeasesCreated() {
	atomic.AddInt64(&s.LeasesCreated, 1)
}

// IncLeasesFailed atomically increments the leases failed counter
func (s *Stats) IncLeasesFailed() {
	atomic.AddInt64(&s.LeasesFailed, 1)
}

// IncSecretsCreated atomically increments the secrets created counter
func (s *Stats) IncSecretsCreated() {
	atomic.AddInt64(&s.SecretsCreated, 1)
}

// IncSecretsFailed atomically increments the secrets failed counter
func (s *Stats) IncSecretsFailed() {
	atomic.AddInt64(&s.SecretsFailed, 1)
}

// IncAuthenticatedReadsSucceeded atomically increments the authenticated reads succeeded counter
func (s *Stats) IncAuthenticatedReadsSucceeded() {
	atomic.AddInt64(&s.AuthenticatedReadsSucceeded, 1)
}

// IncAuthenticatedReadsFailed atomically increments the authenticated reads failed counter
func (s *Stats) IncAuthenticatedReadsFailed() {
	atomic.AddInt64(&s.AuthenticatedReadsFailed, 1)
}

// End marks the end time for statistics
func (s *Stats) End() {
	s.EndTime = time.Now()
}

// Duration returns the duration of the load generation
func (s *Stats) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// TotalOperations returns the total number of operations performed
func (s *Stats) TotalOperations() int {
	return int(s.NamespacesCreated + s.NamespacesSkipped + s.NamespacesFailed +
		s.LeasesCreated + s.LeasesFailed +
		s.SecretsCreated + s.SecretsFailed +
		s.AuthenticatedReadsSucceeded + s.AuthenticatedReadsFailed)
}

// OpsPerSecond calculates operations per second
func (s *Stats) OpsPerSecond() float64 {
	duration := s.Duration()
	if duration == 0 {
		return 0
	}
	return float64(s.TotalOperations()) / duration.Seconds()
}

// LeasesPerSecond calculates leases created per second
func (s *Stats) LeasesPerSecond() float64 {
	duration := s.Duration()
	if duration == 0 {
		return 0
	}
	return float64(s.LeasesCreated) / duration.Seconds()
}

// SecretsPerSecond calculates secrets created per second
func (s *Stats) SecretsPerSecond() float64 {
	duration := s.Duration()
	if duration == 0 {
		return 0
	}
	return float64(s.SecretsCreated) / duration.Seconds()
}

// AuthenticatedReadsPerSecond calculates authenticated reads per second
func (s *Stats) AuthenticatedReadsPerSecond() float64 {
	duration := s.Duration()
	if duration == 0 {
		return 0
	}
	return float64(s.AuthenticatedReadsSucceeded) / duration.Seconds()
}

// SuccessRate calculates the success rate as a percentage
func (s *Stats) SuccessRate() float64 {
	total := s.TotalOperations()
	if total == 0 {
		return 0
	}
	successful := s.NamespacesCreated + s.LeasesCreated + s.SecretsCreated + s.AuthenticatedReadsSucceeded
	return float64(successful) / float64(total) * 100
}

// PrintSummary prints a formatted summary of the statistics
func (s *Stats) PrintSummary(mode string) {
	separator := repeatString("=", 60)

	fmt.Println("\n" + separator)
	fmt.Println("Load Generation Summary")
	fmt.Println(separator)
	fmt.Printf("Mode: %s\n", mode)
	fmt.Printf("Duration: %s\n", s.Duration().Round(time.Millisecond))
	fmt.Println()

	// Namespace stats
	if s.NamespacesCreated > 0 || s.NamespacesSkipped > 0 || s.NamespacesFailed > 0 {
		fmt.Println("Namespaces:")
		fmt.Printf("  Created: %d\n", s.NamespacesCreated)
		fmt.Printf("  Skipped: %d\n", s.NamespacesSkipped)
		fmt.Printf("  Failed:  %d\n", s.NamespacesFailed)
		fmt.Println()
	}

	// Lease stats
	if s.LeasesCreated > 0 || s.LeasesFailed > 0 {
		fmt.Println("Leases:")
		fmt.Printf("  Created: %d\n", s.LeasesCreated)
		fmt.Printf("  Failed:  %d\n", s.LeasesFailed)
		fmt.Println()
	}

	// Secret stats
	if s.SecretsCreated > 0 || s.SecretsFailed > 0 {
		fmt.Println("Secrets:")
		fmt.Printf("  Created: %d\n", s.SecretsCreated)
		fmt.Printf("  Failed:  %d\n", s.SecretsFailed)
		fmt.Println()
	}

	// Authenticated read stats
	if s.AuthenticatedReadsSucceeded > 0 || s.AuthenticatedReadsFailed > 0 {
		fmt.Println("Authenticated Reads:")
		fmt.Printf("  Succeeded: %d\n", s.AuthenticatedReadsSucceeded)
		fmt.Printf("  Failed:    %d\n", s.AuthenticatedReadsFailed)
		fmt.Println()
	}

	// Performance metrics
	fmt.Println("Performance:")
	fmt.Printf("  Total Operations: %d\n", s.TotalOperations())
	fmt.Printf("  Operations/sec:   %.2f\n", s.OpsPerSecond())
	if s.LeasesCreated > 0 {
		fmt.Printf("  Leases/sec:       %.2f\n", s.LeasesPerSecond())
	}
	if s.AuthenticatedReadsSucceeded > 0 {
		fmt.Printf("  Auth Reads/sec:   %.2f\n", s.AuthenticatedReadsPerSecond())
	}
	fmt.Printf("  Success Rate:     %.1f%%\n", s.SuccessRate())
	fmt.Println(separator)
}

// repeatString repeats a string n times
func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
