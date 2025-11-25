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

	// Auth method operations (AppRole)
	AuthMethodsEnabled int64
	AuthMethodsSkipped int64
	AuthMethodsFailed  int64

	// PKI engine operations
	PKIEnginesEnabled int64
	PKIEnginesSkipped int64
	PKIEnginesFailed  int64

	// KV engine operations
	KVEnginesEnabled int64
	KVEnginesSkipped int64
	KVEnginesFailed  int64

	// AppRole role operations
	AppRoleRolesCreated int64
	AppRoleRolesSkipped int64
	AppRoleRolesFailed  int64

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

// IncAuthMethodsEnabled atomically increments the auth methods enabled counter
func (s *Stats) IncAuthMethodsEnabled() {
	atomic.AddInt64(&s.AuthMethodsEnabled, 1)
}

// IncAuthMethodsSkipped atomically increments the auth methods skipped counter
func (s *Stats) IncAuthMethodsSkipped() {
	atomic.AddInt64(&s.AuthMethodsSkipped, 1)
}

// IncAuthMethodsFailed atomically increments the auth methods failed counter
func (s *Stats) IncAuthMethodsFailed() {
	atomic.AddInt64(&s.AuthMethodsFailed, 1)
}

// IncPKIEnginesEnabled atomically increments the PKI engines enabled counter
func (s *Stats) IncPKIEnginesEnabled() {
	atomic.AddInt64(&s.PKIEnginesEnabled, 1)
}

// IncPKIEnginesSkipped atomically increments the PKI engines skipped counter
func (s *Stats) IncPKIEnginesSkipped() {
	atomic.AddInt64(&s.PKIEnginesSkipped, 1)
}

// IncPKIEnginesFailed atomically increments the PKI engines failed counter
func (s *Stats) IncPKIEnginesFailed() {
	atomic.AddInt64(&s.PKIEnginesFailed, 1)
}

// IncKVEnginesEnabled atomically increments the KV engines enabled counter
func (s *Stats) IncKVEnginesEnabled() {
	atomic.AddInt64(&s.KVEnginesEnabled, 1)
}

// IncKVEnginesSkipped atomically increments the KV engines skipped counter
func (s *Stats) IncKVEnginesSkipped() {
	atomic.AddInt64(&s.KVEnginesSkipped, 1)
}

// IncKVEnginesFailed atomically increments the KV engines failed counter
func (s *Stats) IncKVEnginesFailed() {
	atomic.AddInt64(&s.KVEnginesFailed, 1)
}

// IncAppRoleRolesCreated atomically increments the AppRole roles created counter
func (s *Stats) IncAppRoleRolesCreated() {
	atomic.AddInt64(&s.AppRoleRolesCreated, 1)
}

// IncAppRoleRolesSkipped atomically increments the AppRole roles skipped counter
func (s *Stats) IncAppRoleRolesSkipped() {
	atomic.AddInt64(&s.AppRoleRolesSkipped, 1)
}

// IncAppRoleRolesFailed atomically increments the AppRole roles failed counter
func (s *Stats) IncAppRoleRolesFailed() {
	atomic.AddInt64(&s.AppRoleRolesFailed, 1)
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
		s.AuthMethodsEnabled + s.AuthMethodsSkipped + s.AuthMethodsFailed +
		s.PKIEnginesEnabled + s.PKIEnginesSkipped + s.PKIEnginesFailed +
		s.KVEnginesEnabled + s.KVEnginesSkipped + s.KVEnginesFailed +
		s.AppRoleRolesCreated + s.AppRoleRolesSkipped + s.AppRoleRolesFailed +
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
	successful := s.NamespacesCreated + s.NamespacesSkipped +
		s.AuthMethodsEnabled + s.AuthMethodsSkipped +
		s.PKIEnginesEnabled + s.PKIEnginesSkipped +
		s.KVEnginesEnabled + s.KVEnginesSkipped +
		s.AppRoleRolesCreated + s.AppRoleRolesSkipped +
		s.LeasesCreated + s.SecretsCreated + s.AuthenticatedReadsSucceeded
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

	// Auth method stats (for AppRole mode)
	if s.AuthMethodsEnabled > 0 || s.AuthMethodsSkipped > 0 || s.AuthMethodsFailed > 0 {
		fmt.Println("Auth Methods:")
		fmt.Printf("  Enabled: %d\n", s.AuthMethodsEnabled)
		fmt.Printf("  Skipped: %d\n", s.AuthMethodsSkipped)
		fmt.Printf("  Failed:  %d\n", s.AuthMethodsFailed)
		fmt.Println()
	}

	// PKI engine stats (for PKI mode)
	if s.PKIEnginesEnabled > 0 || s.PKIEnginesSkipped > 0 || s.PKIEnginesFailed > 0 {
		fmt.Println("PKI Engines:")
		fmt.Printf("  Enabled: %d\n", s.PKIEnginesEnabled)
		fmt.Printf("  Skipped: %d\n", s.PKIEnginesSkipped)
		fmt.Printf("  Failed:  %d\n", s.PKIEnginesFailed)
		fmt.Println()
	}

	// KV engine stats (for KV and AppRole modes)
	if s.KVEnginesEnabled > 0 || s.KVEnginesSkipped > 0 || s.KVEnginesFailed > 0 {
		fmt.Println("KV Engines:")
		fmt.Printf("  Enabled: %d\n", s.KVEnginesEnabled)
		fmt.Printf("  Skipped: %d\n", s.KVEnginesSkipped)
		fmt.Printf("  Failed:  %d\n", s.KVEnginesFailed)
		fmt.Println()
	}

	// AppRole role stats (for AppRole mode)
	if s.AppRoleRolesCreated > 0 || s.AppRoleRolesSkipped > 0 || s.AppRoleRolesFailed > 0 {
		fmt.Println("AppRole Roles:")
		fmt.Printf("  Created: %d\n", s.AppRoleRolesCreated)
		fmt.Printf("  Skipped: %d\n", s.AppRoleRolesSkipped)
		fmt.Printf("  Failed:  %d\n", s.AppRoleRolesFailed)
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
