package stats

import (
	"testing"
	"time"
)

func TestStats_Increment(t *testing.T) {
	s := New()

	s.IncNamespacesCreated()
	s.IncNamespacesCreated()
	s.IncNamespacesSkipped()
	s.IncNamespacesFailed()

	if s.NamespacesCreated != 2 {
		t.Errorf("NamespacesCreated = %d, want 2", s.NamespacesCreated)
	}
	if s.NamespacesSkipped != 1 {
		t.Errorf("NamespacesSkipped = %d, want 1", s.NamespacesSkipped)
	}
	if s.NamespacesFailed != 1 {
		t.Errorf("NamespacesFailed = %d, want 1", s.NamespacesFailed)
	}
}

func TestStats_LeasesIncrement(t *testing.T) {
	s := New()

	s.IncLeasesCreated()
	s.IncLeasesCreated()
	s.IncLeasesCreated()
	s.IncLeasesFailed()

	if s.LeasesCreated != 3 {
		t.Errorf("LeasesCreated = %d, want 3", s.LeasesCreated)
	}
	if s.LeasesFailed != 1 {
		t.Errorf("LeasesFailed = %d, want 1", s.LeasesFailed)
	}
}

func TestStats_SecretsIncrement(t *testing.T) {
	s := New()

	s.IncSecretsCreated()
	s.IncSecretsCreated()
	s.IncSecretsFailed()

	if s.SecretsCreated != 2 {
		t.Errorf("SecretsCreated = %d, want 2", s.SecretsCreated)
	}
	if s.SecretsFailed != 1 {
		t.Errorf("SecretsFailed = %d, want 1", s.SecretsFailed)
	}
}

func TestStats_AuthenticatedReadsIncrement(t *testing.T) {
	s := New()

	s.IncAuthenticatedReadsSucceeded()
	s.IncAuthenticatedReadsSucceeded()
	s.IncAuthenticatedReadsSucceeded()
	s.IncAuthenticatedReadsFailed()

	if s.AuthenticatedReadsSucceeded != 3 {
		t.Errorf("AuthenticatedReadsSucceeded = %d, want 3", s.AuthenticatedReadsSucceeded)
	}
	if s.AuthenticatedReadsFailed != 1 {
		t.Errorf("AuthenticatedReadsFailed = %d, want 1", s.AuthenticatedReadsFailed)
	}
}

func TestStats_AuthMethodsIncrement(t *testing.T) {
	s := New()

	s.IncAuthMethodsEnabled()
	s.IncAuthMethodsEnabled()
	s.IncAuthMethodsSkipped()
	s.IncAuthMethodsFailed()

	if s.AuthMethodsEnabled != 2 {
		t.Errorf("AuthMethodsEnabled = %d, want 2", s.AuthMethodsEnabled)
	}
	if s.AuthMethodsSkipped != 1 {
		t.Errorf("AuthMethodsSkipped = %d, want 1", s.AuthMethodsSkipped)
	}
	if s.AuthMethodsFailed != 1 {
		t.Errorf("AuthMethodsFailed = %d, want 1", s.AuthMethodsFailed)
	}
}

func TestStats_PKIEnginesIncrement(t *testing.T) {
	s := New()

	s.IncPKIEnginesEnabled()
	s.IncPKIEnginesEnabled()
	s.IncPKIEnginesSkipped()
	s.IncPKIEnginesFailed()

	if s.PKIEnginesEnabled != 2 {
		t.Errorf("PKIEnginesEnabled = %d, want 2", s.PKIEnginesEnabled)
	}
	if s.PKIEnginesSkipped != 1 {
		t.Errorf("PKIEnginesSkipped = %d, want 1", s.PKIEnginesSkipped)
	}
	if s.PKIEnginesFailed != 1 {
		t.Errorf("PKIEnginesFailed = %d, want 1", s.PKIEnginesFailed)
	}
}

func TestStats_KVEnginesIncrement(t *testing.T) {
	s := New()

	s.IncKVEnginesEnabled()
	s.IncKVEnginesEnabled()
	s.IncKVEnginesEnabled()
	s.IncKVEnginesSkipped()
	s.IncKVEnginesFailed()

	if s.KVEnginesEnabled != 3 {
		t.Errorf("KVEnginesEnabled = %d, want 3", s.KVEnginesEnabled)
	}
	if s.KVEnginesSkipped != 1 {
		t.Errorf("KVEnginesSkipped = %d, want 1", s.KVEnginesSkipped)
	}
	if s.KVEnginesFailed != 1 {
		t.Errorf("KVEnginesFailed = %d, want 1", s.KVEnginesFailed)
	}
}

func TestStats_AppRoleRolesIncrement(t *testing.T) {
	s := New()

	s.IncAppRoleRolesCreated()
	s.IncAppRoleRolesCreated()
	s.IncAppRoleRolesSkipped()
	s.IncAppRoleRolesFailed()

	if s.AppRoleRolesCreated != 2 {
		t.Errorf("AppRoleRolesCreated = %d, want 2", s.AppRoleRolesCreated)
	}
	if s.AppRoleRolesSkipped != 1 {
		t.Errorf("AppRoleRolesSkipped = %d, want 1", s.AppRoleRolesSkipped)
	}
	if s.AppRoleRolesFailed != 1 {
		t.Errorf("AppRoleRolesFailed = %d, want 1", s.AppRoleRolesFailed)
	}
}

func TestStats_Duration(t *testing.T) {
	s := New()

	// Sleep for a short time
	time.Sleep(10 * time.Millisecond)

	s.End()

	duration := s.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("Duration = %v, want >= 10ms", duration)
	}
}

func TestStats_TotalOperations(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*Stats)
		want      int
	}{
		{
			name: "namespaces only",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 5
				s.NamespacesSkipped = 2
				s.NamespacesFailed = 1
			},
			want: 8,
		},
		{
			name: "leases only",
			setupFunc: func(s *Stats) {
				s.LeasesCreated = 100
				s.LeasesFailed = 10
			},
			want: 110,
		},
		{
			name: "secrets only",
			setupFunc: func(s *Stats) {
				s.SecretsCreated = 50
				s.SecretsFailed = 5
			},
			want: 55,
		},
		{
			name: "authenticated reads only",
			setupFunc: func(s *Stats) {
				s.AuthenticatedReadsSucceeded = 80
				s.AuthenticatedReadsFailed = 20
			},
			want: 100,
		},
		{
			name: "mixed operations",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 5
				s.LeasesCreated = 100
				s.SecretsCreated = 50
				s.AuthenticatedReadsSucceeded = 80
				s.NamespacesFailed = 1
				s.LeasesFailed = 10
				s.SecretsFailed = 5
				s.AuthenticatedReadsFailed = 20
			},
			want: 271,
		},
		{
			name: "engines and auth methods",
			setupFunc: func(s *Stats) {
				s.AuthMethodsEnabled = 5
				s.AuthMethodsSkipped = 2
				s.AuthMethodsFailed = 1
				s.PKIEnginesEnabled = 10
				s.PKIEnginesSkipped = 3
				s.PKIEnginesFailed = 1
				s.KVEnginesEnabled = 20
				s.KVEnginesSkipped = 5
				s.KVEnginesFailed = 2
				s.AppRoleRolesCreated = 100
				s.AppRoleRolesSkipped = 50
				s.AppRoleRolesFailed = 10
			},
			want: 209,
		},
		{
			name: "all operations including engines",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 5
				s.NamespacesSkipped = 2
				s.AuthMethodsEnabled = 5
				s.PKIEnginesEnabled = 5
				s.KVEnginesEnabled = 10
				s.AppRoleRolesCreated = 50
				s.LeasesCreated = 100
				s.SecretsCreated = 50
				s.AuthenticatedReadsSucceeded = 80
			},
			want: 307,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			tt.setupFunc(s)

			got := s.TotalOperations()
			if got != tt.want {
				t.Errorf("TotalOperations() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestStats_OpsPerSecond(t *testing.T) {
	s := New()

	s.NamespacesCreated = 10
	s.LeasesCreated = 100

	// Simulate 1 second duration
	s.StartTime = time.Now().Add(-1 * time.Second)
	s.EndTime = time.Now()

	ops := s.OpsPerSecond()

	// Should be around 110 ops/sec
	if ops < 100 || ops > 120 {
		t.Errorf("OpsPerSecond() = %.2f, want ~110", ops)
	}
}

func TestStats_AuthenticatedReadsPerSecond(t *testing.T) {
	s := New()

	s.AuthenticatedReadsSucceeded = 50

	// Simulate 2 second duration
	s.StartTime = time.Now().Add(-2 * time.Second)
	s.EndTime = time.Now()

	reads := s.AuthenticatedReadsPerSecond()

	// Should be around 25 reads/sec
	if reads < 20 || reads > 30 {
		t.Errorf("AuthenticatedReadsPerSecond() = %.2f, want ~25", reads)
	}
}

func TestStats_AuthenticatedReadsPerSecond_ZeroDuration(t *testing.T) {
	s := New()
	s.AuthenticatedReadsSucceeded = 100
	s.End() // Set same end time as start time for zero duration

	// Reset to exact same time to ensure zero duration
	s.EndTime = s.StartTime

	reads := s.AuthenticatedReadsPerSecond()
	if reads != 0 {
		t.Errorf("AuthenticatedReadsPerSecond() = %.2f, want 0", reads)
	}
}

func TestStats_LeasesPerSecond(t *testing.T) {
	s := New()

	s.LeasesCreated = 100

	// Simulate 2 second duration
	s.StartTime = time.Now().Add(-2 * time.Second)
	s.EndTime = time.Now()

	lps := s.LeasesPerSecond()

	// Should be around 50 leases/sec
	if lps < 45 || lps > 55 {
		t.Errorf("LeasesPerSecond() = %.2f, want ~50", lps)
	}
}

func TestStats_OpsPerSecond_ZeroDuration(t *testing.T) {
	s := New()
	s.NamespacesCreated = 10

	// Same start and end time
	s.StartTime = time.Now()
	s.EndTime = s.StartTime

	ops := s.OpsPerSecond()
	if ops != 0 {
		t.Errorf("OpsPerSecond() with zero duration = %.2f, want 0", ops)
	}
}

func TestStats_SuccessRate(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*Stats)
		want      float64
	}{
		{
			name: "100% success",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 10
				s.LeasesCreated = 100
			},
			want: 100.0,
		},
		{
			name: "90% success",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 9
				s.NamespacesFailed = 1
			},
			want: 90.0,
		},
		{
			name: "50% success",
			setupFunc: func(s *Stats) {
				s.LeasesCreated = 50
				s.LeasesFailed = 50
			},
			want: 50.0,
		},
		{
			name: "authenticated reads success",
			setupFunc: func(s *Stats) {
				s.AuthenticatedReadsSucceeded = 90
				s.AuthenticatedReadsFailed = 10
			},
			want: 90.0,
		},
		{
			name: "0% success",
			setupFunc: func(s *Stats) {
				s.NamespacesFailed = 10
				s.LeasesFailed = 100
			},
			want: 0.0,
		},
		{
			name: "no operations",
			setupFunc: func(s *Stats) {
				// No operations
			},
			want: 0.0,
		},
		{
			name: "skipped resources count as success",
			setupFunc: func(s *Stats) {
				s.NamespacesSkipped = 5
				s.AuthMethodsSkipped = 3
				s.PKIEnginesSkipped = 2
				s.KVEnginesSkipped = 10
				s.AppRoleRolesSkipped = 20
			},
			want: 100.0,
		},
		{
			name: "mixed with skipped resources",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 5
				s.NamespacesSkipped = 3
				s.NamespacesFailed = 2
				s.PKIEnginesEnabled = 10
				s.PKIEnginesSkipped = 5
				s.PKIEnginesFailed = 1
			},
			want: 88.46, // 23 successful out of 26 total
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			tt.setupFunc(s)

			got := s.SuccessRate()
			// Allow small floating point differences
			diff := got - tt.want
			if diff < 0 {
				diff = -diff
			}
			if diff > 0.01 {
				t.Errorf("SuccessRate() = %.2f, want %.2f", got, tt.want)
			}
		})
	}
}

func TestStats_Concurrent(t *testing.T) {
	s := New()

	done := make(chan bool)

	// Concurrent increments
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				s.IncLeasesCreated()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	expected := 1000
	if s.LeasesCreated != int64(expected) {
		t.Errorf("Concurrent LeasesCreated = %d, want %d", s.LeasesCreated, expected)
	}
}

func TestStats_Duration_NoEndTime(t *testing.T) {
	s := New()

	// Sleep briefly to ensure duration > 0
	time.Sleep(10 * time.Millisecond)

	// Don't call End() - Duration should use time.Since(StartTime)
	duration := s.Duration()

	if duration < 10*time.Millisecond {
		t.Errorf("Duration without End() = %v, want >= 10ms", duration)
	}

	// Verify EndTime is still zero
	if !s.EndTime.IsZero() {
		t.Error("EndTime should be zero when End() not called")
	}
}

func TestStats_SecretsPerSecond(t *testing.T) {
	s := New()

	s.SecretsCreated = 50

	// Simulate 2 second duration
	s.StartTime = time.Now().Add(-2 * time.Second)
	s.EndTime = time.Now()

	sps := s.SecretsPerSecond()

	// Should be around 25 secrets/sec
	if sps < 20 || sps > 30 {
		t.Errorf("SecretsPerSecond() = %.2f, want ~25", sps)
	}
}

func TestStats_SecretsPerSecond_ZeroDuration(t *testing.T) {
	s := New()
	s.SecretsCreated = 50

	// Same start and end time
	s.StartTime = time.Now()
	s.EndTime = s.StartTime

	sps := s.SecretsPerSecond()
	if sps != 0 {
		t.Errorf("SecretsPerSecond() with zero duration = %.2f, want 0", sps)
	}
}

func TestStats_PrintSummary_AllStats(t *testing.T) {
	s := New()

	s.NamespacesCreated = 5
	s.NamespacesSkipped = 1
	s.NamespacesFailed = 1
	s.LeasesCreated = 100
	s.LeasesFailed = 5
	s.SecretsCreated = 50
	s.SecretsFailed = 2

	s.StartTime = time.Now().Add(-10 * time.Second)
	s.EndTime = time.Now()

	// Just verify it doesn't panic and runs without error
	// Output validation would require capturing stdout
	s.PrintSummary("Test Mode")
}

func TestStats_PrintSummary_OnlyNamespaces(t *testing.T) {
	s := New()

	s.NamespacesCreated = 10
	s.StartTime = time.Now().Add(-5 * time.Second)
	s.EndTime = time.Now()

	// Verify no panic with only namespace stats
	s.PrintSummary("Namespace Only")
}

func TestStats_PrintSummary_OnlyLeases(t *testing.T) {
	s := New()

	s.LeasesCreated = 200
	s.LeasesFailed = 10
	s.StartTime = time.Now().Add(-20 * time.Second)
	s.EndTime = time.Now()

	// Verify no panic with only lease stats
	s.PrintSummary("Leases Only")
}

func TestStats_PrintSummary_OnlySecrets(t *testing.T) {
	s := New()

	s.SecretsCreated = 75
	s.SecretsFailed = 3
	s.StartTime = time.Now().Add(-15 * time.Second)
	s.EndTime = time.Now()

	// Verify no panic with only secret stats
	s.PrintSummary("Secrets Only")
}

func TestStats_PrintSummary_Empty(t *testing.T) {
	s := New()

	s.StartTime = time.Now()
	s.EndTime = time.Now()

	// Verify no panic with empty stats
	s.PrintSummary("Empty")
}
