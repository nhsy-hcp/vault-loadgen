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
			name: "mixed operations",
			setupFunc: func(s *Stats) {
				s.NamespacesCreated = 5
				s.LeasesCreated = 100
				s.SecretsCreated = 50
				s.NamespacesFailed = 1
				s.LeasesFailed = 10
				s.SecretsFailed = 5
			},
			want: 171,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			tt.setupFunc(s)

			got := s.SuccessRate()
			if got != tt.want {
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
