package loadgen

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// mockWorker is a mock implementation of the Worker interface for testing.
type mockWorker struct {
	setupCalls   atomic.Int64
	executeCalls atomic.Int64
	cleanupCalls atomic.Int64
	failSetup    bool
	failExecute  bool
	stats        *stats.Stats
}

func newMockWorker() *mockWorker {
	return &mockWorker{
		stats: stats.New(),
	}
}

func (m *mockWorker) Setup(ctx context.Context, namespace string) error {
	m.setupCalls.Add(1)
	if m.failSetup {
		return errors.New("setup failed")
	}
	return nil
}

func (m *mockWorker) Execute(ctx context.Context, namespace string, workIndex int) error {
	m.executeCalls.Add(1)
	if m.failExecute {
		m.stats.IncLeasesFailed()
		return errors.New("execute failed")
	}
	m.stats.IncLeasesCreated()
	return nil
}

func (m *mockWorker) Cleanup(ctx context.Context, namespace string) error {
	m.cleanupCalls.Add(1)
	return nil
}

func (m *mockWorker) GetStats() *stats.Stats {
	return m.stats
}

func TestMockWorkerImplementsInterface(t *testing.T) {
	var _ Worker = (*mockWorker)(nil)
}

func TestDistributeWork(t *testing.T) {
	tests := []struct {
		name                 string
		namespaces           []string
		totalOperations      int
		expectedDistribution map[string]int
	}{
		{
			name:            "equal distribution",
			namespaces:      []string{"ns1", "ns2", "ns3"},
			totalOperations: 99,
			expectedDistribution: map[string]int{
				"ns1": 33,
				"ns2": 33,
				"ns3": 33,
			},
		},
		{
			name:            "unequal distribution with remainder",
			namespaces:      []string{"ns1", "ns2", "ns3"},
			totalOperations: 100,
			expectedDistribution: map[string]int{
				"ns1": 34,
				"ns2": 33,
				"ns3": 33,
			},
		},
		{
			name:            "single namespace",
			namespaces:      []string{"ns1"},
			totalOperations: 100,
			expectedDistribution: map[string]int{
				"ns1": 100,
			},
		},
		{
			name:            "more namespaces than operations",
			namespaces:      []string{"ns1", "ns2", "ns3", "ns4", "ns5"},
			totalOperations: 3,
			expectedDistribution: map[string]int{
				"ns1": 1,
				"ns2": 1,
				"ns3": 1,
				"ns4": 0,
				"ns5": 0,
			},
		},
		{
			name:            "operations equal to namespaces",
			namespaces:      []string{"ns1", "ns2", "ns3"},
			totalOperations: 3,
			expectedDistribution: map[string]int{
				"ns1": 1,
				"ns2": 1,
				"ns3": 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := distributeWork(tt.namespaces, tt.totalOperations)

			// Verify total count
			if len(items) != tt.totalOperations {
				t.Errorf("expected %d items, got %d", tt.totalOperations, len(items))
			}

			// Verify distribution per namespace
			distribution := make(map[string]int)
			for _, item := range items {
				distribution[item.Namespace]++
			}

			for ns, expectedCount := range tt.expectedDistribution {
				if distribution[ns] != expectedCount {
					t.Errorf("namespace %s: expected %d operations, got %d",
						ns, expectedCount, distribution[ns])
				}
			}

			// Verify indexes are sequential
			for i, item := range items {
				if item.Index != i {
					t.Errorf("item %d: expected index %d, got %d", i, i, item.Index)
				}
			}
		})
	}
}

func TestRunWorkerPool(t *testing.T) {
	tests := []struct {
		name            string
		namespaces      []string
		totalOperations int
		workerLimit     int
		failExecute     bool
		expectError     bool
	}{
		{
			name:            "successful execution",
			namespaces:      []string{"ns1", "ns2"},
			totalOperations: 10,
			workerLimit:     4,
			failExecute:     false,
			expectError:     false,
		},
		{
			name:            "single namespace",
			namespaces:      []string{"ns1"},
			totalOperations: 100,
			workerLimit:     8,
			failExecute:     false,
			expectError:     false,
		},
		{
			name:            "single worker",
			namespaces:      []string{"ns1", "ns2"},
			totalOperations: 10,
			workerLimit:     1,
			failExecute:     false,
			expectError:     false,
		},
		{
			name:            "many workers",
			namespaces:      []string{"ns1", "ns2", "ns3"},
			totalOperations: 50,
			workerLimit:     32,
			failExecute:     false,
			expectError:     false,
		},
		{
			name:            "worker execution failures",
			namespaces:      []string{"ns1"},
			totalOperations: 10,
			workerLimit:     4,
			failExecute:     true,
			expectError:     false, // Failures are tracked in stats, not returned
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			worker := newMockWorker()
			worker.failExecute = tt.failExecute
			limiter := ratelimit.New(0) // No rate limiting for tests

			err := RunWorkerPool(ctx, worker, tt.namespaces, tt.totalOperations,
				tt.workerLimit, limiter)

			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}

			// Verify all operations were executed
			executeCalls := worker.executeCalls.Load()
			if int(executeCalls) != tt.totalOperations {
				t.Errorf("expected %d execute calls, got %d",
					tt.totalOperations, executeCalls)
			}

			// Verify stats tracking
			stats := worker.GetStats()
			if tt.failExecute {
				if stats.LeasesFailed != int64(tt.totalOperations) {
					t.Errorf("expected %d failed leases, got %d",
						tt.totalOperations, stats.LeasesFailed)
				}
			} else {
				if stats.LeasesCreated != int64(tt.totalOperations) {
					t.Errorf("expected %d created leases, got %d",
						tt.totalOperations, stats.LeasesCreated)
				}
			}
		})
	}
}

func TestRunWorkerPool_ErrorCases(t *testing.T) {
	tests := []struct {
		name            string
		namespaces      []string
		totalOperations int
		expectError     bool
		errorContains   string
	}{
		{
			name:            "no namespaces",
			namespaces:      []string{},
			totalOperations: 10,
			expectError:     true,
			errorContains:   "no namespaces provided",
		},
		{
			name:            "zero operations",
			namespaces:      []string{"ns1"},
			totalOperations: 0,
			expectError:     true,
			errorContains:   "totalOperations must be >= 1",
		},
		{
			name:            "negative operations",
			namespaces:      []string{"ns1"},
			totalOperations: -1,
			expectError:     true,
			errorContains:   "totalOperations must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			worker := newMockWorker()
			limiter := ratelimit.New(0)

			err := RunWorkerPool(ctx, worker, tt.namespaces, tt.totalOperations, 4, limiter)

			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}

			if err != nil && tt.errorContains != "" {
				if !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q",
						tt.errorContains, err.Error())
				}
			}
		})
	}
}

func TestRunWorkerPool_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	worker := newMockWorker()
	limiter := ratelimit.New(0)

	err := RunWorkerPool(ctx, worker, []string{"ns1"}, 10, 4, limiter)

	// Should complete quickly due to context cancellation
	// No explicit error expected as workers check context and exit gracefully
	if err != nil {
		// Context cancellation is acceptable
		if !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
