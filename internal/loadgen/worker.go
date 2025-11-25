package loadgen

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/vault/api"
	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
	"golang.org/x/sync/errgroup"
)

// Worker defines the interface for all load generation workers.
// Each load generation mode (PKI, AppRole, KV) implements this interface.
type Worker interface {
	// Setup prepares the worker for execution (e.g., mount engines, create auth methods).
	// It is called once per namespace before Execute is called.
	Setup(ctx context.Context, namespace string) error

	// Execute performs a single unit of work and returns an error if it fails.
	// This method is called concurrently by multiple goroutines in the worker pool.
	Execute(ctx context.Context, namespace string, workIndex int) error

	// Cleanup performs any necessary cleanup after work is complete.
	// It is called once per namespace after all Execute calls have completed.
	Cleanup(ctx context.Context, namespace string) error

	// GetStats returns the current statistics for this worker.
	GetStats() *stats.Stats
}

// WorkerConfig holds common configuration needed by all workers.
type WorkerConfig struct {
	VaultClient *api.Client
	Config      *config.Config
	RateLimiter *ratelimit.Limiter
	Stats       *stats.Stats
}

// WorkItem represents a single unit of work to be executed.
type WorkItem struct {
	Namespace string
	Index     int
}

// RunWorkerPool executes a worker pool that distributes work across namespaces.
// It handles rate limiting, context cancellation, and error aggregation.
//
// The function distributes totalOperations across namespaces proportionally,
// with any remainder distributed to the first N namespaces.
//
// Parameters:
//   - ctx: Context for cancellation
//   - worker: Worker implementation to execute
//   - namespaces: List of namespaces to distribute work across
//   - totalOperations: Total number of operations to perform
//   - workerLimit: Maximum number of concurrent workers
//   - limiter: Rate limiter to control throughput
//
// Returns an error if any worker fails during execution.
func RunWorkerPool(ctx context.Context, worker Worker, namespaces []string,
	totalOperations int, workerLimit int, limiter *ratelimit.Limiter) error {

	if len(namespaces) == 0 {
		return fmt.Errorf("no namespaces provided")
	}

	if totalOperations < 1 {
		return fmt.Errorf("totalOperations must be >= 1")
	}

	// Distribute work across namespaces
	workItems := distributeWork(namespaces, totalOperations)

	slog.Info("worker pool starting",
		"total_operations", totalOperations,
		"namespaces", len(namespaces),
		"workers", workerLimit,
		"work_items", len(workItems))

	// Create worker pool with limited concurrency
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workerLimit)

	// Execute work items
	for _, item := range workItems {
		item := item // capture loop variable
		g.Go(func() error {
			// Rate limiting
			if err := limiter.Wait(ctx); err != nil {
				return err
			}

			// Check context cancellation
			if err := ctx.Err(); err != nil {
				return err
			}

			// Execute work
			if err := worker.Execute(ctx, item.Namespace, item.Index); err != nil {
				slog.Debug("work item failed",
					"namespace", item.Namespace,
					"index", item.Index,
					"error", err)
				// Don't return error - continue with other operations
				// The worker's Execute method should track failures in stats
			}

			return nil
		})
	}

	// Wait for all workers to complete
	if err := g.Wait(); err != nil {
		return fmt.Errorf("worker pool failed: %w", err)
	}

	slog.Info("worker pool completed", "total_operations", totalOperations)
	return nil
}

// distributeWork distributes operations across namespaces proportionally.
// It uses a round-robin approach for the remainder to ensure even distribution.
//
// Example: 100 operations across 3 namespaces = [33, 33, 34]
func distributeWork(namespaces []string, totalOperations int) []WorkItem {
	items := make([]WorkItem, 0, totalOperations)

	operationsPerNamespace := totalOperations / len(namespaces)
	remainder := totalOperations % len(namespaces)

	globalIndex := 0
	for nsIndex, ns := range namespaces {
		operationsForNS := operationsPerNamespace
		if nsIndex < remainder {
			operationsForNS++
		}

		for i := 0; i < operationsForNS; i++ {
			items = append(items, WorkItem{
				Namespace: ns,
				Index:     globalIndex,
			})
			globalIndex++
		}
	}

	return items
}
