package loadgen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// KVWorker implements the Worker interface for KV secret writes.
type KVWorker struct {
	client  *api.Client
	cfg     *config.Config
	stats   *stats.Stats
	limiter *ratelimit.Limiter
	engines map[string][]string // namespace -> engine names
	mu      sync.RWMutex
}

// NewKVWorker creates a new KV worker.
func NewKVWorker(wcfg *WorkerConfig) *KVWorker {
	return &KVWorker{
		client:  wcfg.VaultClient,
		cfg:     wcfg.Config,
		stats:   wcfg.Stats,
		limiter: wcfg.RateLimiter,
		engines: make(map[string][]string),
	}
}

// Setup prepares the KV engines in the given namespace.
func (w *KVWorker) Setup(ctx context.Context, namespace string) error {
	engineNames := make([]string, 0, w.cfg.KVEngines)

	for engineIndex := 0; engineIndex < w.cfg.KVEngines; engineIndex++ {
		engineName := fmt.Sprintf("secret-%d", engineIndex)

		if err := setupKVEngine(ctx, w.client, namespace, engineName); err != nil {
			return fmt.Errorf("failed to setup KV engine %q: %w", engineName, err)
		}

		engineNames = append(engineNames, engineName)
		slog.Debug("kv engine setup complete", "namespace", namespace, "engine", engineName)
	}

	// Store engine names for this namespace
	w.mu.Lock()
	w.engines[namespace] = engineNames
	w.mu.Unlock()

	return nil
}

// Execute writes a single secret to a KV engine.
func (w *KVWorker) Execute(ctx context.Context, namespace string, workIndex int) error {
	// Get engine names for this namespace
	w.mu.RLock()
	engineNames := w.engines[namespace]
	w.mu.RUnlock()

	if len(engineNames) == 0 {
		w.stats.IncSecretsFailed()
		return fmt.Errorf("no engines found for namespace %q", namespace)
	}

	// Distribute secrets across engines
	engineIndex := workIndex % len(engineNames)
	engineName := engineNames[engineIndex]
	secretName := fmt.Sprintf("loadtest-%d", workIndex)

	// Generate random secret data
	secretData := generateRandomSecret(w.cfg.SecretSize)

	if err := writeSecret(ctx, w.client, namespace, engineName, secretName, secretData); err != nil {
		slog.Warn("failed to write secret", "namespace", namespace, "engine", engineName, "secret", secretName, "error", err)
		w.stats.IncSecretsFailed()
		return nil // Don't stop other workers
	}

	w.stats.IncSecretsCreated()
	return nil
}

// Cleanup performs any necessary cleanup (currently none needed for KV).
func (w *KVWorker) Cleanup(ctx context.Context, namespace string) error {
	return nil
}

// GetStats returns the worker's statistics.
func (w *KVWorker) GetStats() *stats.Stats {
	return w.stats
}

// GenerateKVLoad generates KV v2 secrets for load testing
// Works in both multi-namespace mode (distributes across namespaces) and single-namespace mode
func GenerateKVLoad(ctx context.Context, cfg *config.Config) (*stats.Stats, error) {
	// Validate config
	if cfg.SecretsPerEngine < 1 {
		return nil, fmt.Errorf("secrets-per-engine must be at least 1, got %d", cfg.SecretsPerEngine)
	}
	if cfg.KVEngines < 1 {
		return nil, fmt.Errorf("kv-engines must be at least 1, got %d", cfg.KVEngines)
	}

	// Initialize client
	vaultClient, err := InitializeClient(cfg)
	if err != nil {
		return nil, err
	}

	// Initialize stats
	st := stats.New()

	// Determine namespaces
	namespaces, err := DetermineNamespaces(ctx, cfg)
	if err != nil {
		return st, err
	}

	// Create rate limiter
	limiter := ratelimit.New(cfg.RateLimit)
	if cfg.RateLimit > 0 {
		slog.Info("rate limiting enabled", "ops_per_second", cfg.RateLimit)
	}

	// Create worker
	worker := NewKVWorker(&WorkerConfig{
		VaultClient: vaultClient,
		Config:      cfg,
		RateLimiter: limiter,
		Stats:       st,
	})

	// Setup KV engines in each namespace
	slog.Info("kv mode: setting up KV v2 engines", "namespaces", len(namespaces), "engines_per_namespace", cfg.KVEngines)
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		if err := worker.Setup(ctx, ns); err != nil {
			slog.Error("failed to setup KV engine", "namespace", ns, "error", err)
			return st, fmt.Errorf("failed to setup KV engine in namespace %q: %w", ns, err)
		}
	}

	// Calculate total secrets to write
	totalSecrets := len(namespaces) * cfg.KVEngines * cfg.SecretsPerEngine

	// Write secrets using worker pool
	slog.Info("kv mode: writing secrets",
		"total_secrets", totalSecrets,
		"namespaces", len(namespaces),
		"engines_per_namespace", cfg.KVEngines,
		"secrets_per_engine", cfg.SecretsPerEngine)

	if err := RunWorkerPool(ctx, worker, namespaces, totalSecrets, cfg.Workers, limiter); err != nil {
		return st, err
	}

	st.End()

	// Log summary
	slog.Info("kv mode complete",
		"created", st.SecretsCreated,
		"failed", st.SecretsFailed,
		"duration", st.Duration(),
		"secrets_per_sec", st.SecretsPerSecond())

	return st, nil
}

// setupKVEngine enables and configures a KV v2 secrets engine in the given namespace
func setupKVEngine(ctx context.Context, vaultClient *api.Client, namespace string, engineName string) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
	}

	// Enable KV v2 secrets engine
	mountInput := &api.MountInput{
		Type: "kv-v2",
		Options: map[string]string{
			"version": "2",
		},
	}

	err = nsClient.Sys().Mount(engineName, mountInput)
	if err != nil {
		// Check if already mounted
		if strings.Contains(err.Error(), "path is already in use") {
			slog.Debug("kv engine already mounted", "namespace", namespace, "engine", engineName)
		} else {
			return fmt.Errorf("failed to mount kv engine: %w", err)
		}
	}

	return nil
}

// generateRandomSecret creates a map with random key-value pairs
func generateRandomSecret(size int) map[string]interface{} {
	secret := make(map[string]interface{}, size)

	for i := 0; i < size; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := generateRandomString(32)
		secret[key] = value
	}

	return secret
}

// generateRandomString generates a random hexadecimal string of the specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to predictable but unique string if random generation fails
		return fmt.Sprintf("value-%d", length)
	}
	return hex.EncodeToString(bytes)
}

// writeSecret writes a secret to a KV v2 engine
func writeSecret(ctx context.Context, vaultClient *api.Client, namespace string, engineName string, secretName string, data map[string]interface{}) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
	}

	// KV v2 requires writing to "data" subpath
	path := engineName + "/data/" + secretName
	secretPayload := map[string]interface{}{
		"data": data,
	}

	_, err = nsClient.Logical().Write(path, secretPayload)
	if err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	slog.Debug("secret written successfully",
		"namespace", namespace,
		"engine", engineName,
		"secret", secretName,
		"keys", len(data))

	return nil
}
