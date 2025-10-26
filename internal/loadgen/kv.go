package loadgen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/vault/api"
	"golang.org/x/sync/errgroup"

	"vault-loadgen/internal/client"
	"vault-loadgen/internal/config"
	"vault-loadgen/internal/ratelimit"
	"vault-loadgen/internal/stats"
)

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

	// Create Vault client
	vaultClient, err := client.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Validate authentication
	if err := client.ValidateAuth(vaultClient); err != nil {
		return nil, fmt.Errorf("authentication validation failed: %w", err)
	}

	st := stats.New()

	// Determine namespaces to use
	namespaces := []string{}
	if cfg.CreateNamespaces && cfg.Namespaces > 0 {
		// Multi-namespace mode: create child namespaces
		slog.Info("kv mode: creating child namespaces", "count", cfg.Namespaces)
		createdNamespaces, err := CreateNamespaces(ctx, cfg)
		if err != nil {
			return st, fmt.Errorf("failed to create namespaces: %w", err)
		}
		namespaces = createdNamespaces
	} else {
		// Single-namespace mode: use parent namespace or root
		slog.Info("kv mode: using single-namespace mode", "namespace", cfg.ParentNamespace)
		namespaces = []string{cfg.ParentNamespace}
	}

	slog.Info("kv mode: setting up KV v2 engines", "namespaces", len(namespaces), "engines_per_namespace", cfg.KVEngines)

	// Setup KV v2 engines in each namespace
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		for engineIndex := 0; engineIndex < cfg.KVEngines; engineIndex++ {
			engineName := fmt.Sprintf("secret-%d", engineIndex)

			if err := setupKVEngine(ctx, vaultClient, ns, engineName); err != nil {
				slog.Error("failed to setup KV engine", "namespace", ns, "engine", engineName, "error", err)
				return st, fmt.Errorf("failed to setup KV engine %q in namespace %q: %w", engineName, ns, err)
			}
			slog.Debug("kv engine setup complete", "namespace", ns, "engine", engineName)
		}
	}

	// Calculate total secrets to write
	totalSecrets := len(namespaces) * cfg.KVEngines * cfg.SecretsPerEngine

	slog.Info("kv mode: writing secrets",
		"total_secrets", totalSecrets,
		"namespaces", len(namespaces),
		"engines_per_namespace", cfg.KVEngines,
		"secrets_per_engine", cfg.SecretsPerEngine)

	// Create rate limiter
	limiter := ratelimit.New(cfg.RateLimit)
	if cfg.RateLimit > 0 {
		slog.Info("rate limiting enabled", "ops_per_second", cfg.RateLimit)
	}

	// Write secrets using worker pool
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.Workers)

	secretIndex := 0
	for _, ns := range namespaces {
		for engineIndex := 0; engineIndex < cfg.KVEngines; engineIndex++ {
			engineName := fmt.Sprintf("secret-%d", engineIndex)

			// Write secrets for this engine
			for i := 0; i < cfg.SecretsPerEngine; i++ {
				ns := ns                 // Capture for goroutine
				engineName := engineName // Capture for goroutine
				secretIndex++
				secretName := fmt.Sprintf("loadtest-%d", secretIndex)

				g.Go(func() error {
					// Wait for rate limiter
					if err := limiter.Wait(ctx); err != nil {
						return err
					}

					if err := ctx.Err(); err != nil {
						return err
					}

					// Generate random secret data
					secretData := generateRandomSecret(cfg.SecretSize)

					if err := writeSecret(ctx, vaultClient, ns, engineName, secretName, secretData); err != nil {
						slog.Warn("failed to write secret", "namespace", ns, "engine", engineName, "secret", secretName, "error", err)
						st.IncSecretsFailed()
						return nil // Don't stop other workers
					}

					st.IncSecretsCreated()
					return nil
				})
			}
		}
	}

	// Wait for all workers
	if err := g.Wait(); err != nil {
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
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
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
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
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
