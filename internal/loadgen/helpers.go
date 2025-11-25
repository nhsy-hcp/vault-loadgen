package loadgen

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/vault/api"
	"github.com/nhsy/vault-loadgen/internal/client"
	"github.com/nhsy/vault-loadgen/internal/config"
)

// InitializeClient creates a new Vault client and validates the connection and authentication.
// This consolidates the common client setup logic used by all load generation modes.
func InitializeClient(cfg *config.Config) (*api.Client, error) {
	slog.Debug("initializing vault client", "addr", cfg.VaultAddr)

	vaultClient, err := client.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	slog.Debug("validating vault connection")
	if err := client.ValidateConnection(vaultClient); err != nil {
		return nil, fmt.Errorf("connection validation failed: %w", err)
	}

	slog.Debug("validating vault authentication")
	if err := client.ValidateAuth(vaultClient); err != nil {
		return nil, fmt.Errorf("authentication validation failed: %w", err)
	}

	slog.Info("vault client initialized successfully")
	return vaultClient, nil
}

// DetermineNamespaces determines which namespaces to use based on configuration.
// It either creates new child namespaces or uses a single namespace (parent or root).
//
// Behavior:
//   - If Namespaces>0: creates child namespaces under parent
//   - If Namespaces=0: uses single-namespace mode (parent namespace or root)
func DetermineNamespaces(ctx context.Context, cfg *config.Config) ([]string, error) {
	if cfg.Namespaces > 0 {
		slog.Info("creating child namespaces",
			"count", cfg.Namespaces,
			"parent", cfg.ParentNamespace)

		createdNamespaces, err := CreateNamespaces(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create namespaces: %w", err)
		}

		slog.Info("child namespaces created successfully", "count", len(createdNamespaces))
		return createdNamespaces, nil
	}

	// Single-namespace mode
	slog.Info("using single-namespace mode", "namespace", cfg.ParentNamespace)
	return []string{cfg.ParentNamespace}, nil
}

// GetNamespacedClient creates a new Vault client scoped to the specified namespace.
// This is a common pattern used throughout the load generation code to perform
// namespace-specific operations.
//
// If namespace is empty, returns a clone without setting a namespace.
func GetNamespacedClient(baseClient *api.Client, namespace string) (*api.Client, error) {
	nsClient, err := baseClient.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	return nsClient, nil
}
