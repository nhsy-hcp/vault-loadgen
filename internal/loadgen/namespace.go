package loadgen

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"vault-loadgen/internal/client"
	"vault-loadgen/internal/config"
	"vault-loadgen/internal/stats"
)

var (
	// Namespace name validation pattern
	// Allow alphanumeric, hyphens, and underscores
	namespaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// GenerateNamespaceNames generates unique namespace names for load testing
func GenerateNamespaceNames(parent string, count int) []string {
	names := make([]string, count)
	timestamp := time.Now().Unix()

	for i := 0; i < count; i++ {
		names[i] = fmt.Sprintf("loadtest-%d-%d", timestamp, i)
	}

	return names
}

// ValidateNamespaceName validates a namespace name
func ValidateNamespaceName(name string) error {
	if name == "" {
		return fmt.Errorf("namespace name cannot be empty")
	}

	if !namespaceNamePattern.MatchString(name) {
		return fmt.Errorf("namespace name %q contains invalid characters (only alphanumeric, hyphens, and underscores allowed)", name)
	}

	return nil
}

// IsNamespaceExistsError checks if an error indicates the namespace already exists
func IsNamespaceExistsError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "already exists") ||
		strings.Contains(errMsg, "already in use")
}

// IsPermissionDeniedError checks if an error indicates permission was denied
func IsPermissionDeniedError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "access denied") ||
		strings.Contains(errMsg, "insufficient permissions")
}

// IsNamespaceNotSupportedError checks if an error indicates namespaces are not supported (OSS)
func IsNamespaceNotSupportedError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "unsupported path") ||
		strings.Contains(errMsg, "unsupported operation") ||
		strings.Contains(errMsg, "unknown command") ||
		strings.Contains(errMsg, "enterprise-only") ||
		strings.Contains(errMsg, "feature is part of vault enterprise") ||
		strings.Contains(errMsg, "namespace feature requires vault enterprise")
}

// FormatOSSNamespaceError returns a helpful error message for OSS namespace failures
func FormatOSSNamespaceError() error {
	return fmt.Errorf(`namespace creation failed: Vault OSS does not support namespaces (Enterprise-only feature)

To run load tests on Vault OSS, use single-namespace mode:
  --namespaces=0
or
  --create-namespaces=false

All operations will run in the root namespace (or --parent-namespace if specified)`)
}

// BuildFullNamespacePath constructs a full namespace path from parent and child
func BuildFullNamespacePath(parent, child string) string {
	return client.BuildNamespacePath(parent, child)
}

// CreateNamespace creates a single namespace in Vault
func CreateNamespace(ctx context.Context, vaultClient *api.Client, namespacePath string, stats *stats.Stats) error {
	// Validate namespace name
	parts := strings.Split(namespacePath, "/")
	childName := parts[len(parts)-1]

	if err := ValidateNamespaceName(childName); err != nil {
		slog.Error("invalid namespace name", "namespace", namespacePath, "error", err)
		stats.IncNamespacesFailed()
		return err
	}

	// Create namespace
	path := "sys/namespaces/" + namespacePath
	_, err := vaultClient.Logical().Write(path, map[string]interface{}{})

	if err != nil {
		// Check if namespace already exists (idempotent operation)
		if IsNamespaceExistsError(err) {
			slog.Debug("namespace already exists, skipping", "namespace", namespacePath)
			stats.IncNamespacesSkipped()
			return nil
		}

		// Check for OSS namespace not supported errors
		if IsNamespaceNotSupportedError(err) {
			slog.Error("namespaces not supported (Vault OSS detected)", "namespace", namespacePath)
			stats.IncNamespacesFailed()
			return FormatOSSNamespaceError()
		}

		// Check for permission errors
		if IsPermissionDeniedError(err) {
			slog.Error("permission denied creating namespace", "namespace", namespacePath)
			stats.IncNamespacesFailed()
			return fmt.Errorf("permission denied: %w", err)
		}

		// Other error
		slog.Error("failed to create namespace", "namespace", namespacePath, "error", err)
		stats.IncNamespacesFailed()
		return fmt.Errorf("failed to create namespace %q: %w", namespacePath, err)
	}

	slog.Info("namespace created successfully", "namespace", namespacePath)
	stats.IncNamespacesCreated()
	return nil
}

// CreateNamespaces creates child namespaces for load generation
func CreateNamespaces(ctx context.Context, cfg *config.Config) ([]string, error) {
	// Validate config
	if cfg.Namespaces < 1 {
		return nil, fmt.Errorf("namespace count must be at least 1, got %d", cfg.Namespaces)
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

	// Validate parent namespace if specified
	if cfg.ParentNamespace != "" {
		if err := client.ValidateNamespace(vaultClient, cfg.ParentNamespace); err != nil {
			slog.Warn("parent namespace validation failed", "namespace", cfg.ParentNamespace, "error", err)
			// Don't fail - parent namespace might not be readable but still usable
		}
	}

	// Generate namespace names
	namespaceNames := GenerateNamespaceNames(cfg.ParentNamespace, cfg.Namespaces)

	// Create statistics tracker
	st := stats.New()

	// Create namespaces
	namespacePaths := make([]string, 0, cfg.Namespaces)

	slog.Info("creating namespaces", "count", cfg.Namespaces, "parent", cfg.ParentNamespace)

	for _, name := range namespaceNames {
		// Check context cancellation
		select {
		case <-ctx.Done():
			slog.Info("namespace creation cancelled by context")
			return namespacePaths, ctx.Err()
		default:
		}

		// Build full path
		fullPath := BuildFullNamespacePath(cfg.ParentNamespace, name)

		// Create namespace
		if err := CreateNamespace(ctx, vaultClient, fullPath, st); err != nil {
			// Check if this is an OSS error - fail fast instead of continuing
			if IsNamespaceNotSupportedError(err) {
				return nil, err
			}

			// Log error but continue with other namespaces
			slog.Warn("error creating namespace, continuing", "namespace", fullPath, "error", err)
			continue
		}

		namespacePaths = append(namespacePaths, fullPath)
	}

	st.End()

	// Log summary
	slog.Info("namespace creation complete",
		"created", st.NamespacesCreated,
		"skipped", st.NamespacesSkipped,
		"failed", st.NamespacesFailed,
		"duration", st.Duration())

	// Return created namespaces (including skipped ones that already existed)
	// But only return the ones that were successfully processed
	if len(namespacePaths) == 0 && st.NamespacesFailed > 0 {
		return nil, fmt.Errorf("failed to create any namespaces: %d failures", st.NamespacesFailed)
	}

	return namespacePaths, nil
}
