package loadgen

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/vault/api"

	"vault-loadgen/internal/config"
	"vault-loadgen/internal/stats"
)

// ValidateResults holds validation results
type ValidateResults struct {
	Expected int
	Actual   int
	Success  bool
	Message  string
}

// ValidateLoad performs post-generation validation
// Verifies that the expected number of operations completed successfully
func ValidateLoad(ctx context.Context, cfg *config.Config, st *stats.Stats) (*ValidateResults, error) {
	result := &ValidateResults{}

	switch cfg.Mode {
	case "pki":
		result.Expected = cfg.PKILeases
		result.Actual = int(st.LeasesCreated)
		result.Success = result.Actual == result.Expected

		if result.Success {
			result.Message = fmt.Sprintf("PKI validation passed: %d/%d leases created", result.Actual, result.Expected)
		} else {
			result.Message = fmt.Sprintf("PKI validation failed: %d/%d leases created (%d failed)",
				result.Actual, result.Expected, st.LeasesFailed)
		}

	case "approle":
		result.Expected = cfg.AppRoleLogins
		result.Actual = int(st.LeasesCreated)
		result.Success = result.Actual == result.Expected

		if result.Success {
			result.Message = fmt.Sprintf("AppRole validation passed: %d/%d token leases created", result.Actual, result.Expected)
		} else {
			result.Message = fmt.Sprintf("AppRole validation failed: %d/%d token leases created (%d failed)",
				result.Actual, result.Expected, st.LeasesFailed)
		}

	case "kv":
		totalExpected := len(getNamespaces(cfg)) * cfg.KVEngines * cfg.SecretsPerEngine
		result.Expected = totalExpected
		result.Actual = int(st.SecretsCreated)
		result.Success = result.Actual == result.Expected

		if result.Success {
			result.Message = fmt.Sprintf("KV validation passed: %d/%d secrets created", result.Actual, result.Expected)
		} else {
			result.Message = fmt.Sprintf("KV validation failed: %d/%d secrets created (%d failed)",
				result.Actual, result.Expected, st.SecretsFailed)
		}

	default:
		return nil, fmt.Errorf("unknown mode: %s", cfg.Mode)
	}

	// Log validation results
	if result.Success {
		slog.Info("validation passed", "mode", cfg.Mode, "expected", result.Expected, "actual", result.Actual)
	} else {
		slog.Warn("validation failed", "mode", cfg.Mode, "expected", result.Expected, "actual", result.Actual)
	}

	return result, nil
}

// ValidateNamespace validates resources in a specific namespace
// This is a more detailed validation that queries Vault to verify resources exist
func ValidateNamespace(ctx context.Context, client *api.Client, namespace string, mode string) error {
	// Create namespace-scoped client
	nsClient, err := client.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	switch mode {
	case "pki":
		// Verify PKI mount exists
		mounts, err := nsClient.Sys().ListMounts()
		if err != nil {
			return fmt.Errorf("failed to list mounts in namespace %q: %w", namespace, err)
		}

		if _, exists := mounts["pki/"]; !exists {
			return fmt.Errorf("PKI mount not found in namespace %q", namespace)
		}

		slog.Debug("pki mount validated", "namespace", namespace)
		return nil

	case "approle":
		// Verify AppRole auth method exists
		auths, err := nsClient.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("failed to list auth methods in namespace %q: %w", namespace, err)
		}

		if _, exists := auths["approle/"]; !exists {
			return fmt.Errorf("AppRole auth method not found in namespace %q", namespace)
		}

		slog.Debug("approle auth validated", "namespace", namespace)
		return nil

	case "kv":
		// Verify at least one KV mount exists
		mounts, err := nsClient.Sys().ListMounts()
		if err != nil {
			return fmt.Errorf("failed to list mounts in namespace %q: %w", namespace, err)
		}

		kvFound := false
		for path := range mounts {
			if mounts[path].Type == "kv" {
				kvFound = true
				break
			}
		}

		if !kvFound {
			return fmt.Errorf("no KV mounts found in namespace %q", namespace)
		}

		slog.Debug("kv mounts validated", "namespace", namespace)
		return nil

	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}

// getNamespaces returns the list of namespaces that will be used
// Helper function to calculate expected resources
func getNamespaces(cfg *config.Config) []string {
	if cfg.CreateNamespaces && cfg.Namespaces > 0 {
		// Multi-namespace mode
		return make([]string, cfg.Namespaces)
	}
	// Single-namespace mode
	return []string{cfg.ParentNamespace}
}
