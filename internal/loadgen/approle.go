package loadgen

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/vault/api"
	"golang.org/x/sync/errgroup"

	"github.com/nhsy/vault-loadgen/internal/client"
	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// GenerateAppRoleLoad generates AppRole authentication token leases for load testing
// Works in both multi-namespace mode (distributes across namespaces) and single-namespace mode
func GenerateAppRoleLoad(ctx context.Context, cfg *config.Config) (*stats.Stats, error) {
	// Validate config
	if cfg.AppRoleLogins < 1 {
		return nil, fmt.Errorf("approle-logins must be at least 1, got %d", cfg.AppRoleLogins)
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
		slog.Info("approle mode: creating child namespaces", "count", cfg.Namespaces)
		createdNamespaces, err := CreateNamespaces(ctx, cfg)
		if err != nil {
			return st, fmt.Errorf("failed to create namespaces: %w", err)
		}
		namespaces = createdNamespaces
	} else {
		// Single-namespace mode: use parent namespace or root
		slog.Info("approle mode: using single-namespace mode", "namespace", cfg.ParentNamespace)
		namespaces = []string{cfg.ParentNamespace}
	}

	slog.Info("approle mode: setting up AppRole auth methods", "namespaces", len(namespaces))

	// Setup AppRole auth methods in each namespace
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		if err := setupAppRoleAuth(ctx, vaultClient, ns, cfg); err != nil {
			slog.Error("failed to setup AppRole auth", "namespace", ns, "error", err)
			return st, fmt.Errorf("failed to setup AppRole auth in namespace %q: %w", ns, err)
		}
		slog.Debug("approle auth setup complete", "namespace", ns)
	}

	// Calculate logins per namespace
	loginsPerNamespace := cfg.AppRoleLogins / len(namespaces)
	remainder := cfg.AppRoleLogins % len(namespaces)

	slog.Info("approle mode: generating token leases",
		"total_logins", cfg.AppRoleLogins,
		"namespaces", len(namespaces),
		"logins_per_namespace", loginsPerNamespace)

	// Create rate limiter
	limiter := ratelimit.New(cfg.RateLimit)
	if cfg.RateLimit > 0 {
		slog.Info("rate limiting enabled", "ops_per_second", cfg.RateLimit)
	}

	// Generate token leases using worker pool
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.Workers)

	for nsIndex, ns := range namespaces {
		// Calculate logins for this namespace
		loginsForNS := loginsPerNamespace
		if nsIndex < remainder {
			loginsForNS++ // Distribute remainder across first namespaces
		}

		// Generate logins for this namespace
		for i := 0; i < loginsForNS; i++ {
			ns := ns // Capture for goroutine

			g.Go(func() error {
				// Wait for rate limiter
				if err := limiter.Wait(ctx); err != nil {
					return err
				}

				if err := ctx.Err(); err != nil {
					return err
				}

				if err := generateAppRoleLogin(ctx, vaultClient, ns); err != nil {
					slog.Warn("failed to generate AppRole login", "namespace", ns, "error", err)
					st.IncLeasesFailed()
					return nil // Don't stop other workers
				}

				st.IncLeasesCreated()
				return nil
			})
		}
	}

	// Wait for all workers
	if err := g.Wait(); err != nil {
		return st, err
	}

	st.End()

	// Log summary
	slog.Info("approle mode complete",
		"created", st.LeasesCreated,
		"failed", st.LeasesFailed,
		"duration", st.Duration(),
		"leases_per_sec", st.LeasesPerSecond())

	return st, nil
}

// setupAppRoleAuth enables and configures AppRole auth method in the given namespace
func setupAppRoleAuth(ctx context.Context, vaultClient *api.Client, namespace string, cfg *config.Config) error {
	// Create a client for this namespace
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	// Enable AppRole auth method
	authPath := "approle"
	mountInput := &api.MountInput{
		Type: "approle",
	}

	err = nsClient.Sys().EnableAuthWithOptions(authPath, mountInput)
	if err != nil {
		// Check if already mounted
		if strings.Contains(err.Error(), "path is already in use") {
			slog.Debug("approle auth already enabled", "namespace", namespace, "path", authPath)
		} else {
			return fmt.Errorf("failed to enable approle auth: %w", err)
		}
	}

	// Create AppRole role
	roleName := "loadtest"
	roleData := map[string]interface{}{
		"token_ttl":          cfg.TokenTTL,
		"token_max_ttl":      cfg.TokenMaxTTL,
		"secret_id_ttl":      cfg.SecretIDTTL,
		"bind_secret_id":     true,
		"token_policies":     []string{"default"},
		"secret_id_num_uses": 0, // Unlimited uses for load testing
	}

	_, err = nsClient.Logical().Write("auth/"+authPath+"/role/"+roleName, roleData)
	if err != nil {
		return fmt.Errorf("failed to create approle role: %w", err)
	}

	return nil
}

// generateAppRoleLogin generates a token lease by performing an AppRole login
func generateAppRoleLogin(ctx context.Context, vaultClient *api.Client, namespace string) error {
	// Create a client for this namespace
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	authPath := "approle"
	roleName := "loadtest"

	// Get role ID
	roleIDPath := "auth/" + authPath + "/role/" + roleName + "/role-id"
	roleIDResp, err := nsClient.Logical().Read(roleIDPath)
	if err != nil {
		return fmt.Errorf("failed to read role ID: %w", err)
	}
	if roleIDResp == nil || roleIDResp.Data["role_id"] == nil {
		return fmt.Errorf("no role ID returned")
	}
	roleID := roleIDResp.Data["role_id"].(string)

	// Generate secret ID
	secretIDPath := "auth/" + authPath + "/role/" + roleName + "/secret-id"
	secretIDResp, err := nsClient.Logical().Write(secretIDPath, nil)
	if err != nil {
		return fmt.Errorf("failed to generate secret ID: %w", err)
	}
	if secretIDResp == nil || secretIDResp.Data["secret_id"] == nil {
		return fmt.Errorf("no secret ID returned")
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	// Perform login
	loginPath := "auth/" + authPath + "/login"
	loginData := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	loginResp, err := nsClient.Logical().Write(loginPath, loginData)
	if err != nil {
		return fmt.Errorf("failed to login with approle: %w", err)
	}

	if loginResp == nil || loginResp.Auth == nil {
		return fmt.Errorf("no auth info returned from login")
	}

	slog.Debug("approle login successful",
		"namespace", namespace,
		"lease_id", loginResp.Auth.ClientToken,
		"lease_duration", loginResp.Auth.LeaseDuration)

	return nil
}
