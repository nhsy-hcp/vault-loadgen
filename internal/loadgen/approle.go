package loadgen

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// AppRoleWorker implements the Worker interface for AppRole authentication.
type AppRoleWorker struct {
	client  *api.Client
	cfg     *config.Config
	stats   *stats.Stats
	limiter *ratelimit.Limiter
}

// NewAppRoleWorker creates a new AppRole worker.
func NewAppRoleWorker(wcfg *WorkerConfig) *AppRoleWorker {
	return &AppRoleWorker{
		client:  wcfg.VaultClient,
		cfg:     wcfg.Config,
		stats:   wcfg.Stats,
		limiter: wcfg.RateLimiter,
	}
}

// Setup prepares the AppRole auth method and KV engine in the given namespace.
func (w *AppRoleWorker) Setup(ctx context.Context, namespace string) error {
	if err := setupAppRoleAuth(ctx, w.client, namespace, w.cfg, w.stats); err != nil {
		return err
	}
	return setupAppRoleKVEngine(ctx, w.client, namespace, w.stats)
}

// Execute performs a single AppRole login and authenticated read.
func (w *AppRoleWorker) Execute(ctx context.Context, namespace string, workIndex int) error {
	roleName := fmt.Sprintf("loadtest-%d", workIndex)

	if err := generateAppRoleLogin(ctx, w.client, namespace, roleName, w.cfg, w.stats); err != nil {
		slog.Warn("failed to generate AppRole login", "namespace", namespace, "role", roleName, "error", err)
		w.stats.IncLeasesFailed()
		return nil // Don't stop other workers
	}

	w.stats.IncLeasesCreated()
	return nil
}

// Cleanup performs any necessary cleanup (currently none needed for AppRole).
func (w *AppRoleWorker) Cleanup(ctx context.Context, namespace string) error {
	return nil
}

// GetStats returns the worker's statistics.
func (w *AppRoleWorker) GetStats() *stats.Stats {
	return w.stats
}

// GenerateAppRoleLoad generates AppRole authentication token leases for load testing
// Works in both multi-namespace mode (distributes across namespaces) and single-namespace mode
func GenerateAppRoleLoad(ctx context.Context, cfg *config.Config) (*stats.Stats, error) {
	// Validate config
	if cfg.AppRoleLogins < 1 {
		return nil, fmt.Errorf("approle-logins must be at least 1, got %d", cfg.AppRoleLogins)
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
	worker := NewAppRoleWorker(&WorkerConfig{
		VaultClient: vaultClient,
		Config:      cfg,
		RateLimiter: limiter,
		Stats:       st,
	})

	// Setup AppRole auth and KV engines in each namespace
	slog.Info("approle mode: setting up AppRole auth methods and KV engines", "namespaces", len(namespaces))
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		if err := worker.Setup(ctx, ns); err != nil {
			slog.Error("failed to setup AppRole auth", "namespace", ns, "error", err)
			return st, fmt.Errorf("failed to setup AppRole auth in namespace %q: %w", ns, err)
		}
		slog.Debug("approle auth and KV engine setup complete", "namespace", ns)
	}

	// Generate logins using worker pool
	slog.Info("approle mode: generating token leases",
		"total_logins", cfg.AppRoleLogins,
		"namespaces", len(namespaces))

	if err := RunWorkerPool(ctx, worker, namespaces, cfg.AppRoleLogins, cfg.Workers, limiter); err != nil {
		return st, err
	}

	st.End()

	// Log summary
	slog.Info("approle mode complete",
		"logins_created", st.LeasesCreated,
		"logins_failed", st.LeasesFailed,
		"reads_succeeded", st.AuthenticatedReadsSucceeded,
		"reads_failed", st.AuthenticatedReadsFailed,
		"duration", st.Duration(),
		"leases_per_sec", st.LeasesPerSecond(),
		"reads_per_sec", st.AuthenticatedReadsPerSecond())

	return st, nil
}

// setupAppRoleAuth enables and configures AppRole auth method in the given namespace
func setupAppRoleAuth(ctx context.Context, vaultClient *api.Client, namespace string, cfg *config.Config, st *stats.Stats) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
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
			st.IncAuthMethodsSkipped()
			// Continue to policy setup even if auth already exists
		} else {
			st.IncAuthMethodsFailed()
			return fmt.Errorf("failed to enable approle auth: %w", err)
		}
	} else {
		st.IncAuthMethodsEnabled()
	}

	// Create a policy for KV read access
	policyName := "loadtest-kv-read"
	policyRules := `
path "loadtest-kv/data/dummy" {
  capabilities = ["read"]
}
`
	err = nsClient.Sys().PutPolicy(policyName, policyRules)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Note: Individual AppRole roles are created on-demand during worker execution
	// This allows for parallel role creation and unique role per login for accurate client counting

	return nil
}

// setupAppRoleKVEngine enables a KV v2 engine and creates a dummy secret for authenticated testing
func setupAppRoleKVEngine(ctx context.Context, vaultClient *api.Client, namespace string, st *stats.Stats) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
	}

	// Enable KV v2 secrets engine
	enginePath := "loadtest-kv"
	mountInput := &api.MountInput{
		Type: "kv-v2",
		Options: map[string]string{
			"version": "2",
		},
	}

	err = nsClient.Sys().Mount(enginePath, mountInput)
	if err != nil {
		// Check if already mounted
		if strings.Contains(err.Error(), "path is already in use") {
			slog.Debug("kv engine already mounted", "namespace", namespace, "engine", enginePath)
			st.IncKVEnginesSkipped()
			// Don't fail - secret might already exist
		} else {
			st.IncKVEnginesFailed()
			return fmt.Errorf("failed to mount kv engine: %w", err)
		}
	} else {
		st.IncKVEnginesEnabled()
	}

	// Create dummy secret for authenticated read testing
	secretPath := enginePath + "/data/dummy"
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"value":     "loadtest-dummy-secret",
			"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
		},
	}

	_, err = nsClient.Logical().Write(secretPath, secretData)
	if err != nil {
		return fmt.Errorf("failed to create dummy secret: %w", err)
	}

	return nil
}

// createAppRoleRole creates an individual AppRole role with idempotent behavior
func createAppRoleRole(ctx context.Context, vaultClient *api.Client, namespace string, roleName string, cfg *config.Config, st *stats.Stats) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
	}

	authPath := "approle"
	policyName := "loadtest-kv-read"

	// Create AppRole role with shared policy
	roleData := map[string]interface{}{
		"token_ttl":          cfg.TokenTTL,
		"token_max_ttl":      cfg.TokenMaxTTL,
		"secret_id_ttl":      cfg.SecretIDTTL,
		"bind_secret_id":     true,
		"token_policies":     []string{"default", policyName},
		"secret_id_num_uses": 0, // Unlimited uses for load testing
	}

	_, err = nsClient.Logical().Write("auth/"+authPath+"/role/"+roleName, roleData)
	if err != nil {
		// Check if role already exists
		if strings.Contains(err.Error(), "role already exists") || strings.Contains(err.Error(), "already in use") {
			slog.Debug("approle role already exists", "namespace", namespace, "role", roleName)
			st.IncAppRoleRolesSkipped()
			return nil
		}
		st.IncAppRoleRolesFailed()
		return fmt.Errorf("failed to create approle role %q: %w", roleName, err)
	}

	st.IncAppRoleRolesCreated()
	slog.Debug("approle role created", "namespace", namespace, "role", roleName)
	return nil
}

// generateAppRoleLogin generates a token lease by performing an AppRole login
func generateAppRoleLogin(ctx context.Context, vaultClient *api.Client, namespace string, roleName string, cfg *config.Config, st *stats.Stats) error {
	// Create a client for this namespace
	nsClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		return err
	}

	// Create the AppRole role on-demand (idempotent)
	if err := createAppRoleRole(ctx, vaultClient, namespace, roleName, cfg, st); err != nil {
		return fmt.Errorf("failed to create approle role: %w", err)
	}

	authPath := "approle"

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

	// Perform authenticated read using the newly created token
	authenticatedClient, err := GetNamespacedClient(vaultClient, namespace)
	if err != nil {
		st.IncAuthenticatedReadsFailed()
		return fmt.Errorf("failed to create client for authenticated read: %w", err)
	}

	// Set the new token
	authenticatedClient.SetToken(loginResp.Auth.ClientToken)

	// Read the dummy secret
	secretPath := "loadtest-kv/data/dummy"
	secret, err := authenticatedClient.Logical().Read(secretPath)
	if err != nil {
		st.IncAuthenticatedReadsFailed()
		slog.Warn("authenticated read failed", "namespace", namespace, "error", err)
		return nil // Don't fail the entire operation, just track the failure
	}

	if secret == nil || secret.Data == nil {
		st.IncAuthenticatedReadsFailed()
		slog.Warn("authenticated read returned no data", "namespace", namespace)
		return nil
	}

	st.IncAuthenticatedReadsSucceeded()
	slog.Debug("authenticated read successful",
		"namespace", namespace,
		"secret_path", secretPath)

	return nil
}
