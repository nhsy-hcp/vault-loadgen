package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/nhsy/vault-loadgen/internal/config"

	"github.com/hashicorp/vault/api"
)

// NewClient creates a new Vault client from configuration
func NewClient(cfg *config.Config) (*api.Client, error) {
	// Validate vault address
	if err := validateVaultAddr(cfg.VaultAddr); err != nil {
		return nil, fmt.Errorf("invalid vault address: %w", err)
	}

	// Create default client config
	clientCfg := api.DefaultConfig()
	clientCfg.Address = cfg.VaultAddr

	// Configure TLS
	if err := configureTLS(clientCfg, cfg); err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}

	// Create client
	client, err := api.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set token
	client.SetToken(cfg.VaultToken)

	// Set namespace if provided
	if cfg.ParentNamespace != "" {
		client.SetNamespace(cfg.ParentNamespace)
		slog.Debug("set vault namespace", "namespace", cfg.ParentNamespace)
	}

	return client, nil
}

// ValidateConnection verifies successful connection to Vault
func ValidateConnection(client *api.Client) error {
	// Check if Vault is reachable and initialized
	health, err := client.Sys().Health()
	if err != nil {
		return fmt.Errorf("failed to connect to vault: %w", err)
	}

	if health == nil {
		return errors.New("vault health check returned nil response")
	}

	// Check if Vault is sealed
	if health.Sealed {
		return errors.New("vault is sealed and cannot accept requests")
	}

	// Check if Vault is initialized
	if !health.Initialized {
		return errors.New("vault is not initialized")
	}

	slog.Debug("vault connection validated successfully",
		"version", health.Version,
		"cluster_name", health.ClusterName)

	return nil
}

// validateVaultAddr validates the Vault address format
func validateVaultAddr(addr string) error {
	if addr == "" {
		return errors.New("vault address cannot be empty")
	}

	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return errors.New("vault address must start with http:// or https://")
	}

	return nil
}

// configureTLS configures TLS settings for the Vault client
func configureTLS(clientCfg *api.Config, cfg *config.Config) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Skip TLS verification if requested
	if cfg.VaultSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		slog.Warn("TLS certificate verification is DISABLED - insecure for production use")
	}

	// Load CA certificate if provided
	if cfg.VaultCACert != "" {
		if err := loadCACert(tlsConfig, cfg.VaultCACert); err != nil {
			return err
		}
	}

	// Set TLS config
	clientCfg.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return nil
}

// loadCACert loads a CA certificate file into the TLS config
func loadCACert(tlsConfig *tls.Config, certPath string) error {
	// Check if file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate file not found: %s", certPath)
	}

	// Read certificate
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create cert pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return errors.New("failed to parse CA certificate")
	}

	tlsConfig.RootCAs = caCertPool
	slog.Debug("loaded CA certificate", "path", certPath)

	return nil
}

// BuildNamespacePath constructs a namespace path from parent and child
func BuildNamespacePath(parent, child string) string {
	// Trim slashes
	parent = strings.Trim(parent, "/")
	child = strings.Trim(child, "/")

	if parent == "" {
		return child
	}

	return parent + "/" + child
}

// ValidateAuth validates that the client can authenticate to Vault
func ValidateAuth(client *api.Client) error {
	// Try to look up the token
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if secret == nil {
		return errors.New("authentication failed: no token info returned")
	}

	slog.Debug("authentication validated successfully")
	return nil
}

// ValidateNamespace validates that a namespace exists
func ValidateNamespace(client *api.Client, namespace string) error {
	if namespace == "" {
		// Root namespace always exists
		return nil
	}

	// Try to read namespace
	path := fmt.Sprintf("sys/namespaces/%s", namespace)
	secret, err := client.Logical().Read(path)

	if err != nil {
		return fmt.Errorf("failed to validate namespace %q: %w", namespace, err)
	}

	if secret == nil {
		return fmt.Errorf("namespace %q does not exist", namespace)
	}

	slog.Debug("namespace validated successfully", "namespace", namespace)
	return nil
}
