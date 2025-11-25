package config

import (
	"errors"
	"fmt"
	"log/slog"
)

// Constants for validation limits
const (
	MaxWorkers    = 32
	MaxNamespaces = 1000
)

// Config holds all configuration for the vault load test tool
type Config struct {
	// Vault connection settings
	VaultAddr       string
	VaultToken      string
	VaultCACert     string
	VaultSkipVerify bool
	ParentNamespace string

	// Configuration file
	ConfigFile string

	// Global settings
	Workers    int
	Namespaces int
	LogLevel   string
	RateLimit  float64
	DryRun     bool
	Output     string
	Progress   bool

	// Mode
	Mode string

	// PKI mode settings
	PKILeases     int
	PKITTL        string
	PKIRootCATTL  string // ROOT CA TTL (default: 7 days)
	PKIKeySize    int
	PKICommonName string

	// AppRole mode settings
	AppRoleLogins int
	SecretIDTTL   string
	TokenTTL      string
	TokenMaxTTL   string

	// KV mode settings
	KVEngines        int
	SecretsPerEngine int
	SecretSize       int
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errs []error

	// Required fields
	if c.VaultAddr == "" {
		errs = append(errs, errors.New("vault address is required"))
	}
	if c.VaultToken == "" {
		errs = append(errs, errors.New("vault token is required"))
	}

	// Range validation
	if c.Workers < 1 || c.Workers > MaxWorkers {
		errs = append(errs, fmt.Errorf("workers must be between 1 and %d", MaxWorkers))
	}
	if c.Namespaces < 0 || c.Namespaces > MaxNamespaces {
		errs = append(errs, fmt.Errorf("namespaces must be between 0 and %d", MaxNamespaces))
	}

	// Namespace mode validation
	if c.Namespaces == 0 {
		slog.Info("single-namespace mode enabled (namespaces=0)")
	} else {
		slog.Info("multi-namespace mode enabled", "namespaces", c.Namespaces)
	}

	// Mode-specific validation
	switch c.Mode {
	case "pki":
		if c.PKILeases < 1 {
			errs = append(errs, errors.New("pki-leases must be >= 1"))
		}
		if c.PKIKeySize != 2048 && c.PKIKeySize != 4096 {
			errs = append(errs, errors.New("pki-key-size must be 2048 or 4096"))
		}
	case "approle":
		if c.AppRoleLogins < 1 {
			errs = append(errs, errors.New("approle-logins must be >= 1"))
		}
	case "kv":
		if c.SecretsPerEngine < 1 {
			errs = append(errs, errors.New("secrets-per-engine must be >= 1"))
		}
	}

	// Security validation
	if c.VaultSkipVerify {
		slog.Warn("TLS verification disabled - insecure for production")
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

// NewDefault returns a Config with default values
func NewDefault() *Config {
	return &Config{
		Workers:          4,
		Namespaces:       0, // 0 = single-namespace mode (Vault OSS compatible)
		LogLevel:         "info",
		Output:           "text",
		Progress:         true,
		PKILeases:        100,
		PKIKeySize:       2048,
		PKITTL:           "24h",
		PKIRootCATTL:     "168h", // 7 days as per requirements
		AppRoleLogins:    100,
		SecretIDTTL:      "1h",
		TokenTTL:         "1h",
		TokenMaxTTL:      "2h",
		KVEngines:        1,
		SecretsPerEngine: 100,
		SecretSize:       5,
		PKICommonName:    "loadtest-{index}.example.com",
	}
}
