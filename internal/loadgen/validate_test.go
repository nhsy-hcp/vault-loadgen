package loadgen

import (
	"context"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

func TestValidateLoad_PKI(t *testing.T) {
	tests := []struct {
		name           string
		expectedLeases int
		createdLeases  int64
		failedLeases   int64
		expectSuccess  bool
	}{
		{
			name:           "all leases created",
			expectedLeases: 100,
			createdLeases:  100,
			failedLeases:   0,
			expectSuccess:  true,
		},
		{
			name:           "some leases failed",
			expectedLeases: 100,
			createdLeases:  90,
			failedLeases:   10,
			expectSuccess:  false,
		},
		{
			name:           "no leases created",
			expectedLeases: 100,
			createdLeases:  0,
			failedLeases:   100,
			expectSuccess:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Mode:      "pki",
				PKILeases: tt.expectedLeases,
			}

			st := &stats.Stats{
				LeasesCreated: tt.createdLeases,
				LeasesFailed:  tt.failedLeases,
			}

			ctx := context.Background()
			result, err := ValidateLoad(ctx, cfg, st)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Expected != tt.expectedLeases {
				t.Errorf("expected %d leases, got %d", tt.expectedLeases, result.Expected)
			}

			if result.Actual != int(tt.createdLeases) {
				t.Errorf("expected %d actual leases, got %d", tt.createdLeases, result.Actual)
			}

			if result.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got %v", tt.expectSuccess, result.Success)
			}

			if result.Message == "" {
				t.Error("expected non-empty message")
			}
		})
	}
}

func TestValidateLoad_AppRole(t *testing.T) {
	tests := []struct {
		name           string
		expectedLogins int
		createdLeases  int64
		failedLeases   int64
		expectSuccess  bool
	}{
		{
			name:           "all logins successful",
			expectedLogins: 50,
			createdLeases:  50,
			failedLeases:   0,
			expectSuccess:  true,
		},
		{
			name:           "some logins failed",
			expectedLogins: 50,
			createdLeases:  45,
			failedLeases:   5,
			expectSuccess:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Mode:          "approle",
				AppRoleLogins: tt.expectedLogins,
			}

			st := &stats.Stats{
				LeasesCreated: tt.createdLeases,
				LeasesFailed:  tt.failedLeases,
			}

			ctx := context.Background()
			result, err := ValidateLoad(ctx, cfg, st)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Expected != tt.expectedLogins {
				t.Errorf("expected %d logins, got %d", tt.expectedLogins, result.Expected)
			}

			if result.Actual != int(tt.createdLeases) {
				t.Errorf("expected %d actual leases, got %d", tt.createdLeases, result.Actual)
			}

			if result.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got %v", tt.expectSuccess, result.Success)
			}
		})
	}
}

func TestValidateLoad_KV(t *testing.T) {
	tests := []struct {
		name             string
		namespaces       int
		createNamespaces bool
		kvEngines        int
		secretsPerEngine int
		createdSecrets   int64
		failedSecrets    int64
		expectSuccess    bool
	}{
		{
			name:             "single namespace - all secrets created",
			namespaces:       0,
			createNamespaces: false,
			kvEngines:        5,
			secretsPerEngine: 100,
			createdSecrets:   500, // 1 namespace * 5 engines * 100 secrets
			failedSecrets:    0,
			expectSuccess:    true,
		},
		{
			name:             "multi namespace - all secrets created",
			namespaces:       3,
			createNamespaces: true,
			kvEngines:        2,
			secretsPerEngine: 10,
			createdSecrets:   60, // 3 namespaces * 2 engines * 10 secrets
			failedSecrets:    0,
			expectSuccess:    true,
		},
		{
			name:             "some secrets failed",
			namespaces:       0,
			createNamespaces: false,
			kvEngines:        1,
			secretsPerEngine: 100,
			createdSecrets:   90,
			failedSecrets:    10,
			expectSuccess:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Mode:             "kv",
				Namespaces:       tt.namespaces,
				CreateNamespaces: tt.createNamespaces,
				KVEngines:        tt.kvEngines,
				SecretsPerEngine: tt.secretsPerEngine,
			}

			st := &stats.Stats{
				SecretsCreated: tt.createdSecrets,
				SecretsFailed:  tt.failedSecrets,
			}

			ctx := context.Background()
			result, err := ValidateLoad(ctx, cfg, st)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedTotal := len(getNamespaces(cfg)) * tt.kvEngines * tt.secretsPerEngine
			if result.Expected != expectedTotal {
				t.Errorf("expected %d secrets, got %d", expectedTotal, result.Expected)
			}

			if result.Actual != int(tt.createdSecrets) {
				t.Errorf("expected %d actual secrets, got %d", tt.createdSecrets, result.Actual)
			}

			if result.Success != tt.expectSuccess {
				t.Errorf("expected success=%v, got %v", tt.expectSuccess, result.Success)
			}
		})
	}
}

func TestValidateLoad_UnknownMode(t *testing.T) {
	cfg := &config.Config{
		Mode: "invalid",
	}

	st := &stats.Stats{}

	ctx := context.Background()
	_, err := ValidateLoad(ctx, cfg, st)
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
}

func TestGetNamespaces(t *testing.T) {
	tests := []struct {
		name             string
		namespaces       int
		createNamespaces bool
		expectedCount    int
	}{
		{
			name:             "single namespace mode",
			namespaces:       0,
			createNamespaces: false,
			expectedCount:    1,
		},
		{
			name:             "multi namespace mode",
			namespaces:       5,
			createNamespaces: true,
			expectedCount:    5,
		},
		{
			name:             "namespace creation disabled",
			namespaces:       10,
			createNamespaces: false,
			expectedCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Namespaces:       tt.namespaces,
				CreateNamespaces: tt.createNamespaces,
			}

			namespaces := getNamespaces(cfg)
			if len(namespaces) != tt.expectedCount {
				t.Errorf("expected %d namespaces, got %d", tt.expectedCount, len(namespaces))
			}
		})
	}
}
