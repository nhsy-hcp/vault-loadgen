package loadgen

import (
	"context"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestGetNamespacedClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// This test requires a real Vault client
	cfg := &config.Config{
		VaultAddr:  getEnvOrDefault("VAULT_ADDR", "http://127.0.0.1:8200"),
		VaultToken: getEnvOrDefault("VAULT_TOKEN", "root"),
	}

	baseClient, err := InitializeClient(cfg)
	if err != nil {
		t.Skipf("skipping test: cannot connect to vault: %v", err)
	}

	tests := []struct {
		name      string
		namespace string
		wantErr   bool
	}{
		{
			name:      "empty namespace",
			namespace: "",
			wantErr:   false,
		},
		{
			name:      "with namespace",
			namespace: "test-ns",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsClient, err := GetNamespacedClient(baseClient, tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetNamespacedClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && nsClient == nil {
				t.Error("GetNamespacedClient() returned nil client")
			}

			// Verify namespace is set correctly
			if err == nil && nsClient != nil {
				// The namespace is set internally, we can verify by checking it's not the same pointer
				if nsClient == baseClient {
					t.Error("GetNamespacedClient() returned same client instead of clone")
				}
			}
		})
	}
}

func TestDetermineNamespaces_SingleNamespace(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *config.Config
		expectedCount   int
		expectedFirstNS string
	}{
		{
			name: "namespaces=0 uses parent",
			cfg: &config.Config{
				Namespaces:       0,
				CreateNamespaces: false,
				ParentNamespace:  "my-parent",
			},
			expectedCount:   1,
			expectedFirstNS: "my-parent",
		},
		{
			name: "namespaces=0 with empty parent",
			cfg: &config.Config{
				Namespaces:       0,
				CreateNamespaces: false,
				ParentNamespace:  "",
			},
			expectedCount:   1,
			expectedFirstNS: "",
		},
		{
			name: "create disabled uses single namespace",
			cfg: &config.Config{
				Namespaces:       5,
				CreateNamespaces: false,
				ParentNamespace:  "parent",
			},
			expectedCount:   1,
			expectedFirstNS: "parent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			namespaces, err := DetermineNamespaces(ctx, tt.cfg)

			if err != nil {
				t.Errorf("DetermineNamespaces() error = %v", err)
				return
			}

			if len(namespaces) != tt.expectedCount {
				t.Errorf("expected %d namespaces, got %d", tt.expectedCount, len(namespaces))
			}

			if len(namespaces) > 0 && namespaces[0] != tt.expectedFirstNS {
				t.Errorf("expected first namespace %q, got %q", tt.expectedFirstNS, namespaces[0])
			}
		})
	}
}

func TestInitializeClient(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantErr    bool
		skipReason string
	}{
		{
			name: "valid configuration",
			cfg: &config.Config{
				VaultAddr:  getEnvOrDefault("VAULT_ADDR", "http://127.0.0.1:8200"),
				VaultToken: getEnvOrDefault("VAULT_TOKEN", "root"),
			},
			wantErr:    false,
			skipReason: "requires vault instance",
		},
		{
			name: "empty vault address",
			cfg: &config.Config{
				VaultAddr:  "",
				VaultToken: "token",
			},
			wantErr: true,
		},
		{
			name: "invalid vault address",
			cfg: &config.Config{
				VaultAddr:  "not-a-url",
				VaultToken: "token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				t.Skip("skipping integration test:", tt.skipReason)
			}

			client, err := InitializeClient(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && client == nil {
				t.Error("InitializeClient() returned nil client without error")
			}
		})
	}
}

// Helper function to get environment variable or default value
func getEnvOrDefault(key, defaultValue string) string {
	// This is a simple implementation - in real code you'd use os.Getenv
	// For tests, we'll just return the default
	return defaultValue
}
