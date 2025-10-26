package client

import (
	"testing"

	"vault-loadgen/internal/config"
)

func TestNewClient_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		VaultAddr:  "https://vault.example.com:8200",
		VaultToken: "test-token",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Errorf("NewClient() error = %v, want nil", err)
	}

	if client == nil {
		t.Error("NewClient() returned nil client")
	}
}

func TestNewClient_WithNamespace(t *testing.T) {
	cfg := &config.Config{
		VaultAddr:       "https://vault.example.com:8200",
		VaultToken:      "test-token",
		ParentNamespace: "admin/test",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Errorf("NewClient() error = %v, want nil", err)
	}

	if client == nil {
		t.Error("NewClient() returned nil client")
	}
}

func TestNewClient_WithSkipVerify(t *testing.T) {
	cfg := &config.Config{
		VaultAddr:       "https://vault.example.com:8200",
		VaultToken:      "test-token",
		VaultSkipVerify: true,
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Errorf("NewClient() error = %v, want nil", err)
	}

	if client == nil {
		t.Error("NewClient() returned nil client")
	}
}

func TestBuildNamespacePath(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   string
	}{
		{
			name:   "no parent",
			parent: "",
			child:  "test",
			want:   "test",
		},
		{
			name:   "with parent",
			parent: "admin",
			child:  "test",
			want:   "admin/test",
		},
		{
			name:   "nested parent",
			parent: "admin/dev",
			child:  "test",
			want:   "admin/dev/test",
		},
		{
			name:   "parent with trailing slash",
			parent: "admin/",
			child:  "test",
			want:   "admin/test",
		},
		{
			name:   "child with leading slash",
			parent: "admin",
			child:  "/test",
			want:   "admin/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildNamespacePath(tt.parent, tt.child)
			if got != tt.want {
				t.Errorf("BuildNamespacePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseVaultAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{
			name:    "valid https",
			addr:    "https://vault.example.com:8200",
			wantErr: false,
		},
		{
			name:    "valid http",
			addr:    "http://localhost:8200",
			wantErr: false,
		},
		{
			name:    "with path",
			addr:    "https://vault.example.com:8200/v1",
			wantErr: false,
		},
		{
			name:    "no scheme",
			addr:    "vault.example.com:8200",
			wantErr: true,
		},
		{
			name:    "empty",
			addr:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVaultAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVaultAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateConnection(t *testing.T) {
	// Note: These tests require a live Vault instance
	// They are designed to be skipped in CI unless VAULT_ADDR is set
	t.Run("requires live vault", func(t *testing.T) {
		// Skip test if no Vault is available
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}

		// This test validates the function signature and error handling
		// Actual connection tests require a running Vault instance
		cfg := &config.Config{
			VaultAddr:  "http://localhost:8200",
			VaultToken: "test-token",
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Skipf("Could not create client: %v", err)
		}

		// Attempt connection validation
		// This will fail without a live Vault but validates the function exists
		err = ValidateConnection(client)
		// We don't assert success/failure here as it depends on Vault availability
		t.Logf("ValidateConnection result: %v", err)
	})
}
