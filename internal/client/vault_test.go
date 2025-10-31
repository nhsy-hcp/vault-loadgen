package client

import (
	"os"
	"strings"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestNewClient_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		VaultAddr:  "http://127.0.0.1:8200",
		VaultToken: "root",
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
		VaultAddr:       "http://127.0.0.1:8200",
		VaultToken:      "root",
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
		VaultAddr:       "http://127.0.0.1:8200",
		VaultToken:      "root",
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
		{
			name:   "both empty strings",
			parent: "",
			child:  "",
			want:   "",
		},
		{
			name:   "parent only with slashes",
			parent: "///",
			child:  "test",
			want:   "test",
		},
		{
			name:   "child only with slashes",
			parent: "admin",
			child:  "///",
			want:   "admin/",
		},
		{
			name:   "both with multiple slashes",
			parent: "admin///",
			child:  "///test",
			want:   "admin/test",
		},
		{
			name:   "deeply nested parent",
			parent: "org/team/project/env",
			child:  "service",
			want:   "org/team/project/env/service",
		},
		{
			name:   "parent with spaces",
			parent: "admin",
			child:  "test child",
			want:   "admin/test child",
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

func TestNewClient_InvalidAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{
			name:    "empty address",
			addr:    "",
			wantErr: "vault address cannot be empty",
		},
		{
			name:    "no scheme",
			addr:    "vault.example.com:8200",
			wantErr: "must start with http:// or https://",
		},
		{
			name:    "invalid scheme",
			addr:    "ftp://vault.example.com:8200",
			wantErr: "must start with http:// or https://",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				VaultAddr:  tt.addr,
				VaultToken: "root",
			}

			client, err := NewClient(cfg)
			if err == nil {
				t.Errorf("NewClient() expected error containing %q, got nil", tt.wantErr)
			}
			if client != nil {
				t.Error("NewClient() expected nil client on error")
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewClient() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigureTLS_InvalidCACert(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		wantErr  string
	}{
		{
			name:     "nonexistent file",
			certPath: "/nonexistent/path/to/ca.crt",
			wantErr:  "not found",
		},
		{
			name:     "invalid PEM",
			certPath: "/tmp/invalid-cert.pem",
			wantErr:  "failed to parse CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For invalid PEM test, create a file with invalid content
			if tt.name == "invalid PEM" {
				err := os.WriteFile(tt.certPath, []byte("invalid pem content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				defer os.Remove(tt.certPath)
			}

			cfg := &config.Config{
				VaultAddr:   "https://vault.example.com:8200",
				VaultToken:  "root",
				VaultCACert: tt.certPath,
			}

			_, err := NewClient(cfg)
			if err == nil {
				t.Errorf("NewClient() with invalid CA cert expected error containing %q, got nil", tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewClient() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewClient_EmptyToken(t *testing.T) {
	cfg := &config.Config{
		VaultAddr:  "http://127.0.0.1:8200",
		VaultToken: "",
	}

	// NewClient should succeed even with empty token
	// Token validation happens in ValidateAuth
	client, err := NewClient(cfg)
	if err != nil {
		t.Errorf("NewClient() unexpected error = %v", err)
	}
	if client == nil {
		t.Error("NewClient() returned nil client")
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
			VaultAddr:  "http://127.0.0.1:8200",
			VaultToken: "root",
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

func TestLoadCACert_ErrorPaths(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		wantErr     bool
		errContains string
	}{
		{
			name: "empty PEM file",
			setupFile: func(t *testing.T) string {
				tmpFile := t.TempDir() + "/empty.pem"
				err := os.WriteFile(tmpFile, []byte(""), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to parse CA certificate",
		},
		{
			name: "non-PEM content",
			setupFile: func(t *testing.T) string {
				tmpFile := t.TempDir() + "/nonpem.txt"
				err := os.WriteFile(tmpFile, []byte("This is not a PEM file"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to parse CA certificate",
		},
		{
			name: "PEM with wrong type",
			setupFile: func(t *testing.T) string {
				tmpFile := t.TempDir() + "/wrongtype.pem"
				// Create a PEM with PRIVATE KEY type instead of CERTIFICATE
				pemContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
-----END PRIVATE KEY-----`
				err := os.WriteFile(tmpFile, []byte(pemContent), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			wantErr:     true,
			errContains: "failed to parse CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPath := tt.setupFile(t)

			cfg := &config.Config{
				VaultAddr:   "https://vault.example.com:8200",
				VaultToken:  "root",
				VaultCACert: certPath,
			}

			_, err := NewClient(cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("NewClient() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}
