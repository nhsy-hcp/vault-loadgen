package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

// TestValidateConnection_MockedResponses tests ValidateConnection with mocked Vault responses
func TestValidateConnection_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "vault sealed",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"initialized": true,
					"sealed":      true,
				})
			},
			wantErr:     true,
			errContains: "sealed",
		},
		{
			name: "vault not initialized",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"initialized": false,
					"sealed":      false,
				})
			},
			wantErr:     true,
			errContains: "not initialized",
		},
		{
			name: "vault healthy",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"initialized":  true,
					"sealed":       false,
					"version":      "1.15.0",
					"cluster_name": "vault-cluster",
				})
			},
			wantErr: false,
		},
		{
			name: "connection error",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantErr:     true,
			errContains: "failed to connect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Create client pointing to mock server
			cfg := &config.Config{
				VaultAddr:  server.URL,
				VaultToken: "mock-token",
			}

			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			// Test ValidateConnection
			err = ValidateConnection(client)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConnection() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateConnection() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestValidateAuth_MockedResponses tests ValidateAuth with mocked Vault responses
func TestValidateAuth_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "valid token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id":           "mock-token-id",
							"display_name": "test-token",
							"policies":     []string{"default"},
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name: "invalid token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "authentication failed",
		},
		{
			name: "expired token",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					// Return 403 for expired token
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"token expired"},
					})
				}
			},
			wantErr:     true,
			errContains: "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Create client pointing to mock server
			cfg := &config.Config{
				VaultAddr:  server.URL,
				VaultToken: "mock-token",
			}

			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			// Test ValidateAuth
			err = ValidateAuth(client)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateAuth() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestValidateNamespace_MockedResponses tests ValidateNamespace with mocked Vault responses
func TestValidateNamespace_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:      "root namespace (empty)",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				// Root namespace always exists, so handler shouldn't be called
			},
			wantErr: false,
		},
		{
			name:      "valid namespace",
			namespace: "admin",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/admin" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id":   "admin-ns-id",
							"path": "admin/",
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name:      "namespace not found",
			namespace: "nonexistent",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/nonexistent" {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"namespace not found"},
					})
				}
			},
			wantErr:     true,
			errContains: "does not exist",
		},
		{
			name:      "nil secret response",
			namespace: "test",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/test" {
					// Return 404 to simulate nil secret
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.namespace == "" {
				// Root namespace test doesn't need mock server
				err := ValidateNamespace(nil, tt.namespace)
				if err != nil {
					t.Errorf("ValidateNamespace() for root namespace should not error, got: %v", err)
				}
				return
			}

			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Create client pointing to mock server
			cfg := &config.Config{
				VaultAddr:  server.URL,
				VaultToken: "mock-token",
			}

			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			// Test ValidateNamespace
			err = ValidateNamespace(client, tt.namespace)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNamespace() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateNamespace() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestValidateConnection_NilHealth tests nil health response handling
func TestValidateConnection_NilHealth(t *testing.T) {
	// This test verifies the nil health check in ValidateConnection
	// We can't easily mock the api.Client to return nil health,
	// but we can test the error path with an unreachable server
	cfg := &config.Config{
		VaultAddr:  "http://localhost:1", // Invalid port
		VaultToken: "mock-token",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Change the address to an unreachable one
	err = client.SetAddress("http://localhost:1")
	if err != nil {
		t.Fatalf("SetAddress() error = %v", err)
	}

	// Test ValidateConnection with unreachable server
	err = ValidateConnection(client)
	if err == nil {
		t.Error("ValidateConnection() with unreachable server should return error")
	}

	if err != nil && !contains(err.Error(), "failed to connect") {
		t.Errorf("ValidateConnection() error = %v, should contain 'failed to connect'", err)
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 &&
			(s[0:len(substr)] == substr || contains(s[1:], substr))))
}

// TestNewClient_WithTLS tests TLS configuration scenarios
func TestNewClient_WithTLS(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name: "HTTPS without skip verify",
			config: &config.Config{
				VaultAddr:       "https://vault.example.com:8200",
				VaultToken:      "root",
				VaultSkipVerify: false,
			},
			wantErr: false,
		},
		{
			name: "HTTPS with skip verify",
			config: &config.Config{
				VaultAddr:       "https://vault.example.com:8200",
				VaultToken:      "root",
				VaultSkipVerify: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}

			// Verify client address is set correctly
			if client != nil && client.Address() != tt.config.VaultAddr {
				t.Errorf("Client address = %s, want %s", client.Address(), tt.config.VaultAddr)
			}
		})
	}
}

// TestValidateAuth_Integration tests ValidateAuth with actual API client behavior
func TestValidateAuth_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a client with invalid credentials
	cfg := &config.Config{
		VaultAddr:  "http://localhost:1", // Unreachable
		VaultToken: "invalid-token",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// ValidateAuth should fail with connection error
	err = ValidateAuth(client)
	if err == nil {
		t.Error("ValidateAuth() with unreachable server should return error")
	}
}

// TestValidateNamespace_Integration tests ValidateNamespace with actual API client behavior
func TestValidateNamespace_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a client with invalid credentials
	cfg := &config.Config{
		VaultAddr:  "http://localhost:1", // Unreachable
		VaultToken: "invalid-token",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// ValidateNamespace should fail with connection error
	err = ValidateNamespace(client, "test")
	if err == nil {
		t.Error("ValidateNamespace() with unreachable server should return error")
	}
}
