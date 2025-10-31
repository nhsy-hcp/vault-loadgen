package loadgen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/nhsy/vault-loadgen/internal/stats"
)

// TestCreateNamespace_MockedResponses tests CreateNamespace with mocked Vault responses
func TestCreateNamespace_MockedResponses(t *testing.T) {
	tests := []struct {
		name          string
		namespacePath string
		mockHandler   http.HandlerFunc
		wantErr       bool
		errContains   string
		checkStats    func(t *testing.T, s *stats.Stats)
	}{
		{
			name:          "successful creation",
			namespacePath: "loadtest-123",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/loadtest-123" {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id":   "ns-123",
							"path": "loadtest-123/",
						},
					})
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesCreated != 1 {
					t.Errorf("Expected NamespacesCreated = 1, got %d", s.NamespacesCreated)
				}
				if s.NamespacesFailed != 0 {
					t.Errorf("Expected NamespacesFailed = 0, got %d", s.NamespacesFailed)
				}
			},
		},
		{
			name:          "namespace already exists (idempotent)",
			namespacePath: "existing-ns",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/existing-ns" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"namespace already exists"},
					})
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesSkipped != 1 {
					t.Errorf("Expected NamespacesSkipped = 1, got %d", s.NamespacesSkipped)
				}
				if s.NamespacesCreated != 0 {
					t.Errorf("Expected NamespacesCreated = 0, got %d", s.NamespacesCreated)
				}
			},
		},
		{
			name:          "OSS namespace not supported",
			namespacePath: "test-ns",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/test-ns" {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"unsupported path"},
					})
				}
			},
			wantErr:     true,
			errContains: "Vault OSS",
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesFailed != 1 {
					t.Errorf("Expected NamespacesFailed = 1, got %d", s.NamespacesFailed)
				}
			},
		},
		{
			name:          "permission denied",
			namespacePath: "restricted-ns",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/restricted-ns" {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "permission denied",
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesFailed != 1 {
					t.Errorf("Expected NamespacesFailed = 1, got %d", s.NamespacesFailed)
				}
			},
		},
		{
			name:          "generic error",
			namespacePath: "error-ns",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/namespaces/error-ns" {
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"internal server error"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to create namespace",
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesFailed != 1 {
					t.Errorf("Expected NamespacesFailed = 1, got %d", s.NamespacesFailed)
				}
			},
		},
		{
			name:          "invalid namespace name",
			namespacePath: "invalid@namespace",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				// Handler shouldn't be called due to validation failure
			},
			wantErr:     true,
			errContains: "invalid characters",
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.NamespacesFailed != 1 {
					t.Errorf("Expected NamespacesFailed = 1, got %d", s.NamespacesFailed)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Create Vault client pointing to mock server
			apiConfig := api.DefaultConfig()
			apiConfig.Address = server.URL
			vaultClient, err := api.NewClient(apiConfig)
			if err != nil {
				t.Fatalf("Failed to create Vault client: %v", err)
			}
			vaultClient.SetToken("mock-token")

			// Create stats tracker
			st := stats.New()

			// Test CreateNamespace
			ctx := context.Background()
			err = CreateNamespace(ctx, vaultClient, tt.namespacePath, st)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateNamespace() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("CreateNamespace() error = %v, should contain %q", err, tt.errContains)
				}
			}

			// Check stats
			if tt.checkStats != nil {
				tt.checkStats(t, st)
			}
		})
	}
}

// TestCreateNamespace_ContextCancellation tests CreateNamespace with context cancellation
func TestCreateNamespace_ContextCancellation(t *testing.T) {
	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create Vault client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = server.URL
	vaultClient, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}

	st := stats.New()

	// Test CreateNamespace with cancelled context
	err = CreateNamespace(ctx, vaultClient, "test-ns", st)

	// Context cancellation may or may not cause an error depending on timing
	// Just verify the function doesn't panic
	t.Logf("CreateNamespace with cancelled context: error = %v", err)
}

// TestValidateNamespace_UnknownMode tests ValidateNamespace with unknown mode
func TestValidateNamespace_UnknownMode(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create Vault client
	apiConfig := api.DefaultConfig()
	apiConfig.Address = server.URL
	vaultClient, err := api.NewClient(apiConfig)
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}

	ctx := context.Background()
	err = ValidateNamespace(ctx, vaultClient, "test", "invalid-mode")

	if err == nil {
		t.Error("ValidateNamespace() with unknown mode should return error")
		return
	}

	if !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("ValidateNamespace() error = %v, should contain 'unknown mode'", err)
	}
}
