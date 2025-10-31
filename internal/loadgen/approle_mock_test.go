package loadgen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// TestSetupAppRoleAuth_MockedResponses tests setupAppRoleAuth with mocked Vault responses
func TestSetupAppRoleAuth_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		cfg         *config.Config
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful AppRole auth setup",
			namespace: "test-ns",
			cfg: &config.Config{
				TokenTTL:    "1h",
				TokenMaxTTL: "2h",
				SecretIDTTL: "1h",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/auth/approle" && r.Method == "POST":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "AppRole auth already enabled (idempotent)",
			namespace: "",
			cfg: &config.Config{
				TokenTTL:    "1h",
				TokenMaxTTL: "2h",
				SecretIDTTL: "1h",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/auth/approle" && r.Method == "POST":
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"path is already in use at approle/"},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "auth method enable failure - permission denied",
			namespace: "test-ns",
			cfg: &config.Config{
				TokenTTL:    "1h",
				TokenMaxTTL: "2h",
				SecretIDTTL: "1h",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/auth/approle" && r.Method == "POST" {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to enable approle auth",
		},
		{
			name:      "role creation failure",
			namespace: "",
			cfg: &config.Config{
				TokenTTL:    "1h",
				TokenMaxTTL: "2h",
				SecretIDTTL: "1h",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/auth/approle" && r.Method == "POST":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"invalid role configuration"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to create approle role",
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

			// Test setupAppRoleAuth
			ctx := context.Background()
			err = setupAppRoleAuth(ctx, vaultClient, tt.namespace, tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("setupAppRoleAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("setupAppRoleAuth() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestGenerateAppRoleLogin_MockedResponses tests generateAppRoleLogin with mocked Vault responses
func TestGenerateAppRoleLogin_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful AppRole login",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id" && r.Method == "GET":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id-12345",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id":          "test-secret-id-67890",
							"secret_id_accessor": "test-accessor",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"auth": map[string]interface{}{
							"client_token":   "s.test-token-abc123",
							"lease_duration": 3600,
							"renewable":      true,
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "successful login with namespace",
			namespace: "test-ns",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id": "test-secret-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"auth": map[string]interface{}{
							"client_token":   "s.test-token",
							"lease_duration": 3600,
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "role ID read failure",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/approle/role/loadtest/role-id" {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to read role ID",
		},
		{
			name:      "nil role ID response",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/approle/role/loadtest/role-id" {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{},
					})
				}
			},
			wantErr:     true,
			errContains: "no role ID returned",
		},
		{
			name:      "secret ID generation failure",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case "/v1/auth/approle/role/loadtest/secret-id":
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"failed to generate secret ID"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to generate secret ID",
		},
		{
			name:      "nil secret ID response",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case "/v1/auth/approle/role/loadtest/secret-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "no secret ID returned",
		},
		{
			name:      "login failure - invalid credentials",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id": "test-secret-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login":
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"invalid credentials"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to login with approle",
		},
		{
			name:      "nil auth response from login",
			namespace: "",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id": "test-secret-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "no auth info returned from login",
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

			// Test generateAppRoleLogin
			ctx := context.Background()
			err = generateAppRoleLogin(ctx, vaultClient, tt.namespace)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateAppRoleLogin() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("generateAppRoleLogin() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestGenerateAppRoleLoad_MockedEndToEnd tests GenerateAppRoleLoad with mocked Vault for end-to-end flow
func TestGenerateAppRoleLoad_MockedEndToEnd(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
		checkStats  func(t *testing.T, s *stats.Stats)
	}{
		{
			name: "successful AppRole load generation - single namespace",
			cfg: &config.Config{
				VaultToken:       "root",
				AppRoleLogins:    5,
				TokenTTL:         "1h",
				TokenMaxTTL:      "2h",
				SecretIDTTL:      "1h",
				Workers:          2,
				CreateNamespaces: false,
				ParentNamespace:  "",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/health":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"initialized": true,
						"sealed":      false,
					})
				case r.URL.Path == "/v1/auth/token/lookup-self":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id": "mock-token",
						},
					})
				case r.URL.Path == "/v1/sys/auth/approle":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id": "test-secret-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"auth": map[string]interface{}{
							"client_token":   "s.test-token",
							"lease_duration": 3600,
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.LeasesCreated != 5 {
					t.Errorf("Expected LeasesCreated = 5, got %d", s.LeasesCreated)
				}
				if s.LeasesFailed != 0 {
					t.Errorf("Expected LeasesFailed = 0, got %d", s.LeasesFailed)
				}
			},
		},
		{
			name: "AppRole load with some login failures",
			cfg: &config.Config{
				VaultToken:       "root",
				AppRoleLogins:    3,
				TokenTTL:         "1h",
				TokenMaxTTL:      "2h",
				SecretIDTTL:      "1h",
				Workers:          2,
				CreateNamespaces: false,
				ParentNamespace:  "",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/health":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"initialized": true,
						"sealed":      false,
					})
				case r.URL.Path == "/v1/auth/token/lookup-self":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id": "mock-token",
						},
					})
				case r.URL.Path == "/v1/sys/auth/approle":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/role-id":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"role_id": "test-role-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/role/loadtest/secret-id" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"secret_id": "test-secret-id",
						},
					})
				case r.URL.Path == "/v1/auth/approle/login":
					// Simulate login failures
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"login failed"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.LeasesFailed != 3 {
					t.Errorf("Expected LeasesFailed = 3, got %d", s.LeasesFailed)
				}
				if s.LeasesCreated != 0 {
					t.Errorf("Expected LeasesCreated = 0, got %d", s.LeasesCreated)
				}
			},
		},
		{
			name: "authentication validation failure",
			cfg: &config.Config{
				VaultToken:       "invalid-token",
				AppRoleLogins:    5,
				TokenTTL:         "1h",
				TokenMaxTTL:      "2h",
				SecretIDTTL:      "1h",
				Workers:          2,
				CreateNamespaces: false,
				ParentNamespace:  "",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/health":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"initialized": true,
						"sealed":      false,
					})
				case "/v1/auth/token/lookup-self":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "authentication validation failed",
		},
		{
			name: "AppRole auth setup failure",
			cfg: &config.Config{
				VaultToken:       "root",
				AppRoleLogins:    5,
				TokenTTL:         "1h",
				TokenMaxTTL:      "2h",
				SecretIDTTL:      "1h",
				Workers:          2,
				CreateNamespaces: false,
				ParentNamespace:  "",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/health":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"initialized": true,
						"sealed":      false,
					})
				case "/v1/auth/token/lookup-self":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"id": "mock-token",
						},
					})
				case "/v1/sys/auth/approle":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to setup AppRole auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Update config with mock server address
			tt.cfg.VaultAddr = server.URL

			// Test GenerateAppRoleLoad
			ctx := context.Background()
			st, err := GenerateAppRoleLoad(ctx, tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAppRoleLoad() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GenerateAppRoleLoad() error = %v, should contain %q", err, tt.errContains)
				}
			}

			// Check stats
			if !tt.wantErr && tt.checkStats != nil && st != nil {
				tt.checkStats(t, st)
			}
		})
	}
}

// TestGenerateAppRoleLoad_ContextCancellation tests context cancellation during AppRole load
func TestGenerateAppRoleLoad_ContextCancellation(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
			})
		case "/v1/auth/token/lookup-self":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id": "mock-token",
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		VaultAddr:        server.URL,
		VaultToken:       "root",
		AppRoleLogins:    100,
		TokenTTL:         "1h",
		TokenMaxTTL:      "2h",
		SecretIDTTL:      "1h",
		Workers:          2,
		CreateNamespaces: false,
		ParentNamespace:  "",
	}

	// Create a context that we cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test GenerateAppRoleLoad with cancelled context
	_, err := GenerateAppRoleLoad(ctx, cfg)

	// Should return error due to context cancellation
	if err == nil {
		t.Error("GenerateAppRoleLoad() should return error when context is cancelled")
	}
}
