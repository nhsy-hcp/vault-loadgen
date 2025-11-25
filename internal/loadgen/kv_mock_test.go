package loadgen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// TestSetupKVEngine_MockedResponses tests setupKVEngine with mocked Vault responses
func TestSetupKVEngine_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		engineName  string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful KV v2 engine setup",
			namespace:  "test-ns",
			engineName: "secret-0",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/secret-0" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				}
			},
			wantErr: false,
		},
		{
			name:       "KV engine already mounted (idempotent)",
			namespace:  "",
			engineName: "secret-1",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/secret-1" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"path is already in use at secret-1/"},
					})
				}
			},
			wantErr: false,
		},
		{
			name:       "mount failure - permission denied",
			namespace:  "test-ns",
			engineName: "secret-2",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/secret-2" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to mount kv engine",
		},
		{
			name:       "mount failure - invalid engine type",
			namespace:  "",
			engineName: "secret-3",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/secret-3" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"unknown type: kv-v2"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to mount kv engine",
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

			// Test setupKVEngine
			ctx := context.Background()
			st := stats.New()
			err = setupKVEngine(ctx, vaultClient, tt.namespace, tt.engineName, st)

			if (err != nil) != tt.wantErr {
				t.Errorf("setupKVEngine() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("setupKVEngine() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestWriteSecret_MockedResponses tests writeSecret with mocked Vault responses
func TestWriteSecret_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		engineName  string
		secretName  string
		secretData  map[string]interface{}
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful secret write",
			namespace:  "",
			engineName: "secret-0",
			secretName: "loadtest-1",
			secretData: map[string]interface{}{
				"key-0": "value-0",
				"key-1": "value-1",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret-0/data/loadtest-1" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"version": 1,
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name:       "successful write with namespace",
			namespace:  "test-ns",
			engineName: "secret-1",
			secretName: "loadtest-2",
			secretData: map[string]interface{}{
				"key-0": "value-0",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret-1/data/loadtest-2" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"version": 1,
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name:       "write failure - permission denied",
			namespace:  "",
			engineName: "secret-0",
			secretName: "loadtest-3",
			secretData: map[string]interface{}{
				"key-0": "value-0",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret-0/data/loadtest-3" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to write secret",
		},
		{
			name:       "write failure - engine not found",
			namespace:  "",
			engineName: "nonexistent",
			secretName: "loadtest-4",
			secretData: map[string]interface{}{
				"key-0": "value-0",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/nonexistent/data/loadtest-4" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"no handler for route"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to write secret",
		},
		{
			name:       "write with large secret",
			namespace:  "",
			engineName: "secret-0",
			secretName: "loadtest-large",
			secretData: func() map[string]interface{} {
				data := make(map[string]interface{})
				for i := 0; i < 20; i++ {
					data[strings.Repeat("k", i+1)] = strings.Repeat("v", 100)
				}
				return data
			}(),
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret-0/data/loadtest-large" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"version": 1,
						},
					})
				}
			},
			wantErr: false,
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

			// Test writeSecret
			ctx := context.Background()
			err = writeSecret(ctx, vaultClient, tt.namespace, tt.engineName, tt.secretName, tt.secretData)

			if (err != nil) != tt.wantErr {
				t.Errorf("writeSecret() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("writeSecret() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestGenerateKVLoad_MockedEndToEnd tests GenerateKVLoad with mocked Vault for end-to-end flow
func TestGenerateKVLoad_MockedEndToEnd(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
		checkStats  func(t *testing.T, s *stats.Stats)
	}{
		{
			name: "successful KV load generation - single namespace, single engine",
			cfg: &config.Config{
				VaultToken:       "root",
				SecretsPerEngine: 5,
				KVEngines:        1,
				SecretSize:       3,
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
				case r.URL.Path == "/v1/sys/mounts/secret-0":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case strings.HasPrefix(r.URL.Path, "/v1/secret-0/data/loadtest-"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"version": 1,
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.SecretsCreated != 5 {
					t.Errorf("Expected SecretsCreated = 5, got %d", s.SecretsCreated)
				}
				if s.SecretsFailed != 0 {
					t.Errorf("Expected SecretsFailed = 0, got %d", s.SecretsFailed)
				}
			},
		},
		{
			name: "successful KV load - multiple engines",
			cfg: &config.Config{
				VaultToken:       "root",
				SecretsPerEngine: 2,
				KVEngines:        3,
				SecretSize:       2,
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
				case strings.HasPrefix(r.URL.Path, "/v1/sys/mounts/secret-"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case strings.Contains(r.URL.Path, "/data/loadtest-"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"version": 1,
						},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				expectedSecrets := 2 * 3 // 2 secrets per engine * 3 engines
				if s.SecretsCreated != int64(expectedSecrets) {
					t.Errorf("Expected SecretsCreated = %d, got %d", expectedSecrets, s.SecretsCreated)
				}
				if s.SecretsFailed != 0 {
					t.Errorf("Expected SecretsFailed = 0, got %d", s.SecretsFailed)
				}
			},
		},
		{
			name: "KV load with some write failures",
			cfg: &config.Config{
				VaultToken:       "root",
				SecretsPerEngine: 3,
				KVEngines:        1,
				SecretSize:       2,
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
				case r.URL.Path == "/v1/sys/mounts/secret-0":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case strings.HasPrefix(r.URL.Path, "/v1/secret-0/data/loadtest-"):
					// Simulate write failures
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"write failed"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
			checkStats: func(t *testing.T, s *stats.Stats) {
				if s.SecretsFailed != 3 {
					t.Errorf("Expected SecretsFailed = 3, got %d", s.SecretsFailed)
				}
				if s.SecretsCreated != 0 {
					t.Errorf("Expected SecretsCreated = 0, got %d", s.SecretsCreated)
				}
			},
		},
		{
			name: "authentication validation failure",
			cfg: &config.Config{
				VaultToken:       "invalid-token",
				SecretsPerEngine: 5,
				KVEngines:        1,
				SecretSize:       3,
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
			name: "KV engine setup failure",
			cfg: &config.Config{
				VaultToken:       "root",
				SecretsPerEngine: 5,
				KVEngines:        1,
				SecretSize:       3,
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
				case "/v1/sys/mounts/secret-0":
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to setup KV engine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Update config with mock server address
			tt.cfg.VaultAddr = server.URL

			// Test GenerateKVLoad
			ctx := context.Background()
			st, err := GenerateKVLoad(ctx, tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKVLoad() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GenerateKVLoad() error = %v, should contain %q", err, tt.errContains)
				}
			}

			// Check stats
			if !tt.wantErr && tt.checkStats != nil && st != nil {
				tt.checkStats(t, st)
			}
		})
	}
}

// TestGenerateKVLoad_ContextCancellation tests context cancellation during KV load
func TestGenerateKVLoad_ContextCancellation(t *testing.T) {
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
		SecretsPerEngine: 100,
		KVEngines:        3,
		SecretSize:       5,
		Workers:          2,
		CreateNamespaces: false,
		ParentNamespace:  "",
	}

	// Create a context that we cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test GenerateKVLoad with cancelled context
	_, err := GenerateKVLoad(ctx, cfg)

	// Should return error due to context cancellation
	if err == nil {
		t.Error("GenerateKVLoad() should return error when context is cancelled")
	}
}

// TestGenerateRandomSecret tests the generateRandomSecret function
func TestGenerateRandomSecret(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{
			name: "small secret",
			size: 1,
		},
		{
			name: "medium secret",
			size: 5,
		},
		{
			name: "large secret",
			size: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := generateRandomSecret(tt.size)

			if len(secret) != tt.size {
				t.Errorf("Expected secret with %d keys, got %d", tt.size, len(secret))
			}

			// Verify all keys and values exist
			for i := 0; i < tt.size; i++ {
				key := fmt.Sprintf("key-%d", i)
				if _, ok := secret[key]; !ok {
					t.Errorf("Expected key %s to exist", key)
				}

				// Verify value is a non-empty string
				if val, ok := secret[key].(string); !ok || val == "" {
					t.Errorf("Expected non-empty string value for key %s", key)
				}
			}

			// Verify randomness - two calls should produce different values
			secret2 := generateRandomSecret(tt.size)
			if tt.size > 0 {
				key := "key-0"
				if secret[key] == secret2[key] {
					t.Log("Warning: Two random secrets have the same value (rare but possible)")
				}
			}
		})
	}
}

// TestGenerateRandomString tests the generateRandomString function
func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "short string",
			length: 8,
		},
		{
			name:   "medium string",
			length: 32,
		},
		{
			name:   "long string",
			length: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := generateRandomString(tt.length)

			if len(str) != tt.length {
				t.Errorf("Expected string length %d, got %d", tt.length, len(str))
			}

			// Verify it's valid hex (only 0-9 and a-f characters)
			for _, char := range str {
				if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
					t.Errorf("Invalid hex character in string: %c", char)
				}
			}
		})
	}
}
