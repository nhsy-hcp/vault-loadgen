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

// TestSetupPKIEngine_MockedResponses tests setupPKIEngine with mocked Vault responses
func TestSetupPKIEngine_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		certTTL     string
		rootCATTL   string
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful PKI engine setup",
			namespace: "test-ns",
			certTTL:   "24h",
			rootCATTL: "168h",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/mounts/pki" && r.Method == "POST":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/pki/root/generate/internal" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				case r.URL.Path == "/v1/pki/roles/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "PKI engine already mounted (idempotent)",
			namespace: "",
			certTTL:   "24h",
			rootCATTL: "168h",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/mounts/pki" && r.Method == "POST":
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"path is already in use at pki/"},
					})
				case r.URL.Path == "/v1/pki/root/generate/internal" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				case r.URL.Path == "/v1/pki/roles/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name:      "mount failure - permission denied",
			namespace: "test-ns",
			certTTL:   "24h",
			rootCATTL: "168h",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/pki" && r.Method == "POST" {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to mount pki engine",
		},
		{
			name:      "root CA generation failure",
			namespace: "",
			certTTL:   "24h",
			rootCATTL: "168h",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/mounts/pki" && r.Method == "POST":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/pki/root/generate/internal" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"failed to generate root CA"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to generate root CA",
		},
		{
			name:      "role creation failure",
			namespace: "",
			certTTL:   "24h",
			rootCATTL: "168h",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/mounts/pki" && r.Method == "POST":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/pki/root/generate/internal" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				case r.URL.Path == "/v1/pki/roles/loadtest" && (r.Method == "POST" || r.Method == "PUT"):
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"invalid role configuration"},
					})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr:     true,
			errContains: "failed to create pki role",
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

			// Test setupPKIEngine
			ctx := context.Background()
			st := stats.New()
			err = setupPKIEngine(ctx, vaultClient, tt.namespace, tt.certTTL, tt.rootCATTL, st)

			if (err != nil) != tt.wantErr {
				t.Errorf("setupPKIEngine() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("setupPKIEngine() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestGenerateCertificateLease_MockedResponses tests generateCertificateLease with mocked Vault responses
func TestGenerateCertificateLease_MockedResponses(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		commonName  string
		keySize     int
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful certificate generation",
			namespace:  "",
			commonName: "test.example.com",
			keySize:    2048,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pki/sign/loadtest" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"lease_id":       "pki/sign/loadtest/abc123",
						"lease_duration": 86400,
						"data": map[string]interface{}{
							"certificate":   "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
							"serial_number": "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58",
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name:       "successful generation with namespace",
			namespace:  "test-ns",
			commonName: "app.example.com",
			keySize:    2048,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pki/sign/loadtest" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"lease_id": "pki/sign/loadtest/xyz789",
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				}
			},
			wantErr: false,
		},
		{
			name:       "signing failure - invalid CSR",
			namespace:  "",
			commonName: "test.example.com",
			keySize:    2048,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pki/sign/loadtest" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"invalid CSR"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to sign certificate",
		},
		{
			name:       "signing failure - permission denied",
			namespace:  "test-ns",
			commonName: "test.example.com",
			keySize:    2048,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pki/sign/loadtest" && (r.Method == "POST" || r.Method == "PUT") {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"permission denied"},
					})
				}
			},
			wantErr:     true,
			errContains: "failed to sign certificate",
		},
		{
			name:       "invalid key size",
			namespace:  "",
			commonName: "test.example.com",
			keySize:    1024,
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				// Should not reach handler due to CSR creation error
				w.WriteHeader(http.StatusOK)
			},
			wantErr:     true,
			errContains: "failed to create CSR",
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

			// Test generateCertificateLease
			ctx := context.Background()
			err = generateCertificateLease(ctx, vaultClient, tt.namespace, tt.commonName, tt.keySize)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateCertificateLease() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("generateCertificateLease() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestGeneratePKILoad_MockedEndToEnd tests GeneratePKILoad with mocked Vault for end-to-end flow
func TestGeneratePKILoad_MockedEndToEnd(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		mockHandler http.HandlerFunc
		wantErr     bool
		errContains string
		checkStats  func(t *testing.T, s *stats.Stats)
	}{
		{
			name: "successful PKI load generation - single namespace",
			cfg: &config.Config{
				VaultToken:       "root",
				PKILeases:        5,
				PKITTL:           "24h",
				PKIRootCATTL:     "168h",
				PKIKeySize:       2048,
				PKICommonName:    "cert-{index}.example.com",
				Workers:          2,
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
				case r.URL.Path == "/v1/sys/mounts/pki":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/pki/root/generate/internal":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				case r.URL.Path == "/v1/pki/roles/loadtest":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/loadtest"):
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"lease_id": "pki/sign/loadtest/test-lease",
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
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
			name: "PKI load with some failures",
			cfg: &config.Config{
				VaultToken:       "root",
				PKILeases:        3,
				PKITTL:           "24h",
				PKIRootCATTL:     "168h",
				PKIKeySize:       2048,
				PKICommonName:    "cert-{index}.example.com",
				Workers:          2,
				ParentNamespace:  "",
			},
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				// Track request count for alternating success/failure
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
				case r.URL.Path == "/v1/sys/mounts/pki":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case r.URL.Path == "/v1/pki/root/generate/internal":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						},
					})
				case r.URL.Path == "/v1/pki/roles/loadtest":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{})
				case strings.HasPrefix(r.URL.Path, "/v1/pki/sign/loadtest"):
					// Simulate some failures
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"errors": []string{"signing failed"},
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
				PKILeases:        5,
				PKITTL:           "24h",
				PKIRootCATTL:     "168h",
				PKIKeySize:       2048,
				PKICommonName:    "cert-{index}.example.com",
				Workers:          2,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			// Update config with mock server address
			tt.cfg.VaultAddr = server.URL

			// Test GeneratePKILoad
			ctx := context.Background()
			st, err := GeneratePKILoad(ctx, tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePKILoad() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GeneratePKILoad() error = %v, should contain %q", err, tt.errContains)
				}
			}

			// Check stats
			if !tt.wantErr && tt.checkStats != nil && st != nil {
				tt.checkStats(t, st)
			}
		})
	}
}

// TestGeneratePKILoad_ContextCancellation tests context cancellation during PKI load
func TestGeneratePKILoad_ContextCancellation(t *testing.T) {
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
		PKILeases:        100,
		PKITTL:           "24h",
		PKIRootCATTL:     "168h",
		PKIKeySize:       2048,
		PKICommonName:    "cert-{index}.example.com",
		Workers:          2,
		ParentNamespace:  "",
	}

	// Create a context that we cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test GeneratePKILoad with cancelled context
	_, err := GeneratePKILoad(ctx, cfg)

	// Should return error due to context cancellation
	if err == nil {
		t.Error("GeneratePKILoad() should return error when context is cancelled")
	}
}
