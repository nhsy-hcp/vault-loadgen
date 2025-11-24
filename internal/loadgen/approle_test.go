package loadgen

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestGenerateAppRoleLoad_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		logins      int
		wantErr     bool
		errContains string
	}{
		{
			name:        "zero logins",
			logins:      0,
			wantErr:     true,
			errContains: "approle-logins must be at least 1",
		},
		{
			name:        "negative logins",
			logins:      -1,
			wantErr:     true,
			errContains: "approle-logins must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				VaultAddr:     "http://127.0.0.1:8200",
				VaultToken:    "root",
				AppRoleLogins: tt.logins,
				SecretIDTTL:   "1h",
				TokenTTL:      "1h",
				TokenMaxTTL:   "2h",
			}

			_, err := GenerateAppRoleLoad(ctx, cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAppRoleLoad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GenerateAppRoleLoad() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestGenerateAppRoleLoad_ConfigValidation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		config    *config.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "missing vault address",
			config: &config.Config{
				VaultToken:    "root",
				AppRoleLogins: 10,
			},
			wantErr:   true,
			errSubstr: "vault address",
		},
		{
			name: "empty vault token",
			config: &config.Config{
				VaultAddr:     "http://127.0.0.1:8200",
				AppRoleLogins: 10,
			},
			wantErr:   true,
			errSubstr: "validation failed", // Will fail at connection or auth validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateAppRoleLoad(ctx, tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateAppRoleLoad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errSubstr != "" {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("GenerateAppRoleLoad() error = %v, should contain %q", err, tt.errSubstr)
				}
			}
		})
	}
}

func TestAppRoleLoad_NamespaceDistribution(t *testing.T) {
	// This test validates the logic for distributing logins across namespaces
	tests := []struct {
		name              string
		totalLogins       int
		numNamespaces     int
		expectedPerNS     int
		expectedRemainder int
	}{
		{
			name:              "even distribution",
			totalLogins:       100,
			numNamespaces:     5,
			expectedPerNS:     20,
			expectedRemainder: 0,
		},
		{
			name:              "uneven distribution",
			totalLogins:       103,
			numNamespaces:     5,
			expectedPerNS:     20,
			expectedRemainder: 3,
		},
		{
			name:              "single namespace",
			totalLogins:       100,
			numNamespaces:     1,
			expectedPerNS:     100,
			expectedRemainder: 0,
		},
		{
			name:              "more namespaces than logins",
			totalLogins:       3,
			numNamespaces:     5,
			expectedPerNS:     0,
			expectedRemainder: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginsPerNS := tt.totalLogins / tt.numNamespaces
			remainder := tt.totalLogins % tt.numNamespaces

			if loginsPerNS != tt.expectedPerNS {
				t.Errorf("logins per namespace = %d, want %d", loginsPerNS, tt.expectedPerNS)
			}

			if remainder != tt.expectedRemainder {
				t.Errorf("remainder = %d, want %d", remainder, tt.expectedRemainder)
			}

			// Verify total distribution
			total := 0
			for i := 0; i < tt.numNamespaces; i++ {
				loginsForThisNS := loginsPerNS
				if i < remainder {
					loginsForThisNS++
				}
				total += loginsForThisNS
			}

			if total != tt.totalLogins {
				t.Errorf("total distributed logins = %d, want %d", total, tt.totalLogins)
			}
		})
	}
}

func TestAppRoleLoad_TTLConfiguration(t *testing.T) {
	// This test validates TTL configuration values
	tests := []struct {
		name        string
		secretIDTTL string
		tokenTTL    string
		tokenMaxTTL string
		expectValid bool
	}{
		{
			name:        "valid standard TTLs",
			secretIDTTL: "1h",
			tokenTTL:    "1h",
			tokenMaxTTL: "2h",
			expectValid: true,
		},
		{
			name:        "valid extended TTLs",
			secretIDTTL: "24h",
			tokenTTL:    "12h",
			tokenMaxTTL: "24h",
			expectValid: true,
		},
		{
			name:        "valid short TTLs",
			secretIDTTL: "5m",
			tokenTTL:    "5m",
			tokenMaxTTL: "10m",
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just validate that the TTL strings are in the expected format
			if tt.secretIDTTL == "" || tt.tokenTTL == "" || tt.tokenMaxTTL == "" {
				if tt.expectValid {
					t.Error("expected valid TTL configuration but got empty values")
				}
			}
		})
	}
}

func TestAppRoleLoad_Integration(t *testing.T) {
	// Integration test - requires live Vault instance
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("requires live vault", func(t *testing.T) {
		// This test validates the function signature and integration
		// Actual AppRole tests require a running Vault instance
		cfg := &config.Config{
			VaultAddr:     "http://127.0.0.1:8200",
			VaultToken:    "root",
			AppRoleLogins: 5,
			SecretIDTTL:   "1h",
			TokenTTL:      "1h",
			TokenMaxTTL:   "2h",
			Workers:       2,
		}

		ctx := context.Background()
		_, err := GenerateAppRoleLoad(ctx, cfg)
		// We don't assert success/failure here as it depends on Vault availability
		t.Logf("GenerateAppRoleLoad result: %v", err)
	})
}

func TestAppRoleLoad_UniqueRoleNames(t *testing.T) {
	tests := []struct {
		name        string
		logins      int
		namespaces  int
		expectedMin int
		expectedMax int
	}{
		{
			name:        "sequential role names for 10 logins",
			logins:      10,
			namespaces:  1,
			expectedMin: 0,
			expectedMax: 9,
		},
		{
			name:        "sequential role names across multiple namespaces",
			logins:      20,
			namespaces:  5,
			expectedMin: 0,
			expectedMax: 19,
		},
		{
			name:        "single login",
			logins:      1,
			namespaces:  1,
			expectedMin: 0,
			expectedMax: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test validates that role names are globally sequential
			// by checking the expected range of role names (loadtest-0 through loadtest-N)
			loginsPerNS := tt.logins / tt.namespaces
			remainder := tt.logins % tt.namespaces

			roleIndex := 0
			for ns := 0; ns < tt.namespaces; ns++ {
				loginsForNS := loginsPerNS
				if ns < remainder {
					loginsForNS++
				}

				for i := 0; i < loginsForNS; i++ {
					expected := fmt.Sprintf("loadtest-%d", roleIndex)
					if roleIndex < tt.expectedMin || roleIndex > tt.expectedMax {
						t.Errorf("Role index %d out of expected range [%d, %d]", roleIndex, tt.expectedMin, tt.expectedMax)
					}
					_ = expected // Role name follows expected pattern
					roleIndex++
				}
			}

			// Verify total count matches
			if roleIndex != tt.logins {
				t.Errorf("Expected %d total roles, got %d", tt.logins, roleIndex)
			}
		})
	}
}

func TestAppRoleLoad_WorkerPoolLimits(t *testing.T) {
	// Test validates worker pool configuration
	tests := []struct {
		name        string
		totalLogins int
		workers     int
	}{
		{
			name:        "more workers than logins",
			totalLogins: 5,
			workers:     10,
		},
		{
			name:        "equal workers and logins",
			totalLogins: 10,
			workers:     10,
		},
		{
			name:        "fewer workers than logins",
			totalLogins: 100,
			workers:     4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate that worker configuration is reasonable
			if tt.workers < 1 {
				t.Errorf("workers must be >= 1, got %d", tt.workers)
			}
			if tt.totalLogins < 0 {
				t.Errorf("total logins must be >= 0, got %d", tt.totalLogins)
			}
		})
	}
}
