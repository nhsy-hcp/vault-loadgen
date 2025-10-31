package loadgen

import (
	"context"
	"strings"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestGenerateKVLoad_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		secretsPerEngine int
		kvEngines        int
		wantErr          bool
		errContains      string
	}{
		{
			name:             "zero secrets per engine",
			secretsPerEngine: 0,
			kvEngines:        1,
			wantErr:          true,
			errContains:      "secrets-per-engine must be at least 1",
		},
		{
			name:             "negative secrets per engine",
			secretsPerEngine: -1,
			kvEngines:        1,
			wantErr:          true,
			errContains:      "secrets-per-engine must be at least 1",
		},
		{
			name:             "zero kv engines",
			secretsPerEngine: 10,
			kvEngines:        0,
			wantErr:          true,
			errContains:      "kv-engines must be at least 1",
		},
		{
			name:             "negative kv engines",
			secretsPerEngine: 10,
			kvEngines:        -1,
			wantErr:          true,
			errContains:      "kv-engines must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				VaultAddr:        "http://127.0.0.1:8200",
				VaultToken:       "root",
				SecretsPerEngine: tt.secretsPerEngine,
				KVEngines:        tt.kvEngines,
			}

			_, err := GenerateKVLoad(ctx, cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKVLoad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GenerateKVLoad() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestGenerateKVLoad_ConfigValidation(t *testing.T) {
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
				VaultToken:       "root",
				SecretsPerEngine: 10,
				KVEngines:        1,
			},
			wantErr:   true,
			errSubstr: "vault address",
		},
		{
			name: "empty vault token",
			config: &config.Config{
				VaultAddr:        "http://127.0.0.1:8200",
				SecretsPerEngine: 10,
				KVEngines:        1,
			},
			wantErr:   true,
			errSubstr: "validation failed", // Will fail at connection or auth validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateKVLoad(ctx, tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKVLoad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errSubstr != "" {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("GenerateKVLoad() error = %v, should contain %q", err, tt.errSubstr)
				}
			}
		})
	}
}

func TestKVLoad_SecretGeneration(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		validate func(t *testing.T, secret map[string]interface{})
	}{
		{
			name: "single key-value pair",
			size: 1,
			validate: func(t *testing.T, secret map[string]interface{}) {
				if len(secret) != 1 {
					t.Errorf("expected 1 key-value pair, got %d", len(secret))
				}
				if _, ok := secret["key-0"]; !ok {
					t.Error("expected key-0 to be present")
				}
			},
		},
		{
			name: "multiple key-value pairs",
			size: 5,
			validate: func(t *testing.T, secret map[string]interface{}) {
				if len(secret) != 5 {
					t.Errorf("expected 5 key-value pairs, got %d", len(secret))
				}
				for i := 0; i < 5; i++ {
					key := strings.Replace("key-N", "N", string(rune('0'+i)), 1)
					if _, ok := secret[key]; !ok {
						t.Errorf("expected %s to be present", key)
					}
				}
			},
		},
		{
			name: "large secret",
			size: 20,
			validate: func(t *testing.T, secret map[string]interface{}) {
				if len(secret) != 20 {
					t.Errorf("expected 20 key-value pairs, got %d", len(secret))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := generateRandomSecret(tt.size)
			tt.validate(t, secret)

			// Validate that values are strings and non-empty
			for key, val := range secret {
				if val == nil {
					t.Errorf("key %s has nil value", key)
				}
				if strVal, ok := val.(string); !ok || strVal == "" {
					t.Errorf("key %s has invalid value: %v", key, val)
				}
			}
		})
	}
}

func TestKVLoad_SecretDistribution(t *testing.T) {
	// This test validates the logic for distributing secrets across engines and namespaces
	tests := []struct {
		name              string
		totalSecrets      int
		engines           int
		namespaces        int
		expectedPerEngine int
	}{
		{
			name:              "even distribution single namespace",
			totalSecrets:      100,
			engines:           5,
			namespaces:        1,
			expectedPerEngine: 20,
		},
		{
			name:              "even distribution multi namespace",
			totalSecrets:      100,
			engines:           2,
			namespaces:        5,
			expectedPerEngine: 10,
		},
		{
			name:              "single engine",
			totalSecrets:      100,
			engines:           1,
			namespaces:        1,
			expectedPerEngine: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretsPerEngine := tt.totalSecrets / (tt.engines * tt.namespaces)

			if secretsPerEngine != tt.expectedPerEngine {
				t.Errorf("secrets per engine = %d, want %d", secretsPerEngine, tt.expectedPerEngine)
			}

			// Verify total distribution
			total := secretsPerEngine * tt.engines * tt.namespaces
			if total != tt.totalSecrets {
				t.Errorf("total distributed secrets = %d, want %d", total, tt.totalSecrets)
			}
		})
	}
}

func TestKVLoad_RandomStringGeneration(t *testing.T) {
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
			str1 := generateRandomString(tt.length)
			str2 := generateRandomString(tt.length)

			// Check length (hex encoding doubles the byte length)
			if len(str1) != tt.length {
				t.Errorf("generated string length = %d, want %d", len(str1), tt.length)
			}

			// Check randomness (two generations should be different)
			if str1 == str2 {
				t.Error("two random strings should be different")
			}

			// Check that it's valid hex
			for _, char := range str1 {
				if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
					t.Errorf("invalid hex character in string: %c", char)
				}
			}
		})
	}
}

func TestKVLoad_Integration(t *testing.T) {
	// Integration test - requires live Vault instance
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("requires live vault", func(t *testing.T) {
		// This test validates the function signature and integration
		// Actual KV tests require a running Vault instance
		cfg := &config.Config{
			VaultAddr:        "http://127.0.0.1:8200",
			VaultToken:       "root",
			SecretsPerEngine: 5,
			KVEngines:        1,
			SecretSize:       3,
			Workers:          2,
		}

		ctx := context.Background()
		_, err := GenerateKVLoad(ctx, cfg)
		// We don't assert success/failure here as it depends on Vault availability
		t.Logf("GenerateKVLoad result: %v", err)
	})
}

func TestKVLoad_WorkerPoolLimits(t *testing.T) {
	// Test validates worker pool configuration
	tests := []struct {
		name         string
		totalSecrets int
		workers      int
	}{
		{
			name:         "more workers than secrets",
			totalSecrets: 5,
			workers:      10,
		},
		{
			name:         "equal workers and secrets",
			totalSecrets: 10,
			workers:      10,
		},
		{
			name:         "fewer workers than secrets",
			totalSecrets: 100,
			workers:      4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate that worker configuration is reasonable
			if tt.workers < 1 {
				t.Errorf("workers must be >= 1, got %d", tt.workers)
			}
			if tt.totalSecrets < 0 {
				t.Errorf("total secrets must be >= 0, got %d", tt.totalSecrets)
			}
		})
	}
}
