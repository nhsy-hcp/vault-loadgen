package config

import (
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid pki config",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    4,
				Namespaces: 5,
				PKILeases:  100,
				PKIKeySize: 2048,
			},
			wantErr: false,
		},
		{
			name: "missing vault address",
			config: Config{
				VaultToken: "root",
				Mode:       "pki",
			},
			wantErr: true,
			errMsg:  "vault address is required",
		},
		{
			name: "missing vault token",
			config: Config{
				VaultAddr: "http://127.0.0.1:8200",
				Mode:      "pki",
			},
			wantErr: true,
			errMsg:  "vault token is required",
		},
		{
			name: "workers too high",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    150,
				Namespaces: 5,
			},
			wantErr: true,
			errMsg:  "workers must be between 1 and 32",
		},
		{
			name: "workers too low",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    0,
				Namespaces: 5,
			},
			wantErr: true,
			errMsg:  "workers must be between 1 and 32",
		},
		{
			name: "namespaces too high",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    4,
				Namespaces: 1500,
			},
			wantErr: true,
			errMsg:  "namespaces must be between 0 and 1000",
		},
		{
			name: "pki invalid key size",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    4,
				Namespaces: 5,
				PKILeases:  100,
				PKIKeySize: 1024,
			},
			wantErr: true,
			errMsg:  "pki-key-size must be 2048 or 4096",
		},
		{
			name: "pki missing leases",
			config: Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    4,
				Namespaces: 5,
				PKILeases:  0,
			},
			wantErr: true,
			errMsg:  "pki-leases must be >= 1",
		},
		{
			name: "valid approle config",
			config: Config{
				VaultAddr:     "http://127.0.0.1:8200",
				VaultToken:    "root",
				Mode:          "approle",
				Workers:       4,
				Namespaces:    5,
				AppRoleLogins: 100,
			},
			wantErr: false,
		},
		{
			name: "approle missing logins",
			config: Config{
				VaultAddr:     "http://127.0.0.1:8200",
				VaultToken:    "root",
				Mode:          "approle",
				Workers:       4,
				Namespaces:    5,
				AppRoleLogins: 0,
			},
			wantErr: true,
			errMsg:  "approle-logins must be >= 1",
		},
		{
			name: "valid kv config",
			config: Config{
				VaultAddr:        "http://127.0.0.1:8200",
				VaultToken:       "root",
				Mode:             "kv",
				Workers:          4,
				Namespaces:       5,
				SecretsPerEngine: 100,
			},
			wantErr: false,
		},
		{
			name: "kv missing secrets per engine",
			config: Config{
				VaultAddr:        "http://127.0.0.1:8200",
				VaultToken:       "root",
				Mode:             "kv",
				Workers:          4,
				Namespaces:       5,
				SecretsPerEngine: 0,
			},
			wantErr: true,
			errMsg:  "secrets-per-engine must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestNewDefault_VaultOSSCompatible(t *testing.T) {
	cfg := NewDefault()

	if cfg.Namespaces != 0 {
		t.Errorf("expected Namespaces=0 for single-namespace mode, got %d", cfg.Namespaces)
	}

	// Validate should pass with default values
	cfg.VaultAddr = "http://127.0.0.1:8200"
	cfg.VaultToken = "root"
	cfg.Mode = "pki"

	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestValidate_NamespaceMode(t *testing.T) {
	tests := []struct {
		name       string
		namespaces int
		wantErr    bool
	}{
		{
			name:       "single-namespace mode",
			namespaces: 0,
			wantErr:    false,
		},
		{
			name:       "multi-namespace mode",
			namespaces: 10,
			wantErr:    false,
		},
		{
			name:       "max namespaces",
			namespaces: 1000,
			wantErr:    false,
		},
		{
			name:       "negative namespaces invalid",
			namespaces: -1,
			wantErr:    true,
		},
		{
			name:       "over max namespaces invalid",
			namespaces: 1001,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				Workers:    4,
				Namespaces: tt.namespaces,
				PKILeases:  100,
				PKIKeySize: 2048,
			}

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_ParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "valid hours",
			duration: "24h",
			want:     24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "valid minutes",
			duration: "30m",
			want:     30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "valid seconds",
			duration: "60s",
			want:     60 * time.Second,
			wantErr:  false,
		},
		{
			name:     "combined duration",
			duration: "1h30m",
			want:     90 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "invalid duration",
			duration: "invalid",
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := time.ParseDuration(tt.duration)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
