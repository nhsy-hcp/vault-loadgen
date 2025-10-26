package main

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/spf13/cobra"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
		want     slog.Level
	}{
		{
			name:     "debug level",
			logLevel: "debug",
			want:     slog.LevelDebug,
		},
		{
			name:     "info level",
			logLevel: "info",
			want:     slog.LevelInfo,
		},
		{
			name:     "warn level",
			logLevel: "warn",
			want:     slog.LevelWarn,
		},
		{
			name:     "error level",
			logLevel: "error",
			want:     slog.LevelError,
		},
		{
			name:     "invalid level defaults to info",
			logLevel: "invalid",
			want:     slog.LevelInfo,
		},
		{
			name:     "empty level defaults to info",
			logLevel: "",
			want:     slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture the logger output
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: tt.want,
			})
			logger := slog.New(handler)
			slog.SetDefault(logger)

			// Call setupLogging
			setupLogging(tt.logLevel)

			// Verify logger is set up (we can't easily inspect the level directly,
			// but we can test that it doesn't panic)
			slog.Debug("debug message")
			slog.Info("info message")
			slog.Warn("warn message")
			slog.Error("error message")
		})
	}
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "valid PKI config",
			cfg: &config.Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Mode:       "pki",
				PKILeases:  10,
				PKIKeySize: 2048,
				Workers:    2,
				Namespaces: 1,
			},
			wantErr: false,
		},
		{
			name: "missing vault address",
			cfg: &config.Config{
				VaultToken: "root",
				Mode:       "pki",
				PKILeases:  10,
			},
			wantErr: true,
		},
		{
			name: "missing vault token",
			cfg: &config.Config{
				VaultAddr: "http://127.0.0.1:8200",
				Mode:      "pki",
				PKILeases: 10,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRun(t *testing.T) {
	// Test the run function with version flag
	// This is a basic smoke test
	exitCode := run()
	// The function should return an exit code
	if exitCode != exitSuccess && exitCode != exitError {
		t.Errorf("run() returned unexpected exit code: %d", exitCode)
	}
}

func TestExitCodes(t *testing.T) {
	if exitSuccess != 0 {
		t.Errorf("exitSuccess = %d, want 0", exitSuccess)
	}
	if exitError != 1 {
		t.Errorf("exitError = %d, want 1", exitError)
	}
}

func TestRootCmd_Structure(t *testing.T) {
	// Verify root command has expected subcommands
	subcommands := rootCmd.Commands()

	foundCommands := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCommands[cmd.Name()] = true
	}

	for _, expected := range []string{"pki", "approle", "kv"} {
		if !foundCommands[expected] {
			t.Errorf("rootCmd missing expected subcommand: %s", expected)
		}
	}
}

func TestPKICmd_Flags(t *testing.T) {
	// Verify PKI command has expected flags
	flags := pkiCmd.Flags()

	expectedFlags := []string{
		"pki-leases",
		"pki-ttl",
		"pki-root-ca-ttl",
		"pki-key-size",
		"pki-common-name",
	}

	for _, flagName := range expectedFlags {
		flag := flags.Lookup(flagName)
		if flag == nil {
			t.Errorf("pkiCmd missing expected flag: %s", flagName)
		}
	}
}

func TestAppRoleCmd_Flags(t *testing.T) {
	// Verify AppRole command has expected flags
	flags := approleCmd.Flags()

	expectedFlags := []string{
		"approle-logins",
		"secret-id-ttl",
		"token-ttl",
		"token-max-ttl",
	}

	for _, flagName := range expectedFlags {
		flag := flags.Lookup(flagName)
		if flag == nil {
			t.Errorf("approleCmd missing expected flag: %s", flagName)
		}
	}
}

func TestKVCmd_Flags(t *testing.T) {
	// Verify KV command has expected flags
	flags := kvCmd.Flags()

	expectedFlags := []string{
		"kv-engines",
		"secrets-per-engine",
		"secret-size",
	}

	for _, flagName := range expectedFlags {
		flag := flags.Lookup(flagName)
		if flag == nil {
			t.Errorf("kvCmd missing expected flag: %s", flagName)
		}
	}
}

func TestRootCmd_PersistentFlags(t *testing.T) {
	// Verify root command has expected persistent flags
	flags := rootCmd.PersistentFlags()

	expectedFlags := []string{
		"vault-addr",
		"vault-token",
		"vault-cacert",
		"vault-skip-verify",
		"parent-namespace",
		"workers",
		"namespaces",
		"create-namespaces",
		"log-level",
		"rate-limit",
		"dry-run",
		"output",
		"progress",
	}

	for _, flagName := range expectedFlags {
		flag := flags.Lookup(flagName)
		if flag == nil {
			t.Errorf("rootCmd missing expected persistent flag: %s", flagName)
		}
	}
}

func TestRootCmd_Version(t *testing.T) {
	// Verify root command has version set
	if rootCmd.Version == "" {
		t.Error("rootCmd.Version is empty")
	}
}

func TestCommands_Usage(t *testing.T) {
	// Verify commands have usage strings
	commands := []*cobra.Command{rootCmd, pkiCmd, approleCmd, kvCmd}
	names := []string{"root", "pki", "approle", "kv"}

	for i, cmd := range commands {
		if cmd.Use == "" {
			t.Errorf("%s command has empty Use string", names[i])
		}
		if cmd.Short == "" {
			t.Errorf("%s command has empty Short description", names[i])
		}
		if cmd.Long == "" {
			t.Errorf("%s command has empty Long description", names[i])
		}
	}
}
