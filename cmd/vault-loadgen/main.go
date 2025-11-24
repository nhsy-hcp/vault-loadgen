package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/loadgen"
	"github.com/nhsy/vault-loadgen/internal/shutdown"
	"github.com/nhsy/vault-loadgen/internal/version"
)

const (
	exitSuccess = 0
	exitError   = 1
)

var (
	cfg *config.Config
)

func main() {
	os.Exit(run())
}

func run() int {
	if err := rootCmd.Execute(); err != nil {
		return exitError
	}
	return exitSuccess
}

var rootCmd = &cobra.Command{
	Use:     "vault-loadgen",
	Short:   "A load testing tool for HashiCorp Vault",
	Version: version.GetVersion(),
	Long: `vault-loadgen is a CLI tool for generating synthetic load on HashiCorp Vault clusters.

It supports three operational modes:
  - PKI Mode: Generate certificate leases through PKI secret engines
  - AppRole Mode: Create AppRole credentials and token leases
  - KV Mode: Populate KV v2 secrets engines with random secrets`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Set up logging
		setupLogging(cfg.LogLevel)

		// Validate configuration
		if err := cfg.Validate(); err != nil {
			slog.Error("configuration validation failed", "error", err)
			return err
		}

		return nil
	},
}

var pkiCmd = &cobra.Command{
	Use:          "pki",
	Short:        "Generate PKI certificate leases",
	Long:         "Generate certificate leases through PKI secret engines with configurable TTL and key sizes",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = "pki"
		return runPKIMode()
	},
}

var approleCmd = &cobra.Command{
	Use:          "approle",
	Short:        "Generate AppRole token leases with authenticated operations",
	Long:         "Create AppRole credentials, generate token leases, and perform authenticated secret reads to simulate realistic application load",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = "approle"
		return runAppRoleMode()
	},
}

var kvCmd = &cobra.Command{
	Use:          "kv",
	Short:        "Populate KV v2 secrets engines",
	Long:         "Write random secrets to KV v2 secrets engines across namespaces",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg.Mode = "kv"
		return runKVMode()
	},
}

func init() {
	cfg = config.NewDefault()

	// Initialize Viper
	viper.SetEnvPrefix("VAULT")
	viper.AutomaticEnv()

	// Set custom version template to show full version info
	rootCmd.SetVersionTemplate(version.GetFullVersion() + "\n")

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfg.VaultAddr, "vault-addr", "", "Vault server address")
	rootCmd.PersistentFlags().StringVar(&cfg.VaultToken, "vault-token", "", "Vault authentication token")
	rootCmd.PersistentFlags().StringVar(&cfg.VaultCACert, "vault-cacert", "", "Path to CA certificate for Vault TLS")
	rootCmd.PersistentFlags().BoolVar(&cfg.VaultSkipVerify, "vault-skip-verify", false, "Skip TLS certificate verification (insecure)")
	rootCmd.PersistentFlags().StringVar(&cfg.ParentNamespace, "parent-namespace", "", "Parent namespace for load test resources")

	rootCmd.PersistentFlags().IntVar(&cfg.Workers, "workers", 4, "Number of concurrent workers")
	rootCmd.PersistentFlags().IntVar(&cfg.Namespaces, "namespaces", 5, "Number of child namespaces to create (0 = single-namespace mode)")
	rootCmd.PersistentFlags().BoolVar(&cfg.CreateNamespaces, "create-namespaces", true, "Create child namespaces for load distribution")
	rootCmd.PersistentFlags().StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().Float64Var(&cfg.RateLimit, "rate-limit", 0, "Rate limit (operations per second, 0 = unlimited)")
	rootCmd.PersistentFlags().BoolVar(&cfg.DryRun, "dry-run", false, "Perform a dry run without making changes")
	rootCmd.PersistentFlags().StringVar(&cfg.Output, "output", "text", "Output format (text, json)")
	rootCmd.PersistentFlags().BoolVar(&cfg.Progress, "progress", true, "Show progress indicators")

	// Bind flags to Viper
	_ = viper.BindPFlag("addr", rootCmd.PersistentFlags().Lookup("vault-addr"))
	_ = viper.BindPFlag("token", rootCmd.PersistentFlags().Lookup("vault-token"))
	_ = viper.BindPFlag("cacert", rootCmd.PersistentFlags().Lookup("vault-cacert"))
	_ = viper.BindPFlag("skip_verify", rootCmd.PersistentFlags().Lookup("vault-skip-verify"))

	// Set defaults from environment variables
	if addr := viper.GetString("addr"); addr != "" && cfg.VaultAddr == "" {
		cfg.VaultAddr = addr
	}
	if token := viper.GetString("token"); token != "" && cfg.VaultToken == "" {
		cfg.VaultToken = token
	}
	if cacert := viper.GetString("cacert"); cacert != "" && cfg.VaultCACert == "" {
		cfg.VaultCACert = cacert
	}
	if skipVerify := viper.GetBool("skip_verify"); skipVerify && !cfg.VaultSkipVerify {
		cfg.VaultSkipVerify = skipVerify
	}

	// PKI command flags
	pkiCmd.Flags().IntVar(&cfg.PKILeases, "pki-leases", 100, "Number of PKI certificate leases to generate")
	pkiCmd.Flags().StringVar(&cfg.PKITTL, "pki-ttl", "24h", "TTL for PKI certificates")
	pkiCmd.Flags().StringVar(&cfg.PKIRootCATTL, "pki-root-ca-ttl", "168h", "TTL for PKI root CA (default: 7 days)")
	pkiCmd.Flags().IntVar(&cfg.PKIKeySize, "pki-key-size", 2048, "Key size for PKI certificates (2048 or 4096)")
	pkiCmd.Flags().StringVar(&cfg.PKICommonName, "pki-common-name", "loadtest-{index}.example.com", "Common name pattern for PKI certificates")

	// AppRole command flags
	approleCmd.Flags().IntVar(&cfg.AppRoleLogins, "approle-logins", 100, "Number of AppRole logins to perform")
	approleCmd.Flags().StringVar(&cfg.SecretIDTTL, "secret-id-ttl", "1h", "TTL for AppRole secret IDs")
	approleCmd.Flags().StringVar(&cfg.TokenTTL, "token-ttl", "1h", "TTL for AppRole tokens")
	approleCmd.Flags().StringVar(&cfg.TokenMaxTTL, "token-max-ttl", "2h", "Max TTL for AppRole tokens")

	// KV command flags
	kvCmd.Flags().IntVar(&cfg.KVEngines, "kv-engines", 1, "Number of KV engines to create")
	kvCmd.Flags().IntVar(&cfg.SecretsPerEngine, "secrets-per-engine", 100, "Number of secrets per KV engine")
	kvCmd.Flags().IntVar(&cfg.SecretSize, "secret-size", 5, "Number of key-value pairs per secret")

	// Add subcommands
	rootCmd.AddCommand(pkiCmd)
	rootCmd.AddCommand(approleCmd)
	rootCmd.AddCommand(kvCmd)
}

func runPKIMode() error {
	// Create shutdown handler
	sh := shutdown.NewHandler()
	sh.Start()
	defer sh.Stop()

	ctx := sh.Context()

	slog.Info("starting vault load test", "mode", "pki")

	stats, err := loadgen.GeneratePKILoad(ctx, cfg)
	if err != nil {
		slog.Error("pki mode failed", "error", err)
		return err
	}

	// Display formatted summary
	stats.PrintSummary("PKI")

	if stats.LeasesFailed > 0 {
		slog.Warn("pki mode completed with failures", "failed_count", stats.LeasesFailed)
		return fmt.Errorf("pki mode completed with %d failures", stats.LeasesFailed)
	}

	return nil
}

func runAppRoleMode() error {
	// Create shutdown handler
	sh := shutdown.NewHandler()
	sh.Start()
	defer sh.Stop()

	ctx := sh.Context()

	slog.Info("starting vault load test", "mode", "approle")

	stats, err := loadgen.GenerateAppRoleLoad(ctx, cfg)
	if err != nil {
		slog.Error("approle mode failed", "error", err)
		return err
	}

	// Display formatted summary
	stats.PrintSummary("AppRole")

	if stats.LeasesFailed > 0 {
		slog.Warn("approle mode completed with failures", "failed_count", stats.LeasesFailed)
		return fmt.Errorf("approle mode completed with %d failures", stats.LeasesFailed)
	}

	return nil
}

func runKVMode() error {
	// Create shutdown handler
	sh := shutdown.NewHandler()
	sh.Start()
	defer sh.Stop()

	ctx := sh.Context()

	slog.Info("starting vault load test", "mode", "kv")

	stats, err := loadgen.GenerateKVLoad(ctx, cfg)
	if err != nil {
		slog.Error("kv mode failed", "error", err)
		return err
	}

	// Display formatted summary
	stats.PrintSummary("KV")

	if stats.SecretsFailed > 0 {
		slog.Warn("kv mode completed with failures", "failed_count", stats.SecretsFailed)
		return fmt.Errorf("kv mode completed with %d failures", stats.SecretsFailed)
	}

	return nil
}

func setupLogging(level string) {
	var logLevel slog.Level

	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)
}
