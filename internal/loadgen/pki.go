package loadgen

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/vault/api"
	"golang.org/x/sync/errgroup"

	"github.com/nhsy/vault-loadgen/internal/client"
	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/ratelimit"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

// GeneratePKILoad generates PKI certificate leases for load testing
// Works in both multi-namespace mode (distributes across namespaces) and single-namespace mode
func GeneratePKILoad(ctx context.Context, cfg *config.Config) (*stats.Stats, error) {
	// Validate config
	if cfg.PKILeases < 1 {
		return nil, fmt.Errorf("pki-leases must be at least 1, got %d", cfg.PKILeases)
	}

	// Create Vault client
	vaultClient, err := client.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Validate authentication
	if err := client.ValidateAuth(vaultClient); err != nil {
		return nil, fmt.Errorf("authentication validation failed: %w", err)
	}

	st := stats.New()

	// Determine namespaces to use
	namespaces := []string{}
	if cfg.CreateNamespaces && cfg.Namespaces > 0 {
		// Multi-namespace mode: create child namespaces
		slog.Info("pki mode: creating child namespaces", "count", cfg.Namespaces)
		createdNamespaces, err := CreateNamespaces(ctx, cfg)
		if err != nil {
			return st, fmt.Errorf("failed to create namespaces: %w", err)
		}
		namespaces = createdNamespaces
	} else {
		// Single-namespace mode: use parent namespace or root
		slog.Info("pki mode: using single-namespace mode", "namespace", cfg.ParentNamespace)
		namespaces = []string{cfg.ParentNamespace}
	}

	slog.Info("pki mode: setting up PKI engines", "namespaces", len(namespaces))

	// Setup PKI engines in each namespace
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		if err := setupPKIEngine(ctx, vaultClient, ns, cfg.PKITTL, cfg.PKIRootCATTL); err != nil {
			slog.Error("failed to setup PKI engine", "namespace", ns, "error", err)
			return st, fmt.Errorf("failed to setup PKI engine in namespace %q: %w", ns, err)
		}
		slog.Debug("pki engine setup complete", "namespace", ns)
	}

	// Calculate leases per namespace
	leasesPerNamespace := cfg.PKILeases / len(namespaces)
	remainder := cfg.PKILeases % len(namespaces)

	slog.Info("pki mode: generating certificate leases",
		"total_leases", cfg.PKILeases,
		"namespaces", len(namespaces),
		"leases_per_namespace", leasesPerNamespace)

	// Create rate limiter
	limiter := ratelimit.New(cfg.RateLimit)
	if cfg.RateLimit > 0 {
		slog.Info("rate limiting enabled", "ops_per_second", cfg.RateLimit)
	}

	// Generate certificates using worker pool
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.Workers)

	leaseIndex := 0
	for nsIndex, ns := range namespaces {
		// Calculate leases for this namespace
		leasesForNS := leasesPerNamespace
		if nsIndex < remainder {
			leasesForNS++ // Distribute remainder across first namespaces
		}

		// Generate certificates for this namespace
		for i := 0; i < leasesForNS; i++ {
			ns := ns // Capture for goroutine
			leaseIndex++
			commonName := formatCommonName(cfg.PKICommonName, leaseIndex)

			g.Go(func() error {
				// Wait for rate limiter
				if err := limiter.Wait(ctx); err != nil {
					return err
				}

				if err := ctx.Err(); err != nil {
					return err
				}

				if err := generateCertificateLease(ctx, vaultClient, ns, commonName, cfg.PKIKeySize); err != nil {
					slog.Warn("failed to generate certificate", "namespace", ns, "cn", commonName, "error", err)
					st.IncLeasesFailed()
					return nil // Don't stop other workers
				}

				st.IncLeasesCreated()
				return nil
			})
		}
	}

	// Wait for all workers
	if err := g.Wait(); err != nil {
		return st, err
	}

	st.End()

	// Log summary
	slog.Info("pki mode complete",
		"created", st.LeasesCreated,
		"failed", st.LeasesFailed,
		"duration", st.Duration(),
		"leases_per_sec", st.LeasesPerSecond())

	return st, nil
}

// setupPKIEngine enables and configures a PKI secrets engine in the given namespace
func setupPKIEngine(ctx context.Context, vaultClient *api.Client, namespace string, certTTL string, rootCATTL string) error {
	// Create a client for this namespace
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	// Enable PKI secrets engine
	// Note: max_lease_ttl must be at least as long as the ROOT CA TTL
	pkiPath := "pki"
	mountInput := &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			MaxLeaseTTL: rootCATTL, // Use ROOT CA TTL as mount max to allow CA generation
		},
	}

	err = nsClient.Sys().Mount(pkiPath, mountInput)
	if err != nil {
		// Check if already mounted
		if strings.Contains(err.Error(), "path is already in use") {
			slog.Debug("pki engine already mounted", "namespace", namespace, "path", pkiPath)
		} else {
			return fmt.Errorf("failed to mount pki engine: %w", err)
		}
	}

	// Generate root CA with configurable TTL (default: 7 days as per requirements)
	// CA TTL should be longer than the certificate TTLs it will sign
	caData := map[string]interface{}{
		"common_name": "Root CA",
		"ttl":         rootCATTL,
	}

	_, err = nsClient.Logical().Write(pkiPath+"/root/generate/internal", caData)
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}

	// Create role for certificate signing
	roleData := map[string]interface{}{
		"allowed_domains":    []string{"example.com", "*.example.com"},
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"allow_localhost":    true,
		"max_ttl":            certTTL, // Max TTL for issued certificates
	}

	_, err = nsClient.Logical().Write(pkiPath+"/roles/loadtest", roleData)
	if err != nil {
		return fmt.Errorf("failed to create pki role: %w", err)
	}

	return nil
}

// generateCertificateLease generates a certificate lease by creating a CSR and signing it
func generateCertificateLease(ctx context.Context, vaultClient *api.Client, namespace string, commonName string, keySize int) error {
	// Create CSR
	csrPEM, _, err := createCSR(commonName, keySize)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// Create a client for this namespace
	nsClient, err := vaultClient.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone client: %w", err)
	}

	if namespace != "" {
		nsClient.SetNamespace(namespace)
	}

	// Sign the certificate
	pkiPath := "pki"
	signData := map[string]interface{}{
		"csr":         csrPEM,
		"common_name": commonName,
	}

	secret, err := nsClient.Logical().Write(pkiPath+"/sign/loadtest", signData)
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("no secret returned from certificate signing")
	}

	slog.Debug("certificate generated", "namespace", namespace, "cn", commonName, "lease_id", secret.LeaseID)
	return nil
}

// createCSR creates a Certificate Signing Request with the given common name
func createCSR(commonName string, keySize int) (string, *rsa.PrivateKey, error) {
	// Validate key size
	if keySize != 2048 && keySize != 4096 {
		return "", nil, fmt.Errorf("invalid key size: %d (must be 2048 or 4096)", keySize)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), privateKey, nil
}

// formatCommonName formats the common name pattern with the given index
func formatCommonName(pattern string, index int) string {
	return strings.ReplaceAll(pattern, "{index}", fmt.Sprintf("%d", index))
}
