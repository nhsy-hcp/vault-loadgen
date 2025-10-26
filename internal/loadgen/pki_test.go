package loadgen

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
)

func TestCreateCSR(t *testing.T) {
	tests := []struct {
		name        string
		commonName  string
		keySize     int
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid CSR with 2048 bit key",
			commonName: "test.example.com",
			keySize:    2048,
			wantErr:    false,
		},
		{
			name:       "valid CSR with 4096 bit key",
			commonName: "test.example.com",
			keySize:    4096,
			wantErr:    false,
		},
		{
			name:        "invalid key size 1024",
			commonName:  "test.example.com",
			keySize:     1024,
			wantErr:     true,
			errContains: "invalid key size",
		},
		{
			name:        "invalid key size 8192",
			commonName:  "test.example.com",
			keySize:     8192,
			wantErr:     true,
			errContains: "invalid key size",
		},
		{
			name:       "common name with subdomain",
			commonName: "app.prod.example.com",
			keySize:    2048,
			wantErr:    false,
		},
		{
			name:       "common name with wildcard",
			commonName: "*.example.com",
			keySize:    2048,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrPEM, privateKey, err := createCSR(tt.commonName, tt.keySize)

			if (err != nil) != tt.wantErr {
				t.Errorf("createCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("createCSR() error = %v, should contain %q", err, tt.errContains)
				}
				return
			}

			// Verify CSR is valid PEM
			block, _ := pem.Decode([]byte(csrPEM))
			if block == nil {
				t.Error("createCSR() returned invalid PEM")
				return
			}

			if block.Type != "CERTIFICATE REQUEST" {
				t.Errorf("createCSR() PEM type = %s, want CERTIFICATE REQUEST", block.Type)
			}

			// Parse CSR
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Errorf("createCSR() returned invalid CSR: %v", err)
				return
			}

			// Verify common name
			if csr.Subject.CommonName != tt.commonName {
				t.Errorf("createCSR() CommonName = %s, want %s", csr.Subject.CommonName, tt.commonName)
			}

			// Verify DNS names
			if len(csr.DNSNames) == 0 {
				t.Error("createCSR() DNSNames is empty")
			} else if csr.DNSNames[0] != tt.commonName {
				t.Errorf("createCSR() DNSNames[0] = %s, want %s", csr.DNSNames[0], tt.commonName)
			}

			// Verify private key
			if privateKey == nil {
				t.Error("createCSR() returned nil private key")
				return
			}

			// Verify key size (validate() checks the size)
			if err := privateKey.Validate(); err != nil {
				t.Errorf("createCSR() returned invalid private key: %v", err)
			}
		})
	}
}

func TestFormatCommonName(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		index   int
		want    string
	}{
		{
			name:    "basic pattern",
			pattern: "loadtest-{index}.example.com",
			index:   1,
			want:    "loadtest-1.example.com",
		},
		{
			name:    "pattern with index 0",
			pattern: "cert-{index}.test.com",
			index:   0,
			want:    "cert-0.test.com",
		},
		{
			name:    "pattern with large index",
			pattern: "server-{index}.prod.example.com",
			index:   9999,
			want:    "server-9999.prod.example.com",
		},
		{
			name:    "pattern without placeholder",
			pattern: "static.example.com",
			index:   42,
			want:    "static.example.com",
		},
		{
			name:    "pattern with multiple placeholders",
			pattern: "server-{index}-app-{index}.example.com",
			index:   5,
			want:    "server-5-app-5.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCommonName(tt.pattern, tt.index)
			if got != tt.want {
				t.Errorf("formatCommonName() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestGeneratePKILoad_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		leases      int
		wantErr     bool
		errContains string
	}{
		{
			name:        "zero leases",
			leases:      0,
			wantErr:     true,
			errContains: "pki-leases must be at least 1",
		},
		{
			name:        "negative leases",
			leases:      -1,
			wantErr:     true,
			errContains: "pki-leases must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				PKILeases:  tt.leases,
				PKITTL:     "24h",
				PKIKeySize: 2048,
			}

			_, err := GeneratePKILoad(ctx, cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePKILoad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("GeneratePKILoad() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestCreateCSR_KeySizes(t *testing.T) {
	// Test that different key sizes produce different sized keys
	csrPEM2048, key2048, err := createCSR("test.example.com", 2048)
	if err != nil {
		t.Fatalf("createCSR(2048) failed: %v", err)
	}

	csrPEM4096, key4096, err := createCSR("test.example.com", 4096)
	if err != nil {
		t.Fatalf("createCSR(4096) failed: %v", err)
	}

	// Verify 2048 bit key
	if key2048.N.BitLen() != 2048 {
		t.Errorf("2048-bit key has %d bits", key2048.N.BitLen())
	}

	// Verify 4096 bit key
	if key4096.N.BitLen() != 4096 {
		t.Errorf("4096-bit key has %d bits", key4096.N.BitLen())
	}

	// Verify CSR PEMs are different sizes
	if len(csrPEM2048) >= len(csrPEM4096) {
		t.Error("Expected 4096-bit CSR to be larger than 2048-bit CSR")
	}
}

func TestCreateCSR_ParseValidity(t *testing.T) {
	// Ensure CSR can be parsed by x509 library
	commonName := "app.example.com"
	csrPEM, _, err := createCSR(commonName, 2048)
	if err != nil {
		t.Fatalf("createCSR() failed: %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}
}
