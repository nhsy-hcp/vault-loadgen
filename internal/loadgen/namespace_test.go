package loadgen

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nhsy/vault-loadgen/internal/config"
	"github.com/nhsy/vault-loadgen/internal/stats"
)

func TestGenerateNamespaceNames(t *testing.T) {
	tests := []struct {
		name       string
		parent     string
		count      int
		wantPrefix string
		wantCount  int
	}{
		{
			name:       "no parent namespace",
			parent:     "",
			count:      5,
			wantPrefix: "loadtest-",
			wantCount:  5,
		},
		{
			name:       "with parent namespace",
			parent:     "admin",
			count:      3,
			wantPrefix: "loadtest-",
			wantCount:  3,
		},
		{
			name:       "single namespace",
			parent:     "",
			count:      1,
			wantPrefix: "loadtest-",
			wantCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := GenerateNamespaceNames(tt.parent, tt.count)

			if len(names) != tt.wantCount {
				t.Errorf("GenerateNamespaceNames() returned %d names, want %d", len(names), tt.wantCount)
			}

			for i, name := range names {
				if len(name) == 0 {
					t.Errorf("GenerateNamespaceNames() name[%d] is empty", i)
				}
				// Each name should have the prefix
				if len(name) < len(tt.wantPrefix) {
					t.Errorf("GenerateNamespaceNames() name[%d] = %q, too short", i, name)
				}
			}

			// Verify uniqueness
			seen := make(map[string]bool)
			for _, name := range names {
				if seen[name] {
					t.Errorf("GenerateNamespaceNames() duplicate name: %q", name)
				}
				seen[name] = true
			}
		})
	}
}

func TestValidateNamespaceName(t *testing.T) {
	tests := []struct {
		name    string
		nsName  string
		wantErr bool
	}{
		{
			name:    "valid name",
			nsName:  "test-namespace",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			nsName:  "test-123",
			wantErr: false,
		},
		{
			name:    "valid with underscores",
			nsName:  "test_namespace",
			wantErr: false,
		},
		{
			name:    "empty name",
			nsName:  "",
			wantErr: true,
		},
		{
			name:    "name with spaces",
			nsName:  "test namespace",
			wantErr: true,
		},
		{
			name:    "name with special chars",
			nsName:  "test@namespace",
			wantErr: true,
		},
		{
			name:    "name starting with number",
			nsName:  "123test",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNamespaceName(tt.nsName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNamespaceName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsNamespaceExistsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "namespace exists error",
			err:  errors.New("namespace already exists"),
			want: true,
		},
		{
			name: "namespace path in use",
			err:  errors.New("namespace path is already in use"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("permission denied"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNamespaceExistsError(tt.err)
			if got != tt.want {
				t.Errorf("IsNamespaceExistsError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPermissionDeniedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "permission denied",
			err:  errors.New("permission denied"),
			want: true,
		},
		{
			name: "access denied",
			err:  errors.New("access denied"),
			want: true,
		},
		{
			name: "insufficient permissions",
			err:  errors.New("insufficient permissions"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("namespace already exists"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPermissionDeniedError(tt.err)
			if got != tt.want {
				t.Errorf("IsPermissionDeniedError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateNamespaces_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "zero namespaces",
			cfg: &config.Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Namespaces: 0,
				Workers:    4,
			},
			wantErr: true,
			errMsg:  "namespace count must be at least 1",
		},
		{
			name: "negative namespaces",
			cfg: &config.Config{
				VaultAddr:  "http://127.0.0.1:8200",
				VaultToken: "root",
				Namespaces: -1,
				Workers:    4,
			},
			wantErr: true,
			errMsg:  "namespace count must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateNamespaces(ctx, tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateNamespaces() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("CreateNamespaces() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestBuildFullNamespacePath(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   string
	}{
		{
			name:   "no parent",
			parent: "",
			child:  "test",
			want:   "test",
		},
		{
			name:   "with parent",
			parent: "admin",
			child:  "test",
			want:   "admin/test",
		},
		{
			name:   "nested parent",
			parent: "admin/dev",
			child:  "test-123",
			want:   "admin/dev/test-123",
		},
		{
			name:   "parent with trailing slash",
			parent: "admin/",
			child:  "test",
			want:   "admin/test",
		},
		{
			name:   "child with leading slash",
			parent: "admin",
			child:  "/test",
			want:   "admin/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFullNamespacePath(tt.parent, tt.child)
			if got != tt.want {
				t.Errorf("BuildFullNamespacePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespaceStats_Integration(t *testing.T) {
	s := stats.New()

	// Simulate namespace creation
	s.IncNamespacesCreated()
	s.IncNamespacesCreated()
	s.IncNamespacesCreated()
	s.IncNamespacesSkipped()
	s.IncNamespacesFailed()

	if s.NamespacesCreated != 3 {
		t.Errorf("NamespacesCreated = %d, want 3", s.NamespacesCreated)
	}
	if s.NamespacesSkipped != 1 {
		t.Errorf("NamespacesSkipped = %d, want 1", s.NamespacesSkipped)
	}
	if s.NamespacesFailed != 1 {
		t.Errorf("NamespacesFailed = %d, want 1", s.NamespacesFailed)
	}

	total := s.TotalOperations()
	if total != 5 {
		t.Errorf("TotalOperations() = %d, want 5", total)
	}
}

func TestCreateNamespaces_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &config.Config{
		VaultAddr:  "http://127.0.0.1:8200",
		VaultToken: "root",
		Namespaces: 5,
		Workers:    2,
	}

	_, err := CreateNamespaces(ctx, cfg)
	if err == nil {
		t.Error("CreateNamespaces() with cancelled context should return error")
	}
	// The error could be context-related or connection-related since context
	// cancellation is checked at different points
	t.Logf("CreateNamespaces() with cancelled context error: %v", err)
}

func TestCreateNamespaces_InvalidVaultAddr(t *testing.T) {
	ctx := context.Background()

	cfg := &config.Config{
		VaultAddr:  "",
		VaultToken: "root",
		Namespaces: 5,
		Workers:    2,
	}

	_, err := CreateNamespaces(ctx, cfg)
	if err == nil {
		t.Error("CreateNamespaces() with empty vault address should return error")
	}
}

func TestIsNamespaceNotSupportedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "unsupported path error",
			err:  errors.New("unsupported path"),
			want: true,
		},
		{
			name: "unsupported operation error",
			err:  errors.New("unsupported operation"),
			want: true,
		},
		{
			name: "unknown command error",
			err:  errors.New("unknown command"),
			want: true,
		},
		{
			name: "enterprise-only error",
			err:  errors.New("This feature is enterprise-only"),
			want: true,
		},
		{
			name: "vault enterprise feature error",
			err:  errors.New("feature is part of vault enterprise"),
			want: true,
		},
		{
			name: "namespace feature requires vault enterprise",
			err:  errors.New("namespace feature requires vault enterprise"),
			want: true,
		},
		{
			name: "case insensitive - UNSUPPORTED PATH",
			err:  errors.New("UNSUPPORTED PATH"),
			want: true,
		},
		{
			name: "case insensitive - ENTERPRISE-ONLY",
			err:  errors.New("FEATURE IS ENTERPRISE-ONLY"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection timeout"),
			want: false,
		},
		{
			name: "permission error (not OSS)",
			err:  errors.New("permission denied"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNamespaceNotSupportedError(tt.err)
			if got != tt.want {
				t.Errorf("IsNamespaceNotSupportedError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatOSSNamespaceError(t *testing.T) {
	err := FormatOSSNamespaceError()

	if err == nil {
		t.Fatal("FormatOSSNamespaceError() returned nil")
	}

	errMsg := err.Error()

	// Check that error message contains key information
	expectedPhrases := []string{
		"Vault OSS",
		"Enterprise-only",
		"--namespaces=0",
		"single-namespace mode",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(errMsg, phrase) {
			t.Errorf("FormatOSSNamespaceError() message should contain %q, got: %s", phrase, errMsg)
		}
	}

	// Verify it provides actionable guidance
	if !strings.Contains(errMsg, "root namespace") {
		t.Error("FormatOSSNamespaceError() should mention root namespace")
	}
}
