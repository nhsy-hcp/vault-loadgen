package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "default version",
			version: "0.1.0",
			want:    "vault-loadgen v0.1.0",
		},
		{
			name:    "development version",
			version: "dev",
			want:    "vault-loadgen vdev",
		},
		{
			name:    "semantic version",
			version: "1.2.3",
			want:    "vault-loadgen v1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original version
			originalVersion := Version
			defer func() { Version = originalVersion }()

			// Set test version
			Version = tt.version

			got := GetVersion()
			if got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetFullVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		gitCommit string
		buildDate string
	}{
		{
			name:      "development build",
			version:   "0.1.0",
			gitCommit: "dev",
			buildDate: "unknown",
		},
		{
			name:      "release build",
			version:   "1.0.0",
			gitCommit: "abc123",
			buildDate: "2024-01-01T00:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original values
			originalVersion := Version
			originalGitCommit := GitCommit
			originalBuildDate := BuildDate
			defer func() {
				Version = originalVersion
				GitCommit = originalGitCommit
				BuildDate = originalBuildDate
			}()

			// Set test values
			Version = tt.version
			GitCommit = tt.gitCommit
			BuildDate = tt.buildDate

			got := GetFullVersion()

			// Verify all components are present
			if !strings.Contains(got, "vault-loadgen v"+tt.version) {
				t.Errorf("GetFullVersion() missing version, got %v", got)
			}
			if !strings.Contains(got, "commit: "+tt.gitCommit) {
				t.Errorf("GetFullVersion() missing git commit, got %v", got)
			}
			if !strings.Contains(got, "built: "+tt.buildDate) {
				t.Errorf("GetFullVersion() missing build date, got %v", got)
			}
			if !strings.Contains(got, "go: "+runtime.Version()) {
				t.Errorf("GetFullVersion() missing go version, got %v", got)
			}
		})
	}
}

func TestVersionFormat(t *testing.T) {
	// Test that GetVersion returns expected format
	version := GetVersion()
	if !strings.HasPrefix(version, "vault-loadgen v") {
		t.Errorf("GetVersion() should start with 'vault-loadgen v', got %v", version)
	}
}

func TestFullVersionFormat(t *testing.T) {
	// Test that GetFullVersion contains all required components
	fullVersion := GetFullVersion()

	requiredComponents := []string{
		"vault-loadgen v",
		"commit:",
		"built:",
		"go:",
	}

	for _, component := range requiredComponents {
		if !strings.Contains(fullVersion, component) {
			t.Errorf("GetFullVersion() missing required component '%s', got %v", component, fullVersion)
		}
	}
}
