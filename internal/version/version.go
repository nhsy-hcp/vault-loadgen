package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the main version number that is being run at the moment.
	Version = "0.1.0"

	// GitCommit is the git commit that was compiled. This will be filled in by the compiler.
	GitCommit = "dev"

	// BuildDate is the date the binary was built
	BuildDate = "unknown"
)

// GetVersion returns the full version string
func GetVersion() string {
	return fmt.Sprintf("vault-loadgen v%s", Version)
}

// GetFullVersion returns the full version string with build information
func GetFullVersion() string {
	return fmt.Sprintf("vault-loadgen v%s (commit: %s, built: %s, go: %s)",
		Version, GitCommit, BuildDate, runtime.Version())
}
