package main

import (
	"github.com/rokmetro/auth-library/envloader"
	"github.com/rokmetro/logging-library/logs"
)

var (
	// Version : version of this executable
	Version string
	// Build : build date of this executable
	Build string
)

func main() {
	if len(Version) == 0 {
		Version = "dev"
	}

	logger := logs.NewLogger("sample", nil)
	envLoader := envloader.NewEnvLoader(Version, logger)

	envVar := envLoader.GetEnvVar("SAMPLE_ENV_VAR", false)
	requiredVar := envLoader.GetEnvVar("REQUIRED_ENV_VAR", true)

	logger.Infof("SAMPLE_ENV_VAR = %s, REQUIRED_ENV_VAR = %s", envVar, requiredVar)
}
