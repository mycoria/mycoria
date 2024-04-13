package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// Version is the version of this command.
	Version = "dev build"
	// BuildSource holds the primary source repo used to build.
	BuildSource = "unknown"
	// BuildTime holds the time when the binary was built.
	BuildTime = "unknown"
)

func init() {
	// Convert version string space placeholders.
	Version = strings.ReplaceAll(Version, "_", " ")
	BuildSource = strings.ReplaceAll(BuildSource, "_", " ")
	BuildTime = strings.ReplaceAll(BuildTime, "_", " ")

	// Get build info.
	buildInfo, _ := debug.ReadBuildInfo()
	buildSettings := make(map[string]string)
	for _, setting := range buildInfo.Settings {
		buildSettings[setting.Key] = setting.Value
	}

	// Add "dev build" to version if repo is dirty.
	if buildSettings["vcs.modified"] == "true" &&
		!strings.HasSuffix(Version, "dev build") {
		Version += " dev build"
	}

	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use: "version",
	Run: version,
}

func version(cmd *cobra.Command, args []string) {
	builder := new(strings.Builder)

	// Get build info.
	buildInfo, _ := debug.ReadBuildInfo()
	buildSettings := make(map[string]string)
	for _, setting := range buildInfo.Settings {
		buildSettings[setting.Key] = setting.Value
	}

	// Print version info.
	builder.WriteString(fmt.Sprintf("Mycoria %s\n", Version))

	// Build info.
	cgoInfo := "-cgo"
	if buildSettings["CGO_ENABLED"] == "1" {
		cgoInfo = "+cgo"
	}
	builder.WriteString(fmt.Sprintf("\nbuilt with %s (%s %s) for %s/%s\n", runtime.Version(), runtime.Compiler, cgoInfo, runtime.GOOS, runtime.GOARCH))
	builder.WriteString(fmt.Sprintf("  at %s\n", BuildTime))

	// Commit info.
	dirtyInfo := "clean"
	if buildSettings["vcs.modified"] == "true" {
		dirtyInfo = "dirty"
	}
	builder.WriteString(fmt.Sprintf("\ncommit %s (%s)\n", buildSettings["vcs.revision"], dirtyInfo))
	builder.WriteString(fmt.Sprintf("  at %s\n", buildSettings["vcs.time"]))
	builder.WriteString(fmt.Sprintf("  from %s\n", BuildSource))

	// License info.
	builder.WriteString("\nLicensed under the BSD-3-Clause license.")

	_, _ = fmt.Println(builder.String())
}
