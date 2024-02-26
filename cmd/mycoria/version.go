package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// Version is the version of this command.
var Version = "dev build"

func init() {
	// Convert version string space placeholders.
	Version = strings.ReplaceAll(Version, "§", " ")

	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use: "version",
	Run: version,
}

func version(cmd *cobra.Command, args []string) {
	// Get build info.
	buildInfo, _ := debug.ReadBuildInfo()
	buildSettings := make(map[string]string)
	for _, setting := range buildInfo.Settings {
		buildSettings[setting.Key] = setting.Value
	}

	// Print version info.
	fmt.Printf("Mycoria %s\n", Version)
	fmt.Printf("  Go %s %s %s\n", buildInfo.GoVersion, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  From %s\n", buildInfo.Path)
	fmt.Printf("  Commit %s @%s dirty=%s\n", buildSettings["vcs.revision"], buildSettings["vcs.time"], buildSettings["vcs.modified"])
}
