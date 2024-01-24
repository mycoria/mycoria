package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Version is the version of this command.
const Version = "v0.0.1"

var (
	rootCmd = &cobra.Command{
		Use: "mycoria",
	}

	configFile = pflag.String("config", "", "set config file")
)

func main() {
	pflag.Parse()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
