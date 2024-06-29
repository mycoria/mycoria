package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	rootCmd = &cobra.Command{
		Use: "mycoria",
	}

	configFile = pflag.String("config", "", "set config file")
	logLevel   = pflag.String("log", "", "set log level")
	devMode    = pflag.Bool("devmode", false, "enable development mode")
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
