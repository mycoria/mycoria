package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/mycoria/mycoria"
	"github.com/mycoria/mycoria/config"
)

func init() {
	rootCmd.AddCommand(runCmd)
}

var (
	runCmd = &cobra.Command{
		Use:  "run",
		RunE: run,
	}

	sigUSR1 = syscall.Signal(0xa)
)

func run(cmd *cobra.Command, args []string) error {
	c, err := config.LoadConfig(*configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Configure logging.
	logOutput := os.Stdout
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stdout, &tint.Options{
			AddSource:  true,
			Level:      slog.LevelDebug,
			TimeFormat: time.DateTime,
			NoColor:    !isatty.IsTerminal(logOutput.Fd()),
		}),
	))

	// Setup up everything.
	myco, err := mycoria.New(Version, c)
	if err != nil {
		return fmt.Errorf("failed to initialize mycoria: %w", err)
	}

	// Finalize and start all workers.
	err = myco.Start()
	if err != nil {
		return fmt.Errorf("failed to start mycoria: %w", err)
	}

	// Wait for signal.
	signalCh := make(chan os.Signal, 1)
	signal.Notify(
		signalCh,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		sigUSR1,
	)

signalLoop:
	for {
		select {
		case sig := <-signalCh:
			// Only print and continue to wait if SIGUSR1
			if sig == sigUSR1 {
				printStackTo(os.Stderr, "PRINTING STACK ON REQUEST")
				continue signalLoop
			}

			fmt.Println(" <INTERRUPT>") // CLI output.
			slog.Warn("program was interrupted, stopping")

			// catch signals during shutdown
			go func() {
				forceCnt := 5
				for {
					<-signalCh
					forceCnt--
					if forceCnt > 0 {
						fmt.Printf(" <INTERRUPT> again, but already shutting down - %d more to force\n", forceCnt)
					} else {
						printStackTo(os.Stderr, "PRINTING STACK ON FORCED EXIT")
						os.Exit(1)
					}
				}
			}()

			go func() {
				time.Sleep(3 * time.Minute)
				printStackTo(os.Stderr, "PRINTING STACK - TAKING TOO LONG FOR SHUTDOWN")
				os.Exit(1)
			}()

			if !myco.Stop() {
				slog.Error("failed to stop mycoria")
				os.Exit(1)
			}
			break signalLoop

		case <-myco.Done():
			break signalLoop
		}
	}

	return nil
}

func printStackTo(writer io.Writer, msg string) {
	_, err := fmt.Fprintf(writer, "===== %s =====\n", msg)
	if err == nil {
		err = pprof.Lookup("goroutine").WriteTo(writer, 1)
	}
	if err != nil {
		slog.Error("failed to write stack trace", "err", err)
	}
}
