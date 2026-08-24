package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"goshs.de/goshs/v2/config"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/sanity"
	"goshs.de/goshs/v2/server"
	"goshs.de/goshs/v2/tui"
)

func main() {
	var err error

	// flags
	opts, print := options.Parse()

	// Print config
	if print {
		config, err := config.PrintExample()
		if err != nil {
			panic(err)
		}
		fmt.Println(config)
		os.Exit(0)
	}

	// Load config
	if opts.ConfigFile != "" {
		opts, err = config.LoadConfig(opts)
		if err != nil {
			logger.Fatalf("Failed to load config: %+v", err)
		}
	}

	// Ensure ~/.config/goshs exists
	if _, err = config.Dir(); err != nil {
		logger.Warnf("Could not create config directory: %+v", err)
	}

	// Sanitize webroot and check sanity
	opts, err = sanity.Sanitize(opts)
	if err != nil {
		logger.Fatalf("Failed to sanitize webroot: %+v", err)
	}

	opts, err = sanity.Check(opts)
	if err != nil {
		logger.Fatalf("Sanity check failed: %+v", err)
	}

	// Further processing of options
	opts, err = sanity.FurtherProcessing(opts)
	if err != nil {
		logger.Fatalf("Further processing failed: %+v", err)
	}

	if !opts.TUI {
		logger.PrintBanner(goshsversion.GoshsVersion)
	}

	// Start all servers. A bind failure (e.g. the HTTP port is already in use)
	// is returned here, before the TUI takes over the terminal, so the message
	// is printed and we exit cleanly instead of the dashboard vanishing without
	// a trace and leaving the terminal in raw mode.
	srv, err := server.StartAll(opts)
	if err != nil {
		logger.Fatalf("Failed to start: %+v", err)
	}

	// Arm the self-destruct timer if --ttl was set. A zero TTL leaves ttlC nil,
	// which blocks forever in the select below.
	var ttlC <-chan time.Time
	if opts.TTL > 0 {
		ttlC = time.After(opts.TTL)
		logger.Infof("Self-destruct armed: shutting down automatically in %s", opts.TTL)
	}

	if opts.TUI {
		// The dashboard owns the terminal, so route logging away from the
		// console for its lifetime to avoid corrupting the rendered view.
		logger.LogFile(io.Discard)
		if err := tui.Run(opts, srv.Hub, srv.Catcher, srv.Chat, srv.TunnelURL, ttlC); err != nil {
			logger.LogFile(os.Stderr)
			logger.Errorf("dashboard error: %+v", err)
		}
		logger.LogFile(os.Stderr)
		logger.Infof("Dashboard closed, shutting down gracefully...")
	} else {
		done := make(chan os.Signal, 1)
		signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-done:
			logger.Infof("Received CTRL+C, shutting down gracefully...")
		case <-ttlC:
			logger.Infof("Self-destruct timer (%s) elapsed, shutting down gracefully...", opts.TTL)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	logger.Infof("Shutdown complete")
}
