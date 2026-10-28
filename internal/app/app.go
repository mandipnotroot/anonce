// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package app supplies process configuration and signal handling, not domain policy.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/mandipnotroot/anonce/internal/service"
)

// Main runs a service until interrupted and returns its process exit code.
func Main(role service.Role) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, role, os.Args[1:], os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func run(ctx context.Context, role service.Role, args []string, output io.Writer) error {
	cfg, err := parse(role, args, output)
	if err != nil {
		return err
	}
	return service.Run(ctx, cfg)
}

func parse(role service.Role, args []string, output io.Writer) (service.Config, error) {
	cfg := service.Config{Role: role, Listen: role.DefaultListen()}
	flags := flag.NewFlagSet(string(role), flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&cfg.Listen, "listen", cfg.Listen, "loopback IP literal and port (0 selects an available port)")
	flags.BoolVar(&cfg.ContainerNetwork, "container-network", false, "allow 0.0.0.0 only behind an isolated container network and loopback host ports")
	flags.StringVar(&cfg.SourceURL, "source-url", "", "required HTTPS URL for this build's exact corresponding source")
	if role == service.Submission {
		flags.BoolVar(&cfg.DevStyleGuide, "dev-styleguide", false, "enable the read-only mock development style guide")
	}
	if err := flags.Parse(args); err != nil {
		return service.Config{}, err
	}
	if flags.NArg() != 0 {
		return service.Config{}, errors.New("configure service: positional arguments are not supported")
	}
	if err := cfg.Validate(); err != nil {
		return service.Config{}, fmt.Errorf("configure service: %w", err)
	}
	return cfg, nil
}
