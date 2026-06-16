// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cilium/tetragon/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tetragon-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		flagAddr    string
		flagTimeout time.Duration
	)
	flag.StringVar(&flagAddr, "address", "", "Tetragon gRPC address (host:port or unix://path). Overrides $TETRAGON_ADDR. Default localhost:1337")
	flag.DurationVar(&flagTimeout, "timeout", 0, "Per-RPC timeout. Overrides $TETRAGON_TIMEOUT. Default 30s")
	flag.Parse()

	cfg, err := resolveConfig(flagAddr, flagTimeout)
	if err != nil {
		return err
	}

	client, err := NewClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "tetragon-mcp",
		Version: version.Version,
	}, nil)
	registerTools(server, client)

	// Serve over stdio until the client disconnects or we get a signal.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
