// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"os"
	"time"
)

// Config holds the runtime configuration for the Tetragon MCP server.
//
// The server talks to a single Tetragon gRPC endpoint. Values are read from
// flags first, then environment variables (env wins for unset flags), then
// fall back to the defaults below. TLS is intentionally out of scope for the
// MVP: the agent listens plaintext by default and the scope is loopback /
// port-forward / unix socket only.
type Config struct {
	// Address is the Tetragon gRPC endpoint: "host:port" or "unix://path".
	Address string
	// Timeout bounds each unary RPC (status, info, list policies).
	Timeout time.Duration
}

const (
	defaultAddress = "localhost:1337"
	defaultTimeout = 30 * time.Second

	envAddress = "TETRAGON_ADDR"
	envTimeout = "TETRAGON_TIMEOUT"
)

// resolveConfig merges flag values with environment variables and defaults.
// A flag value of "" (or zero duration) means "not set", so the environment
// variable is consulted before falling back to the default.
func resolveConfig(flagAddr string, flagTimeout time.Duration) (*Config, error) {
	c := &Config{
		Address: defaultAddress,
		Timeout: defaultTimeout,
	}

	switch {
	case flagAddr != "":
		c.Address = flagAddr
	case os.Getenv(envAddress) != "":
		c.Address = os.Getenv(envAddress)
	}

	switch {
	case flagTimeout != 0:
		c.Timeout = flagTimeout
	case os.Getenv(envTimeout) != "":
		d, err := time.ParseDuration(os.Getenv(envTimeout))
		if err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", envTimeout, os.Getenv(envTimeout), err)
		}
		c.Timeout = d
	}

	if c.Address == "" {
		return nil, fmt.Errorf("tetragon address must not be empty")
	}
	if c.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive, got %s", c.Timeout)
	}

	return c, nil
}
