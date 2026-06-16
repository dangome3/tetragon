// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
)

// retries is the number of connection retries the gRPC client performs on
// UNAVAILABLE before giving up on a call.
const retries = 3

// Client is a long-lived wrapper around a single Tetragon gRPC connection.
//
// Unlike the tetra CLI, which dials per command invocation, the MCP server is
// a long-running process and holds one connection for its lifetime. gRPC
// handles transient reconnects internally via the retry service config, so we
// do not tear down the connection on per-call errors.
type Client struct {
	conn    *grpc.ClientConn
	api     tetragon.FineGuidanceSensorsClient
	timeout time.Duration
}

// NewClient dials the configured Tetragon endpoint and returns a Client.
// The connection is lazy: grpc.NewClient does not perform I/O, so failures
// surface on the first RPC (mapped to a friendly message by the tools).
func NewClient(cfg *Config) (*Client, error) {
	conn, err := grpc.NewClient(cfg.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(common.RetryPolicy(retries)),
		grpc.WithMaxCallAttempts(retries+1), // maxAttempt includes the first call
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(defaults.DefaultMaxGRPCRecvMsgSize)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client for %s: %w", cfg.Address, err)
	}

	return &Client{
		conn:    conn,
		api:     tetragon.NewFineGuidanceSensorsClient(conn),
		timeout: cfg.Timeout,
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// unaryContext derives a context with the configured per-RPC timeout from the
// given parent (typically the tool call's context).
func (c *Client) unaryContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.timeout)
}
