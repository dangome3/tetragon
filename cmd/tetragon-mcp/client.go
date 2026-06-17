// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

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
	address string
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
		address: cfg.Address,
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

// rpcErrorResult turns a gRPC call failure into a tool error result with a
// message tuned for the model: the common failure modes name the endpoint and
// suggest the likely cause instead of leaking raw gRPC status text.
func (c *Client) rpcErrorResult(err error) *mcp.CallToolResult {
	return textErrorResult(c.rpcErrorMessage(err))
}

// rpcErrorMessage renders a gRPC error into a human-readable, actionable
// string. It maps the codes a local/loopback deployment actually hits.
func (c *Client) rpcErrorMessage(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return err.Error()
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Sprintf("Tetragon agent unreachable at %s: is the agent running and the address/port-forward correct? (grpc: %s: %s)",
			c.address, st.Code(), st.Message())
	case codes.DeadlineExceeded:
		return fmt.Sprintf("request to Tetragon agent at %s timed out after %s (raise --timeout if the agent is slow) (grpc: %s)",
			c.address, c.timeout, st.Code())
	case codes.Unimplemented:
		return fmt.Sprintf("the agent at %s does not implement this RPC; check the Tetragon version (grpc: %s: %s)",
			c.address, st.Code(), st.Message())
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Sprintf("access to the agent at %s was denied (grpc: %s: %s)",
			c.address, st.Code(), st.Message())
	default:
		return fmt.Sprintf("%s (grpc: %s)", st.Message(), st.Code())
	}
}
