// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/status"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTools wires all read-only Tetragon tools onto the server.
func registerTools(server *mcp.Server, client *Client) {
	registerStatusTool(server, client)
}

// jsonResult marshals v and returns it as a successful tool result with a
// single text content block of pretty-printed JSON.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(fmt.Errorf("failed to encode response: %w", err)), nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil
}

// errorResult returns a tool-level error result (IsError=true). This reports
// the failure to the model without crashing the server. gRPC status codes are
// mapped to friendlier messages.
func errorResult(err error) *mcp.CallToolResult {
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		msg = fmt.Sprintf("%s (grpc: %s)", st.Message(), st.Code())
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
