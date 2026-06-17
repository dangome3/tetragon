// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTools wires all read-only Tetragon tools onto the server.
func registerTools(server *mcp.Server, client *Client) {
	registerStatusTool(server, client)
	registerInfoTool(server, client)
	registerPoliciesTool(server, client)
	registerEventsTool(server, client)
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

// errorResult returns a tool-level error result (IsError=true) for a
// non-RPC failure (e.g. bad input, encoding). This reports the failure to the
// model without crashing the server. For gRPC call failures, prefer
// Client.rpcErrorResult so the message names the endpoint.
func errorResult(err error) *mcp.CallToolResult {
	return textErrorResult(err.Error())
}

// textErrorResult wraps a ready-made message as a tool error result.
func textErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
