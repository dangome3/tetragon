// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// statusInput has no parameters; GetHealth takes none.
type statusInput struct{}

// statusOutput is the structured health summary returned to the client.
type statusOutput struct {
	Health  string `json:"health" jsonschema:"health status of the agent, e.g. running"`
	Details string `json:"details" jsonschema:"human-readable detail string from the agent"`
}

func registerStatusTool(server *mcp.Server, client *Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "tetragon_status",
		Description: "Check the health of the connected Tetragon agent. Returns whether the agent is running.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ statusInput) (*mcp.CallToolResult, statusOutput, error) {
		rpcCtx, cancel := client.unaryContext(ctx)
		defer cancel()

		resp, err := client.api.GetHealth(rpcCtx, &tetragon.GetHealthStatusRequest{})
		if err != nil {
			return client.rpcErrorResult(err), statusOutput{}, nil
		}

		out := statusOutput{}
		if hs := resp.GetHealthStatus(); len(hs) > 0 {
			out.Health = hs[0].GetStatus().String()
			out.Details = hs[0].GetDetails()
		}

		res, err := jsonResult(out)
		return res, out, err
	})
}
