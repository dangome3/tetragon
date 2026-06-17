// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

// infoInput has no parameters; GetInfo takes none.
type infoInput struct{}

func registerInfoTool(server *mcp.Server, client *Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "tetragon_get_info",
		Description: "Get information about the connected Tetragon agent: version, name, " +
			"build info, available kernel probes, and the agent's configuration.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ infoInput) (*mcp.CallToolResult, any, error) {
		rpcCtx, cancel := client.unaryContext(ctx)
		defer cancel()

		resp, err := client.api.GetInfo(rpcCtx, &tetragon.GetInfoRequest{})
		if err != nil {
			return client.rpcErrorResult(err), nil, nil
		}

		// Decode handles the protobuf Any-typed conf values; see
		// pkg/tetragoninfo. Output mirrors `tetra info`.
		res, err := jsonResult(tetragoninfo.Decode(resp))
		return res, nil, err
	})
}
