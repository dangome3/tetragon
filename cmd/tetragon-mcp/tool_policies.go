// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// policiesInput optionally scopes the listing to a domain.
type policiesInput struct {
	// Domain scopes the listing. Empty lists all domains. Use "k8s" for
	// CRD-based policies; the default gRPC domain holds policies added over
	// the gRPC API.
	Domain string `json:"domain,omitempty" jsonschema:"policy domain to list; empty for all, \"k8s\" for CRD policies"`
}

// policy is a projection of tetragon.TracingPolicyStatus with the fields most
// useful to a reader.
type policy struct {
	ID                uint64   `json:"id"`
	Name              string   `json:"name"`
	Namespace         string   `json:"namespace,omitempty"`
	State             string   `json:"state"`
	Mode              string   `json:"mode"`
	Sensors           []string `json:"sensors,omitempty"`
	Info              string   `json:"info,omitempty"`
	Error             string   `json:"error,omitempty"`
	KernelMemoryBytes uint64   `json:"kernel_memory_bytes"`
}

type policiesOutput struct {
	Policies []policy `json:"policies"`
	Count    int      `json:"count"`
}

func registerPoliciesTool(server *mcp.Server, client *Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "tetragon_list_policies",
		Description: "List the tracing policies loaded in the connected Tetragon agent, " +
			"with their state (enabled/disabled/error), mode (enforce/monitor), and the " +
			"sensors they loaded. Note: this is the queried agent's view; gRPC-domain and " +
			"k8s-CRD policies may differ.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in policiesInput) (*mcp.CallToolResult, policiesOutput, error) {
		rpcCtx, cancel := client.unaryContext(ctx)
		defer cancel()

		resp, err := client.api.ListTracingPolicies(rpcCtx, &tetragon.ListTracingPoliciesRequest{Domain: in.Domain})
		if err != nil {
			return client.rpcErrorResult(err), policiesOutput{}, nil
		}

		out := policiesOutput{Policies: make([]policy, 0, len(resp.GetPolicies()))}
		for _, p := range resp.GetPolicies() {
			out.Policies = append(out.Policies, policy{
				ID:                p.GetId(),
				Name:              p.GetName(),
				Namespace:         p.GetNamespace(),
				State:             p.GetState().String(),
				Mode:              p.GetMode().String(),
				Sensors:           p.GetSensors(),
				Info:              p.GetInfo(),
				Error:             p.GetError(),
				KernelMemoryBytes: p.GetKernelMemoryBytes(),
			})
		}
		out.Count = len(out.Policies)

		res, err := jsonResult(out)
		return res, out, err
	})
}
