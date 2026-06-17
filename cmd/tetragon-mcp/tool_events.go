// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	// defaultMaxEvents is returned when max_events is unset.
	defaultMaxEvents = 50
	// maxMaxEvents is the hard ceiling on max_events. Even bounded events can
	// be large; this protects the model's context window.
	maxMaxEvents = 200

	// defaultDuration is how long to stream when duration is unset.
	defaultDuration = 10 * time.Second
	// maxDuration is the hard ceiling on the streaming window.
	maxDuration = 60 * time.Second
)

// heavyFieldPaths are excluded from events by default. They are large and
// rarely needed for a quick look, and environment variables routinely carry
// secrets. Paths are relative to each event message and matched per event
// type; a path absent from a given event type is simply ignored.
var heavyFieldPaths = []string{
	"process.environment_variables",
	"parent.environment_variables",
	"ancestors",
}

// eventsInput bounds and filters a GetEvents stream. All fields are optional.
type eventsInput struct {
	// MaxEvents caps how many events are collected. Default 50, ceiling 200.
	MaxEvents int `json:"max_events,omitempty" jsonschema:"maximum number of events to collect (default 50, hard ceiling 200)"`
	// Duration is how long to stream, as a Go duration string (e.g. "10s",
	// "1m"). Default "10s", ceiling "60s".
	Duration string `json:"duration,omitempty" jsonschema:"how long to stream as a Go duration string like \"10s\" (default \"10s\", ceiling \"60s\")"`

	// BinaryRegex filters by process binary name (regex). Any match passes.
	BinaryRegex []string `json:"binary_regex,omitempty" jsonschema:"filter to events whose process binary matches one of these regexes"`
	// PodRegex filters by pod name (regex).
	PodRegex []string `json:"pod_regex,omitempty" jsonschema:"filter to events whose pod name matches one of these regexes"`
	// Namespace filters by Kubernetes namespace (exact match).
	Namespace []string `json:"namespace,omitempty" jsonschema:"filter to events in these Kubernetes namespaces"`
	// PolicyNames filters by the tracing policy that produced the event.
	PolicyNames []string `json:"policy_names,omitempty" jsonschema:"filter to events produced by these tracing policies"`
	// EventTypes filters by event type, e.g. PROCESS_EXEC, PROCESS_EXIT,
	// PROCESS_KPROBE, PROCESS_TRACEPOINT, PROCESS_UPROBE, PROCESS_LSM.
	EventTypes []string `json:"event_types,omitempty" jsonschema:"filter to these event types, e.g. PROCESS_EXEC, PROCESS_KPROBE"`
	// CelExpression filters with CEL expressions evaluated server-side.
	CelExpression []string `json:"cel_expression,omitempty" jsonschema:"filter to events satisfying these CEL expressions"`

	// IncludeHeavyFields, when true, keeps environment variables and process
	// ancestry that are excluded by default.
	IncludeHeavyFields bool `json:"include_heavy_fields,omitempty" jsonschema:"include environment variables and process ancestry, which are excluded by default"`
}

// eventsOutput is the bounded result of a GetEvents stream. Events are raw
// protojson objects (snake_case, matching `tetra getevents -o json`).
type eventsOutput struct {
	Events    []json.RawMessage `json:"events"`
	Count     int               `json:"count"`
	// StoppedBy is why streaming stopped: "max_events", "duration",
	// "stream_ended", "canceled", or "error".
	StoppedBy string `json:"stopped_by"`
	// Truncated is true when streaming stopped while the agent might still have
	// had more events (max_events reached or the duration window elapsed).
	Truncated bool `json:"truncated"`
	// Error carries a transport error when the stream failed mid-collection;
	// any events gathered before the failure are still returned.
	Error string `json:"error,omitempty"`
}

func registerEventsTool(server *mcp.Server, client *Client) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "tetragon_get_events",
		Description: "Stream a bounded window of runtime events (process exec/exit, kprobe, " +
			"tracepoint, uprobe, LSM) from the connected Tetragon agent. Collection stops at " +
			"max_events (default 50, max 200) or after duration (default 10s, max 60s), whichever " +
			"comes first. Filter by binary, pod, namespace, policy, event type, or CEL expression. " +
			"Environment variables and process ancestry are excluded by default; set " +
			"include_heavy_fields=true to keep them. Partial results on timeout are normal, not an error.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in eventsInput) (*mcp.CallToolResult, any, error) {
		maxEvents := clampMaxEvents(in.MaxEvents)
		dur, err := resolveDuration(in.Duration)
		if err != nil {
			return errorResult(err), nil, nil
		}

		req, err := buildEventsRequest(in)
		if err != nil {
			return errorResult(err), nil, nil
		}

		// Bound the stream by duration; the parent ctx still cancels us early
		// if the MCP client disconnects.
		streamCtx, cancel := context.WithTimeout(ctx, dur)
		defer cancel()

		out := collectEvents(streamCtx, client.api, req, maxEvents)
		if out.Count == 0 && out.StoppedBy == "error" {
			// Nothing useful to show and the stream failed outright (e.g. the
			// agent is unreachable): surface it as a tool error.
			return errorResult(errors.New(out.Error)), nil, nil
		}

		res, err := jsonResult(out)
		return res, nil, err
	})
}

// clampMaxEvents applies the default and ceiling for max_events.
func clampMaxEvents(n int) int {
	switch {
	case n <= 0:
		return defaultMaxEvents
	case n > maxMaxEvents:
		return maxMaxEvents
	default:
		return n
	}
}

// resolveDuration parses the duration string and applies the default/ceiling.
func resolveDuration(s string) (time.Duration, error) {
	if s == "" {
		return defaultDuration, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if d <= 0 {
		return defaultDuration, nil
	}
	if d > maxDuration {
		return maxDuration, nil
	}
	return d, nil
}

// buildEventsRequest assembles the GetEventsRequest: an AllowList filter from
// the input plus a default exclusion of heavy fields (unless opted in).
func buildEventsRequest(in eventsInput) (*tetragon.GetEventsRequest, error) {
	filter := &tetragon.Filter{}
	// Only set non-empty fields: the agent treats an all-empty AllowList entry
	// as "match everything", which is what we want when no filter is given.
	if len(in.BinaryRegex) > 0 {
		filter.BinaryRegex = in.BinaryRegex
	}
	if len(in.PodRegex) > 0 {
		filter.PodRegex = in.PodRegex
	}
	if len(in.Namespace) > 0 {
		filter.Namespace = in.Namespace
	}
	if len(in.PolicyNames) > 0 {
		filter.PolicyNames = in.PolicyNames
	}
	if len(in.CelExpression) > 0 {
		filter.CelExpression = in.CelExpression
	}
	for _, name := range in.EventTypes {
		v, ok := tetragon.EventType_value[name]
		if !ok {
			return nil, fmt.Errorf("unknown event type %q", name)
		}
		filter.EventSet = append(filter.EventSet, tetragon.EventType(v))
	}

	req := &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{filter},
	}
	if !in.IncludeHeavyFields {
		req.FieldFilters = []*tetragon.FieldFilter{{
			EventSet: []tetragon.EventType{},
			Fields:   &fieldmaskpb.FieldMask{Paths: heavyFieldPaths},
			Action:   tetragon.FieldFilterAction_EXCLUDE,
		}}
	}
	return req, nil
}

// protojsonMarshal matches the agent's exporter and `tetra getevents -o json`:
// snake_case field names.
var protojsonMarshal = protojson.MarshalOptions{UseProtoNames: true}

// collectEvents opens the stream and gathers up to maxEvents, stopping when the
// context (duration) expires or the stream ends. It never returns an error:
// failures are recorded in the result so partial output survives.
func collectEvents(ctx context.Context, api tetragon.FineGuidanceSensorsClient, req *tetragon.GetEventsRequest, maxEvents int) eventsOutput {
	out := eventsOutput{Events: make([]json.RawMessage, 0, maxEvents)}

	stream, err := api.GetEvents(ctx, req)
	if err != nil {
		out.StoppedBy = "error"
		out.Error = grpcMessage(err)
		return out
	}

	for len(out.Events) < maxEvents {
		res, err := stream.Recv()
		if err != nil {
			out.StoppedBy, out.Truncated, out.Error = classifyStreamErr(err)
			out.Count = len(out.Events)
			return out
		}
		b, err := protojsonMarshal.Marshal(res)
		if err != nil {
			out.StoppedBy = "error"
			out.Error = fmt.Sprintf("failed to encode event: %v", err)
			out.Count = len(out.Events)
			return out
		}
		out.Events = append(out.Events, json.RawMessage(b))
	}

	// Hit the cap; the agent likely had more to send.
	out.StoppedBy = "max_events"
	out.Truncated = true
	out.Count = len(out.Events)
	return out
}

// classifyStreamErr maps a stream termination error to (stoppedBy, truncated,
// errMsg). Duration expiry and cancellation are expected, not failures.
func classifyStreamErr(err error) (string, bool, string) {
	switch {
	case errors.Is(err, io.EOF):
		return "stream_ended", false, ""
	case errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
		return "duration", true, ""
	case errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled:
		return "canceled", true, ""
	default:
		return "error", true, grpcMessage(err)
	}
}
