// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/filters"
)

// fakeStream is a server-streaming client backed by a slice of responses. It
// applies the request's AllowList and FieldFilters exactly like the real agent
// + tetra's ioReaderClient, so tests exercise filtering through the real code.
type fakeStream struct {
	grpc.ClientStream
	events       []*tetragon.GetEventsResponse
	idx          int
	allowlist    filters.FilterFuncs
	fieldFilters []*fieldfilters.FieldFilter
	// recvErr, if set, is returned instead of io.EOF once events run out.
	recvErr error
	// block, if true, makes Recv hang until the context is done after the
	// canned events are exhausted (simulating "no more events, keep waiting").
	block bool
	ctx   context.Context
}

func (s *fakeStream) Recv() (*tetragon.GetEventsResponse, error) {
	for s.idx < len(s.events) {
		res := s.events[s.idx]
		s.idx++
		if !filters.Apply(s.allowlist, nil, &event.Event{Event: res}) {
			continue
		}
		var err error
		for _, ff := range s.fieldFilters {
			res, err = ff.Filter(res)
			if err != nil {
				return nil, err
			}
		}
		return res, nil
	}
	if s.block {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	return nil, io.EOF
}

// fakeAPI is a FineGuidanceSensorsClient whose only real method is GetEvents.
// All other methods panic (they are unused by these tests).
type fakeAPI struct {
	tetragon.FineGuidanceSensorsClient
	events  []*tetragon.GetEventsResponse
	recvErr error
	block   bool
	// getErr, if set, makes GetEvents itself fail (e.g. agent unreachable).
	getErr error
	// gotReq captures the request the tool built, for assertions.
	gotReq *tetragon.GetEventsRequest
}

func (a *fakeAPI) GetEvents(ctx context.Context, in *tetragon.GetEventsRequest, _ ...grpc.CallOption) (tetragon.FineGuidanceSensors_GetEventsClient, error) {
	a.gotReq = in
	if a.getErr != nil {
		return nil, a.getErr
	}
	allowlist, err := filters.BuildFilterList(ctx, in.AllowList, filters.Filters)
	if err != nil {
		return nil, err
	}
	ffs, err := fieldfilters.FieldFiltersFromGetEventsRequest(in)
	if err != nil {
		return nil, err
	}
	return &fakeStream{
		events:       a.events,
		allowlist:    allowlist,
		fieldFilters: ffs,
		recvErr:      a.recvErr,
		block:        a.block,
		ctx:          ctx,
	}, nil
}

// execEvent builds a PROCESS_EXEC event with the given binary, a secret env
// var, and an ancestor — the two fields excluded by default.
func execEvent(binary string) *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary: binary,
					EnvironmentVariables: []*tetragon.EnvVar{
						{Key: "SECRET_TOKEN", Value: "hunter2"},
					},
				},
				Ancestors: []*tetragon.Process{
					{Binary: "/sbin/init"},
				},
			},
		},
	}
}

func runEventsTool(t *testing.T, api tetragon.FineGuidanceSensorsClient, in eventsInput) eventsOutput {
	t.Helper()
	maxEvents := clampMaxEvents(in.MaxEvents)
	dur, err := resolveDuration(in.Duration)
	require.NoError(t, err)
	req, err := buildEventsRequest(in)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	return collectEvents(ctx, api, req, maxEvents, func(e error) string { return e.Error() })
}

func TestEventsStopsAtMaxEvents(t *testing.T) {
	api := &fakeAPI{events: []*tetragon.GetEventsResponse{
		execEvent("/bin/a"), execEvent("/bin/b"), execEvent("/bin/c"),
	}}

	out := runEventsTool(t, api, eventsInput{MaxEvents: 2})

	assert.Equal(t, 2, out.Count)
	assert.Len(t, out.Events, 2)
	assert.Equal(t, "max_events", out.StoppedBy)
	assert.True(t, out.Truncated)
	assert.Empty(t, out.Error)
}

func TestEventsStreamEnded(t *testing.T) {
	api := &fakeAPI{events: []*tetragon.GetEventsResponse{
		execEvent("/bin/a"), execEvent("/bin/b"),
	}}

	out := runEventsTool(t, api, eventsInput{MaxEvents: 50})

	assert.Equal(t, 2, out.Count)
	assert.Equal(t, "stream_ended", out.StoppedBy)
	assert.False(t, out.Truncated)
}

func TestEventsStopsAtDuration(t *testing.T) {
	// No events, stream blocks until the deadline -> "duration".
	api := &fakeAPI{block: true}

	out := runEventsTool(t, api, eventsInput{Duration: "50ms"})

	assert.Equal(t, 0, out.Count)
	assert.Equal(t, "duration", out.StoppedBy)
	assert.True(t, out.Truncated)
	assert.Empty(t, out.Error)
}

func TestEventsExcludesHeavyFieldsByDefault(t *testing.T) {
	api := &fakeAPI{events: []*tetragon.GetEventsResponse{execEvent("/bin/a")}}

	out := runEventsTool(t, api, eventsInput{})

	require.Equal(t, 1, out.Count)
	var ev tetragon.GetEventsResponse
	require.NoError(t, protojsonUnmarshal(out.Events[0], &ev))
	exec := ev.GetProcessExec()
	require.NotNil(t, exec)
	assert.Equal(t, "/bin/a", exec.GetProcess().GetBinary(), "non-heavy fields are kept")
	assert.Empty(t, exec.GetProcess().GetEnvironmentVariables(), "env vars excluded by default")
	assert.Empty(t, exec.GetAncestors(), "ancestors excluded by default")
}

func TestEventsIncludesHeavyFieldsWhenRequested(t *testing.T) {
	api := &fakeAPI{events: []*tetragon.GetEventsResponse{execEvent("/bin/a")}}

	out := runEventsTool(t, api, eventsInput{IncludeHeavyFields: true})

	require.Equal(t, 1, out.Count)
	var ev tetragon.GetEventsResponse
	require.NoError(t, protojsonUnmarshal(out.Events[0], &ev))
	exec := ev.GetProcessExec()
	require.NotNil(t, exec)
	assert.NotEmpty(t, exec.GetProcess().GetEnvironmentVariables(), "env vars kept when opted in")
	assert.NotEmpty(t, exec.GetAncestors(), "ancestors kept when opted in")

	// And no field filter should have been sent in that case.
	assert.Empty(t, api.gotReq.GetFieldFilters())
}

func TestEventsBinaryRegexFilter(t *testing.T) {
	api := &fakeAPI{events: []*tetragon.GetEventsResponse{
		execEvent("/usr/bin/curl"), execEvent("/bin/ls"), execEvent("/usr/bin/wget"),
	}}

	out := runEventsTool(t, api, eventsInput{BinaryRegex: []string{"curl|wget"}})

	assert.Equal(t, 2, out.Count)
	assert.Equal(t, "stream_ended", out.StoppedBy)
	// The filter must reach the request as an AllowList entry.
	require.Len(t, api.gotReq.GetAllowList(), 1)
	assert.Equal(t, []string{"curl|wget"}, api.gotReq.GetAllowList()[0].GetBinaryRegex())
}

func TestEventsStreamErrorWithPartialResults(t *testing.T) {
	boom := io.ErrUnexpectedEOF
	api := &fakeAPI{
		events:  []*tetragon.GetEventsResponse{execEvent("/bin/a")},
		recvErr: boom,
	}

	out := runEventsTool(t, api, eventsInput{MaxEvents: 50})

	// The one event that arrived before the error is preserved.
	assert.Equal(t, 1, out.Count)
	assert.Equal(t, "error", out.StoppedBy)
	assert.True(t, out.Truncated)
	assert.NotEmpty(t, out.Error)
}

func TestEventsUnknownEventTypeRejected(t *testing.T) {
	_, err := buildEventsRequest(eventsInput{EventTypes: []string{"NOPE"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NOPE")
}

func TestResolveDuration(t *testing.T) {
	d, err := resolveDuration("")
	require.NoError(t, err)
	assert.Equal(t, defaultDuration, d)

	d, err = resolveDuration("2h")
	require.NoError(t, err)
	assert.Equal(t, maxDuration, d, "duration is clamped to the ceiling")

	d, err = resolveDuration("5s")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, d)

	_, err = resolveDuration("bogus")
	require.Error(t, err)
}

func TestClampMaxEvents(t *testing.T) {
	assert.Equal(t, defaultMaxEvents, clampMaxEvents(0))
	assert.Equal(t, defaultMaxEvents, clampMaxEvents(-5))
	assert.Equal(t, maxMaxEvents, clampMaxEvents(10_000))
	assert.Equal(t, 7, clampMaxEvents(7))
}

// protojsonUnmarshal decodes one of the tool's event objects back into a proto
// for assertions. It tolerates the snake_case names the tool emits.
func protojsonUnmarshal(b json.RawMessage, ev *tetragon.GetEventsResponse) error {
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, ev)
}
