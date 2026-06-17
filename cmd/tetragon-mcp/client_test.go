// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRPCErrorMessage(t *testing.T) {
	c := &Client{address: "localhost:1337", timeout: 30 * time.Second}

	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name:     "unavailable names endpoint",
			err:      status.Error(codes.Unavailable, "connection refused"),
			contains: []string{"unreachable", "localhost:1337"},
		},
		{
			name:     "deadline mentions timeout",
			err:      status.Error(codes.DeadlineExceeded, "ctx deadline"),
			contains: []string{"timed out", "30s", "localhost:1337"},
		},
		{
			name:     "unimplemented mentions version",
			err:      status.Error(codes.Unimplemented, "unknown method"),
			contains: []string{"version", "localhost:1337"},
		},
		{
			name:     "permission denied",
			err:      status.Error(codes.PermissionDenied, "nope"),
			contains: []string{"denied", "localhost:1337"},
		},
		{
			name:     "other code falls back to message+code",
			err:      status.Error(codes.Internal, "boom"),
			contains: []string{"boom", "Internal"},
		},
		{
			name:     "non-grpc error passes through",
			err:      errors.New("plain failure"),
			contains: []string{"plain failure"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := c.rpcErrorMessage(tt.err)
			for _, want := range tt.contains {
				assert.Contains(t, msg, want)
			}
		})
	}
}
