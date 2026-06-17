# tetragon-mcp

An [MCP](https://modelcontextprotocol.io/) server that exposes a Tetragon
agent's runtime observability to LLM clients (Claude Code, Claude Desktop) by
wrapping Tetragon's gRPC API (`FineGuidanceSensors`).

It is a **read-only** MVP: it can query health, agent info, and tracing
policies, and pull a **bounded** window of security events. It never adds,
deletes, or enforces policies.

## Tools

| Tool | RPC | What it answers |
|---|---|---|
| `tetragon_status` | `GetHealth` | Is the agent running? |
| `tetragon_get_info` | `GetInfo` | Agent version, build, available kernel probes, config. |
| `tetragon_list_policies` | `ListTracingPolicies` | Which tracing policies are loaded, and their state/mode/sensors. |
| `tetragon_get_events` | `GetEvents` | A bounded stream of runtime events (exec/exit, kprobe, tracepoint, uprobe, LSM). |

`tetragon_get_events` is always bounded — it stops at `max_events` (default 50,
ceiling 200) or after `duration` (default `10s`, ceiling `60s`), whichever comes
first, so it never opens an unbounded stream. It accepts filters
(`binary_regex`, `pod_regex`, `namespace`, `policy_names`, `event_types`,
`cel_expression`) that the agent applies in-kernel. **Environment variables and
process ancestry are excluded by default** (env vars often carry secrets,
ancestry is bulky); pass `include_heavy_fields=true` to keep them.

## Build

```bash
make tetragon-mcp      # produces ./tetragon-mcp
```

Or as a container image (linux):

```bash
make image-mcp         # builds cilium/tetragon-mcp:latest
```

## Configuration

The server talks to a **single** Tetragon gRPC endpoint. Configure via flags or
environment (flag wins; env is consulted when the flag is unset):

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--address` | `TETRAGON_ADDR` | `localhost:1337` | `host:port` or `unix:///path/to/tetragon.sock` |
| `--timeout` | `TETRAGON_TIMEOUT` | `30s` | per-unary-RPC deadline (also the floor for the events stream) |

## Run

It is an MCP **stdio** server: it speaks newline-delimited JSON-RPC over
stdin/stdout, so an MCP client launches it as a subprocess. To register it with
Claude Code:

```bash
claude mcp add tetragon -- /ABS/PATH/TO/tetragon-mcp --address localhost:1337
```

Then ask, e.g. *"check tetragon status"*, *"what tetragon version is running?"*,
*"list the loaded tracing policies"*, or *"show me the last few tetragon
events"*.

As a container (note `-i` — stdio needs stdin kept open):

```bash
docker run -i --rm cilium/tetragon-mcp:latest --address host.docker.internal:1337
```

### Connecting to the agent

| Deployment | Address |
|---|---|
| Single-node k8s (e.g. minikube) | `localhost:1337` via `kubectl port-forward` (see below) |
| Non-k8s host | `host:54321` or `unix:///var/run/tetragon/tetragon.sock` |

The agent's gRPC listener is pod-local in Kubernetes, so port-forward it to your
host first:

```bash
POD=$(kubectl get pod -n kube-system -l app.kubernetes.io/name=tetragon -o name | head -1)
kubectl port-forward -n kube-system "$POD" 1337:1337 &
```

The agent only exposes a TCP listener if you opted into one (the Helm default is
a unix socket). The current reference setup uses
`--set tetragon.grpc.address=localhost:1337`.

## Security & scope

- **Read-only.** No mutating RPCs are exposed.
- **No TLS in the MVP.** The agent listens plaintext by default and this server
  dials with insecure credentials. Events can carry command arguments, file
  paths, and (if `include_heavy_fields=true`) environment variables — keep the
  endpoint on **loopback / port-forward / unix socket only**. Do not expose the
  plaintext gRPC port over an untrusted network.
- **Single endpoint.** Multi-node fan-in is out of scope (one agent per call).
- Non-k8s events have empty `pod`/`namespace` fields — that is expected, not an
  error.

## Testing

See [`TESTING.md`](./TESTING.md) for a manual end-to-end walkthrough against a
live agent (handshake helper, per-tool examples, and the event-streaming
procedure). Unit tests run with:

```bash
go test ./cmd/tetragon-mcp/
```
