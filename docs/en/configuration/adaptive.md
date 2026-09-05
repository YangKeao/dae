# Adaptive destination-aware selection

The `adaptive` section learns target-specific dialer recommendations in the
background. It is designed to improve frequently visited TCP destinations
without adding probes or scoring work to the foreground connection path.

## Group boundary

Every adaptive entry references an existing outbound group with the same name.
Routing still chooses the group. Adaptive selection may only choose a dialer
that belongs to that group and is healthy for the requested IP family. A
recommendation from `default` can never be used by `ai`, or vice versa.

## Rollout

Start in `shadow` mode. dae observes sniffed TCP domains, tracks a bounded set of
frequent `domain:port:IP-family` targets, and probes those targets through the
healthy dialers of that group. Port 443 uses a verified TLS handshake; other
ports use a TCP connect. Shadow recommendations are logged and exported as
metrics but do not affect connections.

After comparing recommendation, probe, and foreground-error metrics, change one
group at a time to `enforce`. An enforce-mode recommendation is used only while
it is fresh, healthy, in the same group, and not excluded by retry logic.
Otherwise dae immediately falls back to the group's existing policy.

```jsonc
global {
    metrics_listen: '192.168.1.106:2024'
    # Exact target labels are disabled by default for privacy and cardinality.
    metrics_target_labels: false
}

adaptive {
    default {
        mode: shadow
        max_targets: 64
        min_connections: 20
        observation_window: 10m
        idle_ttl: 1h
        probe_interval: 5m
        probe_timeout: 5s
        probe_ports: 443
        max_concurrent_probes: 4
        max_probes_per_minute: 60
        recommendation_ttl: 15m
        switch_tolerance: 50ms
        switch_min_percent: 20
    }

    ai {
        mode: shadow
    }
}
```

The hot-path observation queue is non-blocking. The target set, probe
concurrency, and probe rate are all bounded per group. A healthy recommendation
must win two consecutive evaluations and exceed both the absolute and relative
switch thresholds; an unhealthy recommendation is replaced immediately.

The feature currently learns only TCP destinations with a known sniffed domain
and a port listed in `probe_ports` (443 by default). IP-only flows, UDP, and
other ports continue to use the original group policy. Keeping the default also
avoids opening background TCP connections to arbitrary application protocols.

## Metrics

When `metrics_listen` is set, `/metrics` includes group/dialer health, existing
group-policy selection, foreground dial results, adaptive probe results, tracked
target counts, and dropped observation events. Exact target metrics are emitted
only when `metrics_target_labels` is true.

Bind this endpoint to a trusted interface and restrict it with a firewall. It
does not provide authentication.
