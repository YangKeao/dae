/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

var activePrometheusControlPlane atomic.Pointer[ControlPlane]

func publishPrometheusControlPlane(c *ControlPlane) {
	if c != nil {
		activePrometheusControlPlane.Store(c)
	}
}

func unpublishPrometheusControlPlane(c *ControlPlane) {
	if c != nil {
		activePrometheusControlPlane.CompareAndSwap(c, nil)
	}
}

// PrometheusHandler exposes metrics for the currently serving control-plane
// generation. Prepared and retiring generations are never published here.
func PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controlPlane := activePrometheusControlPlane.Load()
		if controlPlane == nil {
			http.Error(w, "dae control plane is not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := controlPlane.writePrometheus(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func (c *ControlPlane) writePrometheus(w io.Writer) error {
	if c == nil {
		return fmt.Errorf("nil control plane")
	}
	runtime := c.SnapshotRuntimeStats(60, 1)
	writeMetricHeader(w, "dae_runtime_upload_bytes_total", "Total bytes uploaded through dae.", "counter")
	writeMetric(w, "dae_runtime_upload_bytes_total", nil, float64(runtime.UploadTotal))
	writeMetricHeader(w, "dae_runtime_download_bytes_total", "Total bytes downloaded through dae.", "counter")
	writeMetric(w, "dae_runtime_download_bytes_total", nil, float64(runtime.DownloadTotal))
	writeMetricHeader(w, "dae_tcp_connections_active", "Current active TCP connections handled by dae.", "gauge")
	writeMetric(w, "dae_tcp_connections_active", nil, float64(runtime.ActiveConnections))
	writeMetricHeader(w, "dae_udp_sessions_active", "Current active UDP sessions handled by dae.", "gauge")
	writeMetric(w, "dae_udp_sessions_active", nil, float64(runtime.UDPSessions))

	writeMetricHeader(w, "dae_dialer_alive", "Whether a dialer is globally healthy for a group and network family.", "gauge")
	writeMetricHeader(w, "dae_dialer_check_latency_seconds", "Latest generic health-check latency for a dialer.", "gauge")
	writeMetricHeader(w, "dae_dialer_check_timestamp_seconds", "Unix timestamp of the latest generic health check.", "gauge")
	writeMetricHeader(w, "dae_group_selected_dialer_info", "Current deterministic dialer selected by the existing fixed or latency-based group policy.", "gauge")
	for _, group := range c.outbounds {
		if group == nil {
			continue
		}
		for _, networkType := range prometheusTCPNetworkTypes() {
			network := networkType.StringWithoutDns()
			for _, d := range group.Dialers {
				if d == nil {
					continue
				}
				labels := map[string]string{"group": group.Name, "dialer": dialerName(d), "network": network}
				alive := 0.0
				if d.MustGetAlive(networkType) {
					alive = 1
				}
				writeMetric(w, "dae_dialer_alive", labels, alive)
				probe := d.SnapshotLastProbe(networkType)
				if probe.HasLatency {
					writeMetric(w, "dae_dialer_check_latency_seconds", labels, probe.Latency.Seconds())
				}
				if !probe.CheckedAt.IsZero() {
					writeMetric(w, "dae_dialer_check_timestamp_seconds", labels, float64(probe.CheckedAt.Unix()))
				}
			}
			selected, ok := group.SnapshotDeterministicSelection(networkType)
			if ok {
				writeMetric(w, "dae_group_selected_dialer_info", map[string]string{
					"group": group.Name, "dialer": dialerName(selected), "network": network,
					"policy": string(group.GetSelectionPolicy()),
				}, 1)
			}
		}
	}

	if c.adaptive != nil {
		c.adaptive.writePrometheus(w, c.metricsTargetLabels)
	}
	return nil
}

func (r *adaptiveRouter) writePrometheus(w io.Writer, includeTargetLabels bool) {
	snapshot := r.metrics.Load()
	if snapshot == nil {
		return
	}
	writeMetricHeader(w, "dae_connections_total", "Proxy dial attempts by group, dialer, network, and result.", "counter")
	writeMetricHeader(w, "dae_adaptive_probe_total", "Adaptive background probes by group, dialer, network, and result.", "counter")
	writeMetricHeader(w, "dae_adaptive_events_dropped_total", "Adaptive observations dropped because the non-blocking queue was full.", "counter")
	writeMetric(w, "dae_adaptive_events_dropped_total", nil, float64(snapshot.droppedEvents))
	writeMetricHeader(w, "dae_adaptive_targets", "Targets currently tracked by one adaptive group.", "gauge")
	writeMetricHeader(w, "dae_adaptive_target_connections", "Connections observed for a bounded adaptive target in the current window.", "gauge")
	writeMetricHeader(w, "dae_adaptive_recommended_dialer_info", "Current target-specific recommendation, always scoped to one group.", "gauge")
	writeMetricHeader(w, "dae_adaptive_target_probe_success", "Whether the latest target-specific probe succeeded.", "gauge")
	writeMetricHeader(w, "dae_adaptive_target_probe_latency_seconds", "EWMA latency of target-specific probes.", "gauge")
	writeMetricHeader(w, "dae_adaptive_target_probe_timestamp_seconds", "Unix timestamp of the latest target-specific probe.", "gauge")
	writeMetricHeader(w, "dae_adaptive_target_passive_success_total", "Foreground connections that received at least one downstream byte.", "counter")

	for _, group := range snapshot.groups {
		for key, value := range group.connections {
			writeMetric(w, "dae_connections_total", map[string]string{
				"group": group.name, "dialer": key.dialer, "network": key.network, "result": key.result,
			}, float64(value))
		}
		for key, value := range group.probeTotals {
			writeMetric(w, "dae_adaptive_probe_total", map[string]string{
				"group": group.name, "dialer": key.dialer, "network": key.network, "result": key.result,
			}, float64(value))
		}
		writeMetric(w, "dae_adaptive_targets", map[string]string{"group": group.name, "mode": group.mode}, float64(len(group.targets)))
		if !includeTargetLabels {
			continue
		}
		for _, target := range group.targets {
			targetName := netJoinTarget(target.domain, target.port)
			baseLabels := map[string]string{
				"group": group.name, "mode": group.mode, "network": target.network, "target": targetName,
				"hot": strconv.FormatBool(target.hot),
			}
			writeMetric(w, "dae_adaptive_target_connections", baseLabels, float64(target.count))
			if target.recommended != "" {
				labels := cloneMetricLabels(baseLabels)
				labels["dialer"] = target.recommended
				writeMetric(w, "dae_adaptive_recommended_dialer_info", labels, 1)
			}
			for _, probe := range target.probes {
				labels := cloneMetricLabels(baseLabels)
				labels["dialer"] = probe.dialer
				success := 0.0
				if probe.success {
					success = 1
				}
				writeMetric(w, "dae_adaptive_target_probe_success", labels, success)
				if probe.latency > 0 {
					writeMetric(w, "dae_adaptive_target_probe_latency_seconds", labels, probe.latency.Seconds())
				}
				if !probe.lastProbe.IsZero() {
					writeMetric(w, "dae_adaptive_target_probe_timestamp_seconds", labels, float64(probe.lastProbe.Unix()))
				}
				writeMetric(w, "dae_adaptive_target_passive_success_total", labels, float64(probe.passiveSuccess))
			}
		}
	}
}

func prometheusTCPNetworkTypes() []*dialer.NetworkType {
	return []*dialer.NetworkType{
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4},
		{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6},
	}
}

func writeMetricHeader(w io.Writer, name, help, metricType string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeMetric(w io.Writer, name string, labels map[string]string, value float64) {
	_, _ = io.WriteString(w, name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		_, _ = io.WriteString(w, "{")
		for i, key := range keys {
			if i > 0 {
				_, _ = io.WriteString(w, ",")
			}
			_, _ = fmt.Fprintf(w, `%s="%s"`, key, prometheusLabelEscape(labels[key]))
		}
		_, _ = io.WriteString(w, "}")
	}
	_, _ = fmt.Fprintf(w, " %s\n", strconv.FormatFloat(value, 'g', -1, 64))
}

func prometheusLabelEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func cloneMetricLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src)+1)
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func netJoinTarget(domain string, port uint16) string {
	if port == 0 {
		return domain
	}
	return net.JoinHostPort(domain, strconv.Itoa(int(port)))
}
