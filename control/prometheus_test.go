/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWritePrometheusIncludesRuntimeCounters(t *testing.T) {
	plane := &ControlPlane{runtimeStats: newRuntimeStats()}
	plane.runtimeStats.record(128, 256)

	var output strings.Builder
	require.NoError(t, plane.writePrometheus(&output))
	require.Contains(t, output.String(), "# TYPE dae_runtime_upload_bytes_total counter")
	require.Contains(t, output.String(), "dae_runtime_upload_bytes_total 128")
	require.Contains(t, output.String(), "dae_runtime_download_bytes_total 256")
}

func TestPrometheusLabelEscape(t *testing.T) {
	require.Equal(t, `node\\\"a\nb`, prometheusLabelEscape("node\\\"a\nb"))
}
