/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type patch func(params *Config) error

var patches = []patch{
	patchBootstrapResolver,
	patchTcpCheckHttpMethod,
	patchEmptyDns,
	patchMustOutbound,
	patchAdaptive,
	patchMetrics,
}

const (
	AdaptiveModeOff     = "off"
	AdaptiveModeShadow  = "shadow"
	AdaptiveModeEnforce = "enforce"
)

func patchMetrics(params *Config) error {
	listen := strings.TrimSpace(params.Global.MetricsListen)
	params.Global.MetricsListen = listen
	if listen == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return fmt.Errorf("invalid metrics_listen %q: %w", listen, err)
	}
	return nil
}

func patchAdaptive(params *Config) error {
	groups := make(map[string]struct{}, len(params.Group))
	for _, group := range params.Group {
		groups[group.Name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(params.Adaptive))
	for i := range params.Adaptive {
		adaptive := &params.Adaptive[i]
		if _, ok := groups[adaptive.Name]; !ok {
			return fmt.Errorf("adaptive group %q does not reference an existing group", adaptive.Name)
		}
		if _, ok := seen[adaptive.Name]; ok {
			return fmt.Errorf("duplicated adaptive group %q", adaptive.Name)
		}
		seen[adaptive.Name] = struct{}{}
		adaptive.Mode = strings.ToLower(strings.TrimSpace(adaptive.Mode))
		switch adaptive.Mode {
		case AdaptiveModeOff, AdaptiveModeShadow, AdaptiveModeEnforce:
		default:
			return fmt.Errorf("adaptive group %q has unsupported mode %q", adaptive.Name, adaptive.Mode)
		}
		if adaptive.MaxTargets <= 0 || adaptive.MaxTargets > 4096 {
			return fmt.Errorf("adaptive group %q max_targets must be in [1, 4096]", adaptive.Name)
		}
		if adaptive.MinConnections == 0 {
			return fmt.Errorf("adaptive group %q min_connections must be positive", adaptive.Name)
		}
		if adaptive.ObservationWindow <= 0 || adaptive.IdleTtl <= 0 || adaptive.ProbeInterval <= 0 || adaptive.ProbeTimeout <= 0 || adaptive.RecommendationTtl <= 0 {
			return fmt.Errorf("adaptive group %q durations must be positive", adaptive.Name)
		}
		if len(adaptive.ProbePorts) == 0 {
			adaptive.ProbePorts = []uint16{443}
		}
		ports := make(map[uint16]struct{}, len(adaptive.ProbePorts))
		for _, port := range adaptive.ProbePorts {
			if port == 0 {
				return fmt.Errorf("adaptive group %q probe_ports must not contain zero", adaptive.Name)
			}
			if _, duplicate := ports[port]; duplicate {
				return fmt.Errorf("adaptive group %q probe_ports contains duplicate port %d", adaptive.Name, port)
			}
			ports[port] = struct{}{}
		}
		if adaptive.MaxConcurrentProbes <= 0 || adaptive.MaxConcurrentProbes > 128 {
			return fmt.Errorf("adaptive group %q max_concurrent_probes must be in [1, 128]", adaptive.Name)
		}
		if adaptive.MaxProbesPerMinute <= 0 || adaptive.MaxProbesPerMinute > 10000 {
			return fmt.Errorf("adaptive group %q max_probes_per_minute must be in [1, 10000]", adaptive.Name)
		}
		if adaptive.SwitchTolerance < 0 || adaptive.SwitchMinPercent >= 100 {
			return fmt.Errorf("adaptive group %q switch thresholds are invalid", adaptive.Name)
		}
	}
	return nil
}

func patchBootstrapResolver(params *Config) error {
	_, err := BootstrapResolvers(&params.Global)
	return err
}

func patchTcpCheckHttpMethod(params *Config) error {
	if !common.IsValidHttpMethod(params.Global.TcpCheckHttpMethod) {
		logrus.Warnf("Unknown HTTP Method '%v'. Fallback to 'CONNECT'.", params.Global.TcpCheckHttpMethod)
		params.Global.TcpCheckHttpMethod = "CONNECT"
	}
	return nil
}

func patchEmptyDns(params *Config) error {
	if params.Dns.Routing.Request.Fallback == nil {
		params.Dns.Routing.Request.Fallback = consts.DnsRequestOutboundIndex_AsIs.String()
	}
	if params.Dns.Routing.Response.Fallback == nil {
		params.Dns.Routing.Response.Fallback = consts.DnsResponseOutboundIndex_Accept.String()
	}
	return nil
}

func patchMustOutbound(params *Config) error {
	for i := range params.Routing.Rules {
		if strings.HasPrefix(params.Routing.Rules[i].Outbound.Name, "must_") {
			if params.Routing.Rules[i].Outbound.Name == "must_rules" {
				// Reserve must_rules.
				continue
			}
			params.Routing.Rules[i].Outbound.Name = strings.TrimPrefix(params.Routing.Rules[i].Outbound.Name, "must_")
			params.Routing.Rules[i].Outbound.Params = append(params.Routing.Rules[i].Outbound.Params, &config_parser.Param{
				Val: "must",
			})
		}
	}
	f, err := ParseFunctionOrString(params.Routing.Fallback)
	if err != nil {
		return err
	}
	if strings.HasPrefix(f.Name, "must_") {
		f.Name = strings.TrimPrefix(f.Name, "must_")
		f.Params = append(f.Params, &config_parser.Param{
			Val: "must",
		})
		params.Routing.Fallback = f
	}
	return nil
}
