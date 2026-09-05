/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newAdaptiveTestGroup(name string, dialers ...*componentdialer.Dialer) *ob.DialerGroup {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	annotations := make([]*componentdialer.Annotation, len(dialers))
	for i := range annotations {
		annotations[i] = &componentdialer.Annotation{}
	}
	return ob.NewDialerGroup(
		&componentdialer.GlobalOption{Log: logger, CheckInterval: time.Second},
		name,
		dialers,
		annotations,
		ob.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Random},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func adaptiveTestConfig(name, mode string) config.AdaptiveGroup {
	return config.AdaptiveGroup{
		Name: name, Mode: mode, MaxTargets: 2, MinConnections: 2,
		ObservationWindow: time.Minute, IdleTtl: time.Hour,
		ProbeInterval: time.Minute, ProbeTimeout: time.Second,
		ProbePorts:          []uint16{443},
		MaxConcurrentProbes: 1, MaxProbesPerMinute: 1,
		RecommendationTtl: time.Minute, SwitchTolerance: time.Millisecond,
		SwitchMinPercent: 10,
	}
}

func TestNormalizeAdaptiveTarget(t *testing.T) {
	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	key, ok := normalizeAdaptiveTarget("BÜCHER.Example.", 443, tcp4)
	require.True(t, ok)
	require.Equal(t, "xn--bcher-kva.example", key.domain)
	require.Equal(t, "tcp4", key.network())

	udp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4}
	_, ok = normalizeAdaptiveTarget("example.com", 443, udp4)
	require.False(t, ok, "adaptive probing is deliberately limited to TCP targets")
}

func TestAdaptiveTargetSetIsBounded(t *testing.T) {
	state := &adaptiveGroupRuntime{
		config:  adaptiveTestConfig("default", config.AdaptiveModeShadow),
		targets: make(map[adaptiveTargetKey]*adaptiveTargetState),
	}
	state.recommendations.Store(&adaptiveRecommendationSnapshot{entries: make(map[adaptiveTargetKey]adaptiveRecommendation)})
	now := time.Now()
	state.observe(adaptiveTargetKey{domain: "one.example", port: 443, ipVersion: consts.IpVersionStr_4}, now)
	state.observe(adaptiveTargetKey{domain: "one.example", port: 443, ipVersion: consts.IpVersionStr_4}, now.Add(100*time.Millisecond))
	state.observe(adaptiveTargetKey{domain: "one.example", port: 443, ipVersion: consts.IpVersionStr_4}, now.Add(200*time.Millisecond))
	state.observe(adaptiveTargetKey{domain: "two.example", port: 443, ipVersion: consts.IpVersionStr_4}, now.Add(time.Second))
	state.observe(adaptiveTargetKey{domain: "three.example", port: 443, ipVersion: consts.IpVersionStr_4}, now.Add(2*time.Second))
	require.NotContains(t, state.targets, adaptiveTargetKey{domain: "three.example", port: 443, ipVersion: consts.IpVersionStr_4}, "a one-off target must not evict an equally frequent resident")
	state.observe(adaptiveTargetKey{domain: "three.example", port: 443, ipVersion: consts.IpVersionStr_4}, now.Add(3*time.Second))
	require.Len(t, state.targets, 2)
	require.Contains(t, state.targets, adaptiveTargetKey{domain: "one.example", port: 443, ipVersion: consts.IpVersionStr_4}, "the hottest resident must be retained")
	require.NotContains(t, state.targets, adaptiveTargetKey{domain: "two.example", port: 443, ipVersion: consts.IpVersionStr_4})
}

func TestAdaptiveRecommendationNeverCrossesGroupBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialerA := newTestProxyEndpointDialer("a", "a.example")
	dialerB := newTestProxyEndpointDialer("b", "b.example")
	groupA := newAdaptiveTestGroup("default", dialerA)
	groupB := newAdaptiveTestGroup("ai", dialerB)
	router := newAdaptiveRouter(ctx, nil, []*ob.DialerGroup{groupA, groupB}, []config.AdaptiveGroup{
		adaptiveTestConfig("default", config.AdaptiveModeEnforce),
		adaptiveTestConfig("ai", config.AdaptiveModeEnforce),
	}, 0, false)
	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	key, ok := normalizeAdaptiveTarget("github.com", 443, tcp4)
	require.True(t, ok)
	now := time.Now()

	stateA := router.groups[groupA]
	stateA.recommendations.Store(&adaptiveRecommendationSnapshot{entries: map[adaptiveTargetKey]adaptiveRecommendation{
		key: {dialer: dialerA, updatedAt: now},
	}})
	decision := router.recommend(groupA, "github.com", 443, tcp4, nil, false)
	require.True(t, decision.apply)
	require.Same(t, dialerA, decision.recommended)

	stateA.recommendations.Store(&adaptiveRecommendationSnapshot{entries: map[adaptiveTargetKey]adaptiveRecommendation{
		key: {dialer: dialerB, updatedAt: now},
	}})
	decision = router.recommend(groupA, "github.com", 443, tcp4, nil, false)
	require.False(t, decision.apply)
	require.Nil(t, decision.recommended, "a recommendation from the ai group must not be admitted into default")

	stateB := router.groups[groupB]
	stateB.recommendations.Store(&adaptiveRecommendationSnapshot{entries: map[adaptiveTargetKey]adaptiveRecommendation{
		key: {dialer: dialerB, updatedAt: now},
	}})
	decision = router.recommend(groupB, "github.com", 443, tcp4, nil, false)
	require.True(t, decision.apply)
	require.Same(t, dialerB, decision.recommended)
}

func TestAdaptiveShadowRecommendationIsObservableButNotApplied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := newTestProxyEndpointDialer("shadow", "shadow.example")
	group := newAdaptiveTestGroup("default", d)
	router := newAdaptiveRouter(ctx, nil, []*ob.DialerGroup{group}, []config.AdaptiveGroup{
		adaptiveTestConfig("default", config.AdaptiveModeShadow),
	}, 0, false)
	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	key, ok := normalizeAdaptiveTarget("github.com", 443, tcp4)
	require.True(t, ok)
	router.groups[group].recommendations.Store(&adaptiveRecommendationSnapshot{entries: map[adaptiveTargetKey]adaptiveRecommendation{
		key: {dialer: d, updatedAt: time.Now()},
	}})

	decision := router.recommend(group, "github.com", 443, tcp4, nil, false)
	require.Equal(t, config.AdaptiveModeShadow, decision.mode)
	require.Same(t, d, decision.recommended)
	require.False(t, decision.apply)
}

func TestAdaptiveRecommendationRequiresConfiguredProbePort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := newTestProxyEndpointDialer("web", "web.example")
	group := newAdaptiveTestGroup("default", d)
	router := newAdaptiveRouter(ctx, nil, []*ob.DialerGroup{group}, []config.AdaptiveGroup{
		adaptiveTestConfig("default", config.AdaptiveModeEnforce),
	}, 0, false)
	tcp4 := &componentdialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	key := adaptiveTargetKey{domain: "example.com", port: 80, ipVersion: consts.IpVersionStr_4}
	router.groups[group].recommendations.Store(&adaptiveRecommendationSnapshot{entries: map[adaptiveTargetKey]adaptiveRecommendation{
		key: {dialer: d, updatedAt: time.Now()},
	}})

	decision := router.recommend(group, "example.com", 80, tcp4, nil, false)
	require.False(t, decision.apply)
	require.Nil(t, decision.recommended)
}

func TestAdaptivePrometheusTargetLabelsAreOptIn(t *testing.T) {
	router := &adaptiveRouter{}
	router.metrics.Store(&adaptiveMetricsSnapshot{groups: []adaptiveGroupSnapshot{{
		name: "ai", mode: config.AdaptiveModeShadow,
		targets: []adaptiveTargetSnapshot{{domain: "api.example", port: 443, network: "tcp4", hot: true, count: 42}},
	}}})

	var withoutTargets strings.Builder
	router.writePrometheus(&withoutTargets, false)
	require.NotContains(t, withoutTargets.String(), "api.example")
	require.Contains(t, withoutTargets.String(), `dae_adaptive_targets{group="ai",mode="shadow"} 1`)

	var withTargets strings.Builder
	router.writePrometheus(&withTargets, true)
	require.Contains(t, withTargets.String(), `target="api.example:443"`)
}
