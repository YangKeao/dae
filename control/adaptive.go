/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
)

const adaptiveEventQueueSize = 8192

const (
	adaptiveFrequencyRows    = 4
	adaptiveFrequencyBuckets = 256
)

type adaptiveTargetKey struct {
	domain    string
	port      uint16
	ipVersion consts.IpVersionStr
}

func (k adaptiveTargetKey) network() string {
	return "tcp" + string(k.ipVersion)
}

func (k adaptiveTargetKey) address() string {
	return net.JoinHostPort(k.domain, strconv.Itoa(int(k.port)))
}

type adaptiveDecision struct {
	mode        string
	recommended *dialer.Dialer
	apply       bool
}

type adaptiveRecommendation struct {
	dialer    *dialer.Dialer
	latency   time.Duration
	updatedAt time.Time
}

type adaptiveRecommendationSnapshot struct {
	entries map[adaptiveTargetKey]adaptiveRecommendation
}

type adaptiveProbeState struct {
	inFlight       bool
	lastProbe      time.Time
	lastSuccess    time.Time
	success        bool
	latency        time.Duration
	ewmaLatency    time.Duration
	passiveSuccess uint64
}

type adaptiveTargetState struct {
	key         adaptiveTargetKey
	count       uint64
	windowStart time.Time
	lastSeen    time.Time
	probes      map[*dialer.Dialer]*adaptiveProbeState
	recommended *dialer.Dialer
	pending     *dialer.Dialer
	pendingWins int
}

type adaptiveConnectionMetricKey struct {
	dialer  string
	network string
	result  string
}

type adaptiveProbeMetricKey struct {
	dialer  string
	network string
	result  string
}

type adaptiveGroupRuntime struct {
	group   *ob.DialerGroup
	config  config.AdaptiveGroup
	members map[*dialer.Dialer]struct{}
	targets map[adaptiveTargetKey]*adaptiveTargetState

	recommendations atomic.Pointer[adaptiveRecommendationSnapshot]
	connections     map[adaptiveConnectionMetricKey]uint64
	probeTotals     map[adaptiveProbeMetricKey]uint64

	probeTokens     float64
	lastTokenRefill time.Time
	inFlight        int

	frequencyWindowStart time.Time
	frequencySketch      [adaptiveFrequencyRows][adaptiveFrequencyBuckets]uint32
}

type adaptiveEventKind uint8

const (
	adaptiveObserveTarget adaptiveEventKind = iota
	adaptiveRecordConnection
	adaptiveRecordPassiveSuccess
	adaptiveRecordProbeResult
)

type adaptiveEvent struct {
	kind     adaptiveEventKind
	group    *ob.DialerGroup
	key      adaptiveTargetKey
	dialer   *dialer.Dialer
	network  string
	result   string
	latency  time.Duration
	success  bool
	observed time.Time
}

type adaptiveProbeSnapshot struct {
	dialer         string
	success        bool
	latency        time.Duration
	lastProbe      time.Time
	lastSuccess    time.Time
	passiveSuccess uint64
}

type adaptiveTargetSnapshot struct {
	domain           string
	port             uint16
	network          string
	count            uint64
	hot              bool
	lastSeen         time.Time
	recommended      string
	recommendationAt time.Time
	probes           []adaptiveProbeSnapshot
}

type adaptiveGroupSnapshot struct {
	name        string
	mode        string
	targets     []adaptiveTargetSnapshot
	connections map[adaptiveConnectionMetricKey]uint64
	probeTotals map[adaptiveProbeMetricKey]uint64
}

type adaptiveMetricsSnapshot struct {
	groups        []adaptiveGroupSnapshot
	droppedEvents uint64
}

type adaptiveRouter struct {
	ctx    context.Context
	log    *logrus.Logger
	groups map[*ob.DialerGroup]*adaptiveGroupRuntime
	events chan adaptiveEvent
	mark   uint32
	mptcp  bool

	droppedEvents atomic.Uint64
	metrics       atomic.Pointer[adaptiveMetricsSnapshot]
}

func newAdaptiveRouter(
	ctx context.Context,
	log *logrus.Logger,
	outbounds []*ob.DialerGroup,
	configs []config.AdaptiveGroup,
	mark uint32,
	mptcp bool,
) *adaptiveRouter {
	if ctx == nil {
		ctx = context.Background()
	}
	byName := make(map[string]config.AdaptiveGroup, len(configs))
	for _, cfg := range configs {
		byName[cfg.Name] = cfg
	}
	now := time.Now()
	r := &adaptiveRouter{
		ctx:    ctx,
		log:    log,
		groups: make(map[*ob.DialerGroup]*adaptiveGroupRuntime, len(outbounds)),
		events: make(chan adaptiveEvent, adaptiveEventQueueSize),
		mark:   mark,
		mptcp:  mptcp,
	}
	for _, group := range outbounds {
		if group == nil {
			continue
		}
		cfg, ok := byName[group.Name]
		if !ok {
			cfg = config.AdaptiveGroup{Name: group.Name, Mode: config.AdaptiveModeOff}
		}
		members := make(map[*dialer.Dialer]struct{}, len(group.Dialers))
		for _, d := range group.Dialers {
			if d != nil {
				members[d] = struct{}{}
			}
		}
		state := &adaptiveGroupRuntime{
			group:           group,
			config:          cfg,
			members:         members,
			targets:         make(map[adaptiveTargetKey]*adaptiveTargetState),
			connections:     make(map[adaptiveConnectionMetricKey]uint64),
			probeTotals:     make(map[adaptiveProbeMetricKey]uint64),
			probeTokens:     float64(cfg.MaxProbesPerMinute),
			lastTokenRefill: now,
		}
		state.recommendations.Store(&adaptiveRecommendationSnapshot{entries: make(map[adaptiveTargetKey]adaptiveRecommendation)})
		r.groups[group] = state
	}
	r.publishMetrics(now)
	go r.run()
	return r
}

func normalizeAdaptiveTarget(domain string, port uint16, networkType *dialer.NetworkType) (adaptiveTargetKey, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || port == 0 || networkType == nil || networkType.L4Proto != consts.L4ProtoStr_TCP {
		return adaptiveTargetKey{}, false
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil || ascii == "" {
		return adaptiveTargetKey{}, false
	}
	if networkType.IpVersion != consts.IpVersionStr_4 && networkType.IpVersion != consts.IpVersionStr_6 {
		return adaptiveTargetKey{}, false
	}
	return adaptiveTargetKey{domain: ascii, port: port, ipVersion: networkType.IpVersion}, true
}

func (r *adaptiveRouter) recommend(
	group *ob.DialerGroup,
	domain string,
	port uint16,
	networkType *dialer.NetworkType,
	excluded *dialer.Dialer,
	observe bool,
) adaptiveDecision {
	if r == nil || group == nil {
		return adaptiveDecision{}
	}
	state := r.groups[group]
	if state == nil || state.config.Mode == config.AdaptiveModeOff {
		return adaptiveDecision{mode: config.AdaptiveModeOff}
	}
	key, ok := normalizeAdaptiveTarget(domain, port, networkType)
	if !ok || !state.probePortAllowed(key.port) {
		return adaptiveDecision{mode: state.config.Mode}
	}
	if observe {
		r.enqueue(adaptiveEvent{kind: adaptiveObserveTarget, group: group, key: key, observed: time.Now()})
	}
	snapshot := state.recommendations.Load()
	if snapshot == nil {
		return adaptiveDecision{mode: state.config.Mode}
	}
	recommendation, ok := snapshot.entries[key]
	if !ok || recommendation.dialer == nil || time.Since(recommendation.updatedAt) > state.config.RecommendationTtl {
		return adaptiveDecision{mode: state.config.Mode}
	}
	if _, member := state.members[recommendation.dialer]; !member || recommendation.dialer == excluded || !recommendation.dialer.MustGetAlive(networkType) {
		return adaptiveDecision{mode: state.config.Mode}
	}
	return adaptiveDecision{
		mode:        state.config.Mode,
		recommended: recommendation.dialer,
		apply:       state.config.Mode == config.AdaptiveModeEnforce,
	}
}

func (s *adaptiveGroupRuntime) probePortAllowed(port uint16) bool {
	for _, allowed := range s.config.ProbePorts {
		if allowed == port {
			return true
		}
	}
	return false
}

func (r *adaptiveRouter) recordConnection(res *proxyDialResult, err error) {
	if r == nil || res == nil || res.Outbound == nil || res.Dialer == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	r.enqueue(adaptiveEvent{
		kind:    adaptiveRecordConnection,
		group:   res.Outbound,
		dialer:  res.Dialer,
		network: res.OrigNetworkType,
		result:  result,
	})
}

func (r *adaptiveRouter) recordPassiveSuccess(res *proxyDialResult) {
	if r == nil || res == nil || res.Outbound == nil || res.Dialer == nil || res.SniffedDomain == "" || res.TargetPort == 0 || res.OrigNetworkTypeObj == nil {
		return
	}
	key, ok := normalizeAdaptiveTarget(res.SniffedDomain, res.TargetPort, res.OrigNetworkTypeObj)
	if !ok {
		return
	}
	r.enqueue(adaptiveEvent{
		kind:     adaptiveRecordPassiveSuccess,
		group:    res.Outbound,
		key:      key,
		dialer:   res.Dialer,
		observed: time.Now(),
	})
}

func (r *adaptiveRouter) enqueue(event adaptiveEvent) {
	select {
	case r.events <- event:
	default:
		r.droppedEvents.Add(1)
	}
}

func (r *adaptiveRouter) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case event := <-r.events:
			r.handleEvent(event)
		case now := <-ticker.C:
			r.schedule(now)
			r.publishMetrics(now)
		}
	}
}

func (r *adaptiveRouter) handleEvent(event adaptiveEvent) {
	state := r.groups[event.group]
	if state == nil {
		return
	}
	switch event.kind {
	case adaptiveObserveTarget:
		if state.config.Mode != config.AdaptiveModeOff {
			state.observe(event.key, event.observed)
		}
	case adaptiveRecordConnection:
		name := dialerName(event.dialer)
		state.connections[adaptiveConnectionMetricKey{dialer: name, network: event.network, result: event.result}]++
	case adaptiveRecordPassiveSuccess:
		target := state.targets[event.key]
		if target == nil {
			return
		}
		probe := target.probes[event.dialer]
		if probe == nil {
			probe = &adaptiveProbeState{}
			target.probes[event.dialer] = probe
		}
		probe.passiveSuccess++
	case adaptiveRecordProbeResult:
		r.handleProbeResult(state, event)
	}
}

func (s *adaptiveGroupRuntime) observe(key adaptiveTargetKey, now time.Time) {
	estimatedFrequency := s.bumpFrequency(key, now)
	if target := s.targets[key]; target != nil {
		target.count++
		target.lastSeen = now
		return
	}
	if len(s.targets) >= s.config.MaxTargets {
		var victimKey adaptiveTargetKey
		var victim *adaptiveTargetState
		for candidateKey, candidate := range s.targets {
			if victim == nil || candidate.count < victim.count || (candidate.count == victim.count && candidate.lastSeen.Before(victim.lastSeen)) {
				victimKey, victim = candidateKey, candidate
			}
		}
		if victim == nil || uint64(estimatedFrequency) <= victim.count {
			return
		}
		delete(s.targets, victimKey)
		s.removeRecommendation(victimKey)
	}
	s.targets[key] = &adaptiveTargetState{
		key:         key,
		count:       uint64(estimatedFrequency),
		windowStart: now,
		lastSeen:    now,
		probes:      make(map[*dialer.Dialer]*adaptiveProbeState),
	}
}

func (s *adaptiveGroupRuntime) bumpFrequency(key adaptiveTargetKey, now time.Time) uint32 {
	if s.frequencyWindowStart.IsZero() {
		s.frequencyWindowStart = now
	} else if now.Sub(s.frequencyWindowStart) >= s.config.ObservationWindow {
		s.frequencySketch = [adaptiveFrequencyRows][adaptiveFrequencyBuckets]uint32{}
		s.frequencyWindowStart = now
		for _, target := range s.targets {
			target.count = 0
			target.windowStart = now
		}
	}
	encoded := key.domain + "\x00" + strconv.Itoa(int(key.port)) + "\x00" + string(key.ipVersion)
	min := ^uint32(0)
	for row := range adaptiveFrequencyRows {
		hash := uint32(2166136261) ^ uint32(row)*uint32(0x9e3779b9)
		for i := range len(encoded) {
			hash ^= uint32(encoded[i])
			hash *= 16777619
		}
		bucket := hash % adaptiveFrequencyBuckets
		if s.frequencySketch[row][bucket] != ^uint32(0) {
			s.frequencySketch[row][bucket]++
		}
		if value := s.frequencySketch[row][bucket]; value < min {
			min = value
		}
	}
	return min
}

func (r *adaptiveRouter) schedule(now time.Time) {
	for _, state := range r.groups {
		if state.config.Mode == config.AdaptiveModeOff {
			continue
		}
		state.refillTokens(now)
		for key, target := range state.targets {
			if now.Sub(target.lastSeen) > state.config.IdleTtl {
				delete(state.targets, key)
				state.removeRecommendation(key)
				continue
			}
			if !state.isHot(target, now) {
				continue
			}
			for _, d := range state.group.Dialers {
				if d == nil || state.inFlight >= state.config.MaxConcurrentProbes || state.probeTokens < 1 {
					break
				}
				probe := target.probes[d]
				if probe == nil {
					probe = &adaptiveProbeState{}
					target.probes[d] = probe
				}
				if probe.inFlight || (!probe.lastProbe.IsZero() && now.Sub(probe.lastProbe) < state.config.ProbeInterval) {
					continue
				}
				networkType := networkTypeForAdaptiveKey(key)
				if !d.MustGetAlive(networkType) {
					continue
				}
				probe.inFlight = true
				state.inFlight++
				state.probeTokens--
				go r.probe(state, target.key, d)
			}
		}
	}
}

func (s *adaptiveGroupRuntime) refillTokens(now time.Time) {
	if s.lastTokenRefill.IsZero() {
		s.lastTokenRefill = now
	}
	elapsed := now.Sub(s.lastTokenRefill).Minutes()
	if elapsed <= 0 {
		return
	}
	s.probeTokens += elapsed * float64(s.config.MaxProbesPerMinute)
	if maxTokens := float64(s.config.MaxProbesPerMinute); s.probeTokens > maxTokens {
		s.probeTokens = maxTokens
	}
	s.lastTokenRefill = now
}

func (s *adaptiveGroupRuntime) isHot(target *adaptiveTargetState, now time.Time) bool {
	return target != nil && now.Sub(target.windowStart) <= s.config.ObservationWindow && target.count >= s.config.MinConnections
}

func (r *adaptiveRouter) probe(state *adaptiveGroupRuntime, key adaptiveTargetKey, d *dialer.Dialer) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.ctx, state.config.ProbeTimeout)
	defer cancel()

	network := common.MagicNetworkWithIPVersion("tcp", r.mark, r.mptcp, string(key.ipVersion))
	conn, err := d.DialContext(ctx, network, key.address())
	if err == nil {
		if key.port == 443 {
			fakeConn := &netproxy.FakeNetConn{Conn: conn}
			tlsConn := tls.Client(fakeConn, &tls.Config{ServerName: key.domain, MinVersion: tls.VersionTLS12})
			err = tlsConn.HandshakeContext(ctx)
			_ = tlsConn.Close()
		} else {
			_ = conn.Close()
		}
	}
	result := adaptiveEvent{
		kind:     adaptiveRecordProbeResult,
		group:    state.group,
		key:      key,
		dialer:   d,
		latency:  time.Since(started),
		success:  err == nil,
		observed: time.Now(),
	}
	if err != nil {
		result.result = "error"
	} else {
		result.result = "success"
	}
	select {
	case r.events <- result:
	case <-r.ctx.Done():
	}
}

func (r *adaptiveRouter) handleProbeResult(state *adaptiveGroupRuntime, event adaptiveEvent) {
	target := state.targets[event.key]
	if target == nil {
		if state.inFlight > 0 {
			state.inFlight--
		}
		return
	}
	probe := target.probes[event.dialer]
	if probe == nil {
		probe = &adaptiveProbeState{}
		target.probes[event.dialer] = probe
	}
	probe.inFlight = false
	probe.lastProbe = event.observed
	probe.success = event.success
	probe.latency = event.latency
	if event.success {
		probe.lastSuccess = event.observed
		probe.ewmaLatency = adaptiveEWMA(probe.ewmaLatency, event.latency, 0.35)
	}
	if state.inFlight > 0 {
		state.inFlight--
	}
	name := dialerName(event.dialer)
	state.probeTotals[adaptiveProbeMetricKey{dialer: name, network: event.key.network(), result: event.result}]++
	state.recomputeRecommendation(target, event.observed, r.log)
}

func adaptiveEWMA(old, next time.Duration, alpha float64) time.Duration {
	if old <= 0 {
		return next
	}
	return time.Duration((1-alpha)*float64(old) + alpha*float64(next))
}

func (s *adaptiveGroupRuntime) recomputeRecommendation(target *adaptiveTargetState, now time.Time, log *logrus.Logger) {
	var best *dialer.Dialer
	var bestLatency time.Duration
	networkType := networkTypeForAdaptiveKey(target.key)
	eligible := func(d *dialer.Dialer) bool {
		probe := target.probes[d]
		if probe == nil || !probe.success || probe.lastProbe.IsZero() || now.Sub(probe.lastProbe) > s.config.RecommendationTtl {
			return false
		}
		_, member := s.members[d]
		return member && d.MustGetAlive(networkType)
	}
	for _, d := range s.group.Dialers {
		if !eligible(d) {
			continue
		}
		latency := target.probes[d].ewmaLatency
		if best == nil || latency < bestLatency {
			best, bestLatency = d, latency
		}
	}
	if best == nil {
		target.recommended = nil
		target.pending = nil
		target.pendingWins = 0
		s.removeRecommendation(target.key)
		return
	}

	current := target.recommended
	switchNow := current == nil || !eligible(current)
	if current == best {
		target.pending = nil
		target.pendingWins = 0
		s.setRecommendation(target.key, best, bestLatency, now)
		return
	}
	if !switchNow {
		currentLatency := target.probes[current].ewmaLatency
		absoluteImprovement := currentLatency - bestLatency
		required := s.config.SwitchTolerance
		if relative := time.Duration(float64(currentLatency) * float64(s.config.SwitchMinPercent) / 100); relative > required {
			required = relative
		}
		if absoluteImprovement >= required {
			if target.pending == best {
				target.pendingWins++
			} else {
				target.pending = best
				target.pendingWins = 1
			}
			switchNow = target.pendingWins >= 2
		} else {
			target.pending = nil
			target.pendingWins = 0
		}
	}
	if !switchNow {
		return
	}
	oldName := dialerName(current)
	target.recommended = best
	target.pending = nil
	target.pendingWins = 0
	s.setRecommendation(target.key, best, bestLatency, now)
	if log != nil && log.IsLevelEnabled(logrus.InfoLevel) {
		log.WithFields(logrus.Fields{
			"group":         s.group.Name,
			"target":        target.key.address(),
			"network":       target.key.network(),
			"_old_dialer":   oldName,
			"_new_dialer":   dialerName(best),
			"adaptive_mode": s.config.Mode,
			"probe_latency": bestLatency,
		}).Info("Adaptive target recommendation changed")
	}
}

func (s *adaptiveGroupRuntime) setRecommendation(key adaptiveTargetKey, d *dialer.Dialer, latency time.Duration, now time.Time) {
	current := s.recommendations.Load()
	next := make(map[adaptiveTargetKey]adaptiveRecommendation, len(s.targets))
	if current != nil {
		for k, recommendation := range current.entries {
			next[k] = recommendation
		}
	}
	next[key] = adaptiveRecommendation{dialer: d, latency: latency, updatedAt: now}
	s.recommendations.Store(&adaptiveRecommendationSnapshot{entries: next})
}

func (s *adaptiveGroupRuntime) removeRecommendation(key adaptiveTargetKey) {
	current := s.recommendations.Load()
	if current == nil {
		return
	}
	next := make(map[adaptiveTargetKey]adaptiveRecommendation, len(current.entries))
	for k, recommendation := range current.entries {
		if k != key {
			next[k] = recommendation
		}
	}
	s.recommendations.Store(&adaptiveRecommendationSnapshot{entries: next})
}

func (r *adaptiveRouter) publishMetrics(now time.Time) {
	snapshot := &adaptiveMetricsSnapshot{droppedEvents: r.droppedEvents.Load()}
	for _, state := range r.groups {
		groupSnapshot := adaptiveGroupSnapshot{
			name:        state.group.Name,
			mode:        state.config.Mode,
			connections: cloneConnectionMetrics(state.connections),
			probeTotals: cloneProbeMetrics(state.probeTotals),
		}
		recommendations := state.recommendations.Load()
		for _, target := range state.targets {
			targetSnapshot := adaptiveTargetSnapshot{
				domain:   target.key.domain,
				port:     target.key.port,
				network:  target.key.network(),
				count:    target.count,
				hot:      state.isHot(target, now),
				lastSeen: target.lastSeen,
			}
			if recommendations != nil {
				if recommendation, ok := recommendations.entries[target.key]; ok {
					targetSnapshot.recommended = dialerName(recommendation.dialer)
					targetSnapshot.recommendationAt = recommendation.updatedAt
				}
			}
			for _, d := range state.group.Dialers {
				probe := target.probes[d]
				if probe == nil || probe.lastProbe.IsZero() {
					continue
				}
				targetSnapshot.probes = append(targetSnapshot.probes, adaptiveProbeSnapshot{
					dialer:         dialerName(d),
					success:        probe.success,
					latency:        probe.ewmaLatency,
					lastProbe:      probe.lastProbe,
					lastSuccess:    probe.lastSuccess,
					passiveSuccess: probe.passiveSuccess,
				})
			}
			groupSnapshot.targets = append(groupSnapshot.targets, targetSnapshot)
		}
		snapshot.groups = append(snapshot.groups, groupSnapshot)
	}
	r.metrics.Store(snapshot)
}

func cloneConnectionMetrics(src map[adaptiveConnectionMetricKey]uint64) map[adaptiveConnectionMetricKey]uint64 {
	dst := make(map[adaptiveConnectionMetricKey]uint64, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneProbeMetrics(src map[adaptiveProbeMetricKey]uint64) map[adaptiveProbeMetricKey]uint64 {
	dst := make(map[adaptiveProbeMetricKey]uint64, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func networkTypeForAdaptiveKey(key adaptiveTargetKey) *dialer.NetworkType {
	return &dialer.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: key.ipVersion}
}

func dialerName(d *dialer.Dialer) string {
	if d == nil || d.Property() == nil {
		return ""
	}
	return d.Property().Name
}
