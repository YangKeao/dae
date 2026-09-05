/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	daerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

func TestRouteDial_RetriesAlternateFamilyAfterLocalNetworkFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	d, underlay := newSequenceProxyEndpointDialer(
		"shadowsocks_2022",
		"proxy.example:443",
		scriptedDialResult{err: daerrors.ErrNetworkUnreachable},
		scriptedDialResult{conn: clientConn},
	)
	cp := newTestDialControlPlane(newTestFixedOutboundGroup(d))

	conn, res, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Src:      netip.MustParseAddrPort("[2001:db8::10]:42687"),
		Dest:     netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatalf("routeDial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := underlay.calls.Load(); got != 2 {
		t.Fatalf("DialContext calls = %d, want 2", got)
	}
	if got := res.SelectionNetworkTypeObj.IpVersion; got != consts.IpVersionStr_4 {
		t.Fatalf("selection ip version = %v, want %v", got, consts.IpVersionStr_4)
	}
}

func TestRouteDial_AdaptiveRecommendationFailureFallsBackInsideGroup(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	fallback, fallbackUnderlay := newSequenceProxyEndpointDialer(
		"socks5",
		"fallback.example:1080",
		scriptedDialResult{conn: clientConn},
	)
	recommended, recommendedUnderlay := newSequenceProxyEndpointDialer(
		"socks5",
		"recommended.example:1080",
		scriptedDialResult{err: io.ErrUnexpectedEOF},
	)
	group := newTestFixedOutboundGroup(fallback, recommended)
	cp := newTestDialControlPlane(group)

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp.adaptive = newAdaptiveRouter(ctx, logger, cp.outbounds, []config.AdaptiveGroup{{
		Name:              group.Name,
		Mode:              config.AdaptiveModeEnforce,
		ProbePorts:        []uint16{443},
		RecommendationTtl: time.Minute,
	}}, cp.soMarkFromDae, false)
	key := adaptiveTargetKey{
		domain:    "target.test",
		port:      443,
		ipVersion: consts.IpVersionStr_4,
	}
	cp.adaptive.groups[group].recommendations.Store(&adaptiveRecommendationSnapshot{
		entries: map[adaptiveTargetKey]adaptiveRecommendation{
			key: {dialer: recommended, updatedAt: time.Now()},
		},
	})

	conn, res, err := cp.routeDial(context.Background(), &proxyDialParam{
		Outbound: consts.OutboundUserDefinedMin,
		Domain:   "target.test",
		Src:      netip.MustParseAddrPort("192.0.2.10:42687"),
		Dest:     netip.MustParseAddrPort("198.51.100.10:443"),
		Network:  "tcp",
	})
	if err != nil {
		t.Fatalf("routeDial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if res.Dialer != fallback {
		t.Fatalf("selected dialer = %q, want fallback", res.Dialer.Property().Name)
	}
	if got := recommendedUnderlay.calls.Load(); got != 1 {
		t.Fatalf("recommended DialContext calls = %d, want 1", got)
	}
	if got := fallbackUnderlay.calls.Load(); got != 1 {
		t.Fatalf("fallback DialContext calls = %d, want 1", got)
	}
	if got := dialerSignalChannelLen(t, recommended, "checkTcpCh"); got != 1 {
		t.Fatalf("recommended checkTcpCh len = %d, want 1", got)
	}
}

func TestShouldRetryAdaptiveProxyDial_DoesNotRetryCanceledRequest(t *testing.T) {
	d, _ := newTestEndpointErrorDialer("socks5", "proxy.example:1080", context.Canceled)
	res := &proxyDialResult{Dialer: d, AdaptiveApplied: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if shouldRetryAdaptiveProxyDial(ctx, res, context.Canceled) {
		t.Fatal("canceled parent request should not retry")
	}
	if got := proxyDialTimeout(res); got != adaptiveRecommendedDialTimeout {
		t.Fatalf("adaptive proxy dial timeout = %v, want %v", got, adaptiveRecommendedDialTimeout)
	}
	if got := proxyDialTimeout(&proxyDialResult{}); got != consts.DefaultDialTimeout {
		t.Fatalf("ordinary proxy dial timeout = %v, want %v", got, consts.DefaultDialTimeout)
	}
}
