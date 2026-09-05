/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

type proxyDialParam struct {
	Outbound         consts.OutboundIndex
	Domain           string
	Mac              [6]uint8
	Dscp             uint8
	ProcessName      [16]uint8
	Src              netip.AddrPort
	Dest             netip.AddrPort
	Mark             uint32
	Network          string         // e.g. "tcp", "udp"
	Excluded         *dialer.Dialer // Dialer to exclude in selection
	adaptiveObserved bool
}

type proxyDialResult struct {
	Outbound                *ob.DialerGroup
	Dialer                  *dialer.Dialer
	DialTarget              string
	Network                 string
	Mark                    uint32
	SniffedDomain           string
	IsDialIp                bool
	OrigNetworkType         string
	SelectionNetworkType    string
	OrigNetworkTypeObj      *dialer.NetworkType
	SelectionNetworkTypeObj *dialer.NetworkType
	AdmissionNetworkTypeObj *dialer.NetworkType
	TargetPort              uint16
	AdaptiveMode            string
	AdaptiveRecommended     string
	AdaptiveApplied         bool
}

const adaptiveRecommendedDialTimeout = 3 * time.Second

func shouldForceMarkUnavailableOnProxyDialError(err error) bool {
	if err == nil {
		return false
	}
	return commonerrors.IsNetworkUnreachable(err) || commonerrors.IsAddressNotSuitable(err)
}

func notifyProxyDialerHealthCheck(d *dialer.Dialer, l4proto consts.L4ProtoStr, err error) {
	if d == nil || err == nil {
		return
	}
	if commonerrors.IsCanceledOrClosed(err) || !isProxyBackedDialer(d) {
		return
	}
	if l4proto == consts.L4ProtoStr_UDP {
		d.NotifyCheckDnsUdp()
		return
	}
	d.NotifyCheckTcp()
}

func shouldRetryAdaptiveProxyDial(ctx context.Context, res *proxyDialResult, err error) bool {
	if err == nil || res == nil || res.Dialer == nil || !res.AdaptiveApplied {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return isProxyBackedDialer(res.Dialer)
}

func proxyDialTimeout(res *proxyDialResult) time.Duration {
	if res != nil && res.AdaptiveApplied {
		return adaptiveRecommendedDialTimeout
	}
	return consts.DefaultDialTimeout
}

func alternateNetworkType(networkType *dialer.NetworkType) *dialer.NetworkType {
	if networkType == nil {
		return nil
	}
	switch networkType.IpVersion {
	case consts.IpVersionStr_4:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_6
		return &alt
	case consts.IpVersionStr_6:
		alt := *networkType
		alt.IpVersion = consts.IpVersionStr_4
		return &alt
	default:
		return nil
	}
}

func endpointNetworkTypeForSelection(requestedNetworkType *dialer.NetworkType, admissionNetworkType *dialer.NetworkType) *dialer.NetworkType {
	if requestedNetworkType == nil {
		return nil
	}
	endpointType := *requestedNetworkType
	if admissionNetworkType != nil && admissionNetworkType.IpVersion != "" {
		endpointType.IpVersion = admissionNetworkType.IpVersion
	}
	if endpointType.L4Proto == consts.L4ProtoStr_UDP {
		endpointType.IsDns = false
		endpointType.UdpHealthDomain = dialer.UdpHealthDomainData
	}
	return &endpointType
}

func (c *ControlPlane) chooseProxyDialer(ctx context.Context, p *proxyDialParam) (*proxyDialResult, error) {
	outboundIndex := p.Outbound
	domain := p.Domain
	src := p.Src
	dst := p.Dest
	mark := p.Mark

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	if outboundIndex == consts.OutboundControlPlaneRouting {
		routingResult := &bpfRoutingResult{
			Mark:     mark,
			Mac:      p.Mac,
			Outbound: uint8(p.Outbound),
			Pname:    p.ProcessName,
			Dscp:     p.Dscp,
		}
		var newMark uint32
		var err error
		proto := consts.L4ProtoType_TCP
		if p.Network == "udp" {
			proto = consts.L4ProtoType_UDP
		}
		if outboundIndex, newMark, _, err = c.Route(src, dst, domain, proto, routingResult); err != nil {
			return nil, err
		}
		mark = newMark
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, dst, domain)
		c.log.Tracef("outbound rerouted: %v => %v",
			consts.OutboundControlPlaneRouting.String(),
			outboundIndex.String(),
		)
	}

	if mark == 0 {
		mark = c.soMarkFromDae
	}

	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}

	outbound := c.outbounds[outboundIndex]
	networkType := &dialer.NetworkType{
		L4Proto:         consts.L4ProtoStr(p.Network),
		IpVersion:       consts.IpVersionFromAddr(dst.Addr()),
		IsDns:           false,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}

	// For UDP, ensure dialer's address family matches client's to prevent
	// "non-IPv4/IPv6 address" errors when writing responses.
	selectionNetworkType := networkType
	if p.Network == "udp" {
		if clientIpVersion := consts.IpVersionFromAddr(src.Addr()); clientIpVersion != networkType.IpVersion {
			selectionNetworkType = &dialer.NetworkType{
				L4Proto:         networkType.L4Proto,
				IpVersion:       clientIpVersion,
				IsDns:           false,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			}
		}
	}

	strictIpVersion := dialIp
	observeAdaptive := !p.adaptiveObserved
	p.adaptiveObserved = true
	adaptiveDecision := c.adaptive.recommend(outbound, domain, dst.Port(), selectionNetworkType, p.Excluded, observeAdaptive)
	var (
		d                    *dialer.Dialer
		admissionNetworkType *dialer.NetworkType
		err                  error
	)
	if adaptiveDecision.apply && adaptiveDecision.recommended != nil {
		d = adaptiveDecision.recommended
		admissionNetworkType = selectionNetworkType
	} else {
		d, _, admissionNetworkType, err = outbound.SelectWithExclusionResult(selectionNetworkType, strictIpVersion, p.Excluded)
	}
	if err != nil && err == ob.ErrNoAliveDialer {
		// Fallback for UDP/TCP: if selection failed (probably due to health check fail),
		// try the other IP version if strictIpVersion is not absolutely required by domain routing.
		altType := alternateNetworkType(selectionNetworkType)
		d, _, admissionNetworkType, err = outbound.SelectWithExclusionResult(altType, false, p.Excluded)
		if err == nil {
			selectionNetworkType = altType
		}
	}

	if err != nil {
		return &proxyDialResult{
				Outbound:                outbound,
				IsDialIp:                strictIpVersion,
				OrigNetworkType:         networkType.StringWithoutDns(),
				SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
				OrigNetworkTypeObj:      networkType,
				SelectionNetworkTypeObj: selectionNetworkType,
				AdmissionNetworkTypeObj: admissionNetworkType,
				TargetPort:              dst.Port(),
				AdaptiveMode:            adaptiveDecision.mode,
				AdaptiveRecommended:     dialerName(adaptiveDecision.recommended),
				AdaptiveApplied:         adaptiveDecision.apply,
			}, fmt.Errorf("select dialer from group %v (orig:%v sel:%v src:%v): %w",
				outbound.Name,
				networkType.StringWithoutDns(),
				selectionNetworkType.StringWithoutDns(),
				p.Src.String(),
				err,
			)
	}

	selectionNetworkType = endpointNetworkTypeForSelection(selectionNetworkType, admissionNetworkType)

	return &proxyDialResult{
		Outbound:   outbound,
		Dialer:     d,
		DialTarget: dialTarget,
		Network: func() string {
			if p.Network == "udp" {
				return common.MagicNetworkWithIPVersion(p.Network, mark, c.mptcp, string(selectionNetworkType.IpVersion))
			}
			return common.MagicNetwork(p.Network, mark, c.mptcp)
		}(),
		SniffedDomain:           domain,
		Mark:                    mark,
		IsDialIp:                strictIpVersion,
		OrigNetworkType:         networkType.StringWithoutDns(),
		SelectionNetworkType:    selectionNetworkType.StringWithoutDns(),
		OrigNetworkTypeObj:      networkType,
		SelectionNetworkTypeObj: selectionNetworkType,
		AdmissionNetworkTypeObj: admissionNetworkType,
		TargetPort:              dst.Port(),
		AdaptiveMode:            adaptiveDecision.mode,
		AdaptiveRecommended:     dialerName(adaptiveDecision.recommended),
		AdaptiveApplied:         adaptiveDecision.apply,
	}, nil
}

func (c *ControlPlane) routeDial(ctx context.Context, p *proxyDialParam) (netproxy.Conn, *proxyDialResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastRes *proxyDialResult
	var lastErr error
	for attempt := range 2 {
		res, err := c.chooseProxyDialer(ctx, p)
		if err != nil {
			if c.log != nil {
				c.log.WithError(err).WithFields(logrus.Fields{
					"attempt":       attempt + 1,
					"requested_out": p.Outbound.String(),
					"network":       p.Network,
					"src":           p.Src.String(),
					"dst":           p.Dest.String(),
					"sniffed":       p.Domain,
					"excluded":      dialerName(p.Excluded),
				}).Warn("diagnostic: outbound dialer selection failed")
			}
			return nil, res, err
		}
		lastRes = res

		startedAt := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, proxyDialTimeout(res))
		conn, err := res.Dialer.DialContext(dialCtx, res.Network, res.DialTarget)
		cancel()
		elapsed := time.Since(startedAt)
		var entry *logrus.Entry
		if c.log != nil {
			entry = c.log.WithFields(logrus.Fields{
				"attempt":              attempt + 1,
				"group":                res.Outbound.Name,
				"dialer":               dialerName(res.Dialer),
				"proxy_backed":         isProxyBackedDialer(res.Dialer),
				"dial_target":          res.DialTarget,
				"network":              res.SelectionNetworkType,
				"magic_network_hex":    fmt.Sprintf("%x", []byte(res.Network)),
				"mark":                 fmt.Sprintf("0x%x", res.Mark),
				"elapsed":              elapsed.String(),
				"sniffed":              res.SniffedDomain,
				"adaptive_mode":        res.AdaptiveMode,
				"adaptive_recommended": res.AdaptiveRecommended,
				"adaptive_applied":     res.AdaptiveApplied,
				"excluded":             dialerName(p.Excluded),
			})
		}
		c.adaptive.recordConnection(res, err)
		if err == nil {
			if entry != nil {
				entry.Debug("diagnostic: outbound dial succeeded")
			}
			return conn, res, nil
		}
		if entry != nil {
			entry.WithError(err).Warn("diagnostic: outbound dial failed")
		}
		lastErr = err
		forceUnavailable := shouldForceMarkUnavailableOnProxyDialError(err)
		retryAdaptive := shouldRetryAdaptiveProxyDial(ctx, res, err)
		if attempt > 0 || (!forceUnavailable && !retryAdaptive) {
			l4proto := consts.L4ProtoStr(p.Network)
			if res.SelectionNetworkTypeObj != nil {
				l4proto = res.SelectionNetworkTypeObj.L4Proto
			}
			notifyProxyDialerHealthCheck(res.Dialer, l4proto, err)
			return nil, res, err
		}
		// A target-specific recommendation is advisory state layered on top of
		// the group's configured selector. If that recommended proxy fails, retry
		// once through the same group while excluding it. This keeps failures
		// from pinning new connections to a stale recommendation, without ever
		// widening selection to another group.
		p.Excluded = res.Dialer
		if forceUnavailable && res.SelectionNetworkTypeObj != nil {
			res.Dialer.ReportUnavailableForced(
				res.SelectionNetworkTypeObj,
				fmt.Errorf("proxy dial failed: %w", err),
			)
		} else if retryAdaptive {
			l4proto := consts.L4ProtoStr(p.Network)
			if res.SelectionNetworkTypeObj != nil {
				l4proto = res.SelectionNetworkTypeObj.L4Proto
			}
			notifyProxyDialerHealthCheck(res.Dialer, l4proto, err)
		}
	}
	return nil, lastRes, lastErr
}
