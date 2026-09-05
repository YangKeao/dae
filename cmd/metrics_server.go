/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

func startMetricsServer(log *logrus.Logger, listen string) (*http.Server, error) {
	if listen == "" {
		return nil, nil
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", control.PrometheusHandler())
	server := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.WithError(err).Error("Prometheus metrics server stopped unexpectedly")
		}
	}()
	if log != nil {
		log.WithField("listen", listen).Info("Prometheus metrics server started")
	}
	return server, nil
}

func refreshMetricsServer(log *logrus.Logger, server **http.Server, currentListen *string, nextListen string) {
	if server == nil || currentListen == nil || *currentListen == nextListen {
		return
	}
	oldListen := *currentListen
	if *server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = (*server).Shutdown(ctx)
		cancel()
		*server = nil
	}
	*currentListen = ""
	nextServer, err := startMetricsServer(log, nextListen)
	if err == nil {
		*server = nextServer
		*currentListen = nextListen
		return
	}
	if log != nil {
		log.WithError(err).WithField("listen", nextListen).Error("Failed to refresh Prometheus metrics server")
	}
	if oldListen != "" {
		fallbackServer, fallbackErr := startMetricsServer(log, oldListen)
		if fallbackErr == nil {
			*server = fallbackServer
			*currentListen = oldListen
		} else if log != nil {
			log.WithError(fallbackErr).WithField("listen", oldListen).Error("Failed to restore previous Prometheus metrics server")
		}
	}
}
