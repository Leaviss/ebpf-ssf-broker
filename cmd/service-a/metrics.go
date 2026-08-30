package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// zta_probe_requests_total — the A-side view of the 200 -> 403 transition,
// dashboard visual only. It is not the measurement: T8
// comes off this process's log at nanosecond resolution, and the authoritative
// deny is istio_requests_total from Service B's sidecar, the enforcement point
// rather than the caller's self-report.
//
// What it buys is a series that flips at the same instant as the prober log, so
// a trial can be watched live in Grafana. At a 20ms probe interval it also makes
// a stalled prober obvious — a flat line is a contaminated trial.
var probeRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "zta_probe_requests_total",
	Help: "Requests from Service A to Service B by HTTP status; code=\"error\" when the request never got a response.",
}, []string{"code"})

func init() {
	// Created at zero so the deny shows as a step rather than a series appearing
	// from nothing.
	for _, code := range []string{"200", "403"} {
		probeRequests.WithLabelValues(code)
	}
}
