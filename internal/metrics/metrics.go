// Package metrics holds the pieces of the metric spec that
// more than one binary needs: the histogram bucket boundaries and the /metrics
// listener. The metric declarations live with the code that observes them, so
// there is no registry indirection between a measurement and its subject.
package metrics

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Buckets for every latency histogram in this project. They run from 100µs (the
// sub-millisecond end resolved) to 5s (outliers bounded, not +Inf); the default
// client_golang buckets start at 5ms, which puts the whole in-code pipeline
// inside their first two and makes p95 a boundary artefact.
//
// The dense region (4ms-30ms) is cut from measured data, not guessed
// (an early run with client_golang's defaults put most pipeline samples in
// one bucket, pushing the interpolated p95 above the observed maximum).
// Re-check it if the pipeline moves scale.
var Buckets = []float64{
	.0001, .00025, .0005, // transport
	.001, .0015, .002, .003, // translate
	.004, .006, .008, // detect / actuate
	.01, .0125, .015, .0175, .02, .0225, .025, .0275, .03, // pipeline
	.04, .05, .075, .1, .25, .5, 1, 2.5, 5, // tail: outliers, bounded
}

// Route is an extra handler to mount on the metrics listener alongside /metrics,
// so a binary can expose a lab-control endpoint on the one port already outside
// the mesh (see Serve) without a third listener. The actuator's dedupe reset is
// the only user today.
type Route struct {
	Pattern string
	Handler http.Handler
}

// Serve starts a /metrics endpoint on addr in the background and returns
// immediately, optionally mounting extra routes on the same listener. An empty
// addr disables it, which is what unit tests and local `go run` want.
//
// Its own mux and its own port, not the service's: the actuator's :9090 is the
// RFC 8935 SET receiver and sits inside the mesh, so a scrape target on it would
// be one more thing on the measured path. That separation is also why `routes`
// mount here — this port carries the annotation excluding it from inbound mesh
// capture, so a lab-control endpoint on it is reachable by a plain port-forward
// and still never touches the measured path.
func Serve(addr string, routes ...Route) {
	if addr == "" {
		slog.Info("Metrics endpoint disabled (empty METRICS_ADDR)")
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	for _, r := range routes {
		mux.Handle(r.Pattern, r.Handler)
		slog.Info("Mounted control endpoint on the metrics listener", "addr", addr, "path", r.Pattern)
	}

	go func() {
		slog.Info("Metrics endpoint listening", "addr", addr, "path", "/metrics")
		if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Not fatal: losing the scrape target costs the dashboard, not the
			// revocation. The per-trial CSV is built from logs regardless.
			slog.Error("Metrics endpoint stopped", "error", err, "addr", addr)
		}
	}()
}
