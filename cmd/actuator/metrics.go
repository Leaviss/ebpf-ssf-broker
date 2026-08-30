package main

import (
	"time"

	"github.com/Leaviss/ebpf-ssf-broker/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The `service` label on zta_revocation_stage_seconds. Every stage is computed
// here, so the label is constant today. It stays because the PromQL and the
// dashboard are written against it, and because a second observer would
// double-count into `sum by (stage)`.
const serviceLabel = "actuator"

var (
	// One histogram with a `stage` label rather than four metrics: the
	// dashboard wants them stacked, and `sum by (le, stage)` only works if they
	// share a name.
	stageSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "zta_revocation_stage_seconds",
		Help:    "Latency of one stage of the revocation pipeline.",
		Buckets: metrics.Buckets,
	}, []string{"stage", "service"})

	// T6-T0: everything the code can see. Separate from the stage histogram
	// because summing the stages would exclude the gaps between them, and this
	// is reported as one distribution.
	pipelineSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "zta_revocation_pipeline_seconds",
		Help:    "End-to-end in-code revocation latency, T6-T0 (kernel policy match to the mesh patch committed).",
		Buckets: metrics.Buckets,
	})

	// The determinism denominator: every SET that reached the handler lands in
	// exactly one of these.
	eventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "zta_revocation_events_total",
		Help: "SETs received by the actuator, by outcome: revoked (actuated), deduped (subject already revoked), failed (malformed SET or a mesh patch that errored).",
	}, []string{"result"})
)

func init() {
	// Create the series at zero. Otherwise a trial with no dedupes has no
	// `deduped` series, and "the query returned nothing" is indistinguishable
	// from "nothing was deduped" — the trial-hygiene signal the dashboard exists
	// to show.
	for _, result := range []string{"revoked", "deduped", "failed"} {
		eventsTotal.WithLabelValues(result)
	}
}

// span is one measured interval, named by its `stage` label value.
type span struct {
	stage       string
	start, stop time.Time
}

// known reports whether both endpoints were recorded. A span bounded by a clock
// this process never received is dropped rather than observed: an unset time is
// the zero time, and a 56-year sample destroys every quantile over the
// histogram.
func (s span) known() bool { return !s.start.IsZero() && !s.stop.IsZero() }

func (s span) duration() time.Duration { return s.stop.Sub(s.start) }

// spanTable is the single source of truth for which pair of clocks bounds which
// span — both the log line (pipelineSpans) and the histograms (observeSpans)
// read it, so a transposed pair cannot make the two disagree.
func spanTable(t0, t1, t3, t4, t5, t6 time.Time) []span {
	return []span{
		{"detect", t0, t1},    // Tetragon -> translator delivery
		{"translate", t1, t3}, // resolve subject, mint SET
		{"transport", t3, t4}, // translator -> actuator hop
		{"actuate", t5, t6},   // API-server write
		{"pipeline", t0, t6},  // everything the code can see
	}
}

// observeSpans records one trial's timings. Call it only for events that
// actuated: a deduped event skips the API-server write, so its `actuate` span is
// a few microseconds of map lookup and would pull every percentile toward zero.
func observeSpans(t0, t1, t3, t4, t5, t6 time.Time) {
	for _, s := range spanTable(t0, t1, t3, t4, t5, t6) {
		if !s.known() {
			continue
		}
		if s.stage == "pipeline" {
			pipelineSeconds.Observe(s.duration().Seconds())
			continue
		}
		stageSeconds.WithLabelValues(s.stage, serviceLabel).Observe(s.duration().Seconds())
	}
}
