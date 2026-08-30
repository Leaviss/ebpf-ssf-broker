package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// The metrics are package-level and shared across tests in this package, so
// every assertion here is a delta rather than an absolute — otherwise the result
// depends on test ordering.

func eventCount(t *testing.T, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(eventsTotal.WithLabelValues(result))
}

// samples returns the number of observations in a histogram, which is what these
// tests care about — CollectAndCount would return the number of series.
func samples(t *testing.T, m prometheus.Metric) uint64 {
	t.Helper()

	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("writing metric: %v", err)
	}
	return out.GetHistogram().GetSampleCount()
}

func stageSamples(t *testing.T, stage string) uint64 {
	t.Helper()

	m, err := stageSeconds.GetMetricWithLabelValues(stage, serviceLabel)
	if err != nil {
		t.Fatalf("getting stage %q: %v", stage, err)
	}
	return samples(t, m.(prometheus.Metric))
}

// post drives one SET through the handler and returns the response recorder.
func post(t *testing.T, handler http.HandlerFunc, subjectURI string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validSET(t, subjectURI)))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// zta_revocation_events_total is the denominator for the "did it revoke, every
// time?" claim, so each of the three outcomes has to land in
// its own bucket.
func TestEventsHandlerCountsResults(t *testing.T) {
	const subjectURI = "spiffe://example.org/ns/zta-ssf/sa/metrics-results"

	before := map[string]float64{}
	for _, r := range []string{"revoked", "deduped", "failed"} {
		before[r] = eventCount(t, r)
	}

	handler := eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)

	// First event actuates; the second is the same subject, so it dedupes.
	post(t, handler, subjectURI)
	post(t, handler, subjectURI)

	// A body that is not a SET at all cannot yield a subject, so it counts as a
	// failure rather than vanishing from the accounting.
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader("not-a-jwt"))
	handler(httptest.NewRecorder(), req)

	for result, want := range map[string]float64{"revoked": 1, "deduped": 1, "failed": 1} {
		if got := eventCount(t, result) - before[result]; got != want {
			t.Errorf("zta_revocation_events_total{result=%q} rose by %v, want %v", result, got, want)
		}
	}
}

// A mesh patch that errors is a revocation that did not happen — the one outcome
// a success-rate figure must not miss.
func TestEventsHandlerCountsFailedPatch(t *testing.T) {
	before := eventCount(t, "failed")

	client := newFakeMesh()
	client.(*dynamicfake.FakeDynamicClient).PrependReactor("patch", "authorizationpolicies",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api server said no")
		})

	rec := post(t, eventsHandler(client, &sync.Map{}, testNamespace, testPolicyName),
		"spiffe://example.org/ns/zta-ssf/sa/metrics-failed")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := eventCount(t, "failed") - before; got != 1 {
		t.Errorf("zta_revocation_events_total{result=\"failed\"} rose by %v, want 1", got)
	}
}

// A deduped event skips the API-server write, so its `actuate` span is a map
// lookup. Observing it would drag every reported percentile toward zero — the
// histograms must only ever see events that actually actuated.
func TestDedupedEventIsNotALatencySample(t *testing.T) {
	const subjectURI = "spiffe://example.org/ns/zta-ssf/sa/metrics-dedupe"

	before := samples(t, pipelineSeconds)
	beforeActuate := stageSamples(t, "actuate")

	handler := eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)
	for range 3 {
		if rec := post(t, handler, subjectURI); rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
		}
	}

	if got := samples(t, pipelineSeconds) - before; got != 1 {
		t.Errorf("zta_revocation_pipeline_seconds took %d samples from 3 events, want 1", got)
	}
	if got := stageSamples(t, "actuate") - beforeActuate; got != 1 {
		t.Errorf("zta_revocation_stage_seconds{stage=\"actuate\"} took %d samples from 3 events, want 1", got)
	}
}

// The same guard as TestPipelineSpansOmitsUnknownClocks, one layer down: a span
// bounded by a clock this process never received must not reach the histogram,
// where an unset time read as 1970 becomes a 56-year sample in the +Inf bucket
// and every quantile computed over it is wrong.
func TestObserveSpansSkipsUnknownClocks(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	t4 := base.Add(900 * time.Microsecond)
	t5 := base.Add(time.Millisecond)
	t6 := base.Add(4 * time.Millisecond)

	before := map[string]uint64{}
	for _, stage := range []string{"detect", "translate", "transport", "actuate"} {
		before[stage] = stageSamples(t, stage)
	}
	beforePipeline := samples(t, pipelineSeconds)

	// No T0/T1/T3: a SET with no event timestamp and no timing headers.
	observeSpans(time.Time{}, time.Time{}, time.Time{}, t4, t5, t6)

	for _, stage := range []string{"detect", "translate", "transport"} {
		if got := stageSamples(t, stage) - before[stage]; got != 0 {
			t.Errorf("stage %q took %d samples with its endpoints unknown, want 0", stage, got)
		}
	}
	if got := samples(t, pipelineSeconds) - beforePipeline; got != 0 {
		t.Errorf("pipeline took %d samples with T0 unknown, want 0", got)
	}
	// actuate is entirely actuator-side, so it survives.
	if got := stageSamples(t, "actuate") - before["actuate"]; got != 1 {
		t.Errorf("stage \"actuate\" took %d samples, want 1", got)
	}
}

// The bucket boundaries are load-bearing (internal/metrics/metrics.go): with
// client_golang's defaults the whole pipeline lands in the first two buckets and
// histogram_quantile interpolates across an order of magnitude.
func TestPipelineHistogramResolvesSubMillisecond(t *testing.T) {
	var out dto.Metric
	if err := pipelineSeconds.(prometheus.Metric).Write(&out); err != nil {
		t.Fatalf("writing metric: %v", err)
	}

	var belowMilli int
	for _, b := range out.GetHistogram().GetBucket() {
		if b.GetUpperBound() < 0.001 {
			belowMilli++
		}
	}
	if belowMilli == 0 {
		t.Errorf("no bucket boundary below 1ms; sub-millisecond spans would be unresolvable")
	}
}
