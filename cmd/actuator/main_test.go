package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Leaviss/ebpf-ssf-broker/internal/caep"

	"github.com/golang-jwt/jwt/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const (
	testNamespace  = "zta-ssf"
	testPolicyName = "revoked-identities"
)

// seededPolicy mirrors deploy/istio/authorization-policy-deny-revoked.yaml: the
// starting state the actuator's JSON patch appends to.
func seededPolicy() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.istio.io/v1",
		"kind":       "AuthorizationPolicy",
		"metadata": map[string]any{
			"name":      testPolicyName,
			"namespace": testNamespace,
		},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "service-b"}},
			"action":   "DENY",
			"rules": []any{map[string]any{
				"from": []any{map[string]any{
					"source": map[string]any{"principals": []any{
						"example.org/ns/zta-ssf/sa/placeholder-never-matches",
					}},
				}},
			}},
		},
	}}
}

// newFakeMesh returns a dynamic client holding the seeded policy plus any extra
// objects, standing in for the cluster so the handler can be exercised with no
// live Kubernetes. Pods are registered too because the handler's other action —
// removeSpireLabel — lists them.
func newFakeMesh(objects ...runtime.Object) dynamic.Interface {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			authzPolicyGVR: "AuthorizationPolicyList",
			podGVR:         "PodList",
		},
		append([]runtime.Object{seededPolicy()}, objects...)...,
	)
}

// principals reads the revoked set back off the policy in the fake cluster.
func principals(t *testing.T, client dynamic.Interface) []string {
	t.Helper()

	obj, err := client.Resource(authzPolicyGVR).Namespace(testNamespace).
		Get(context.Background(), testPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting policy: %v", err)
	}
	// The unstructured.Nested* helpers only walk maps, and the path crosses two
	// list indices, so dig by hand.
	rules, _, _ := unstructured.NestedSlice(obj.Object, "spec", "rules")
	from := rules[0].(map[string]any)["from"].([]any)
	source := from[0].(map[string]any)["source"].(map[string]any)

	var got []string
	for _, p := range source["principals"].([]any) {
		got = append(got, p.(string))
	}
	return got
}

// validSET mints an unsigned (alg:none) SET carrying the given subject URI, the
// same wire form the translator POSTs to /events.
func validSET(t *testing.T, subjectURI string) string {
	t.Helper()

	subject := caep.SubjectId{Format: "uri", URI: subjectURI}
	event := caep.CAEPEvent{EventTimeStampNs: 1_700_000_000_123_456_789, InitiatingEntity: "policy"}
	set := caep.NewSet("translator", "actuator", "jti-test", time.Unix(1_700_000_000, 0), subject, event)

	token, err := set.EncodeUnsigned()
	if err != nil {
		t.Fatalf("EncodeUnsigned() error = %v", err)
	}
	return token
}

func TestEventsHandlerAcceptsValidSET(t *testing.T) {
	const subjectURI = "spiffe://example.org/ns/zta-ssf/sa/service-a"
	body := validSET(t, subjectURI)

	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	client := newFakeMesh()
	eventsHandler(client, &sync.Map{}, testNamespace, testPolicyName)(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d; body = %q", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	// The SET's subject must land in the policy's revoked set, scheme stripped.
	want := "example.org/ns/zta-ssf/sa/service-a"
	got := principals(t, client)
	if len(got) != 2 || got[1] != want {
		t.Errorf("principals = %v, want the seed plus %q", got, want)
	}
}

// A Tetragon policy match fires once per process in the attacker's loop, so the
// same subject arrives repeatedly. Only the first should reach the API server —
// otherwise the principals list grows without bound over a trial run.
func TestEventsHandlerDedupesRepeatedSubject(t *testing.T) {
	const subjectURI = "spiffe://example.org/ns/zta-ssf/sa/service-a"

	client := newFakeMesh()
	handler := eventsHandler(client, &sync.Map{}, testNamespace, testPolicyName)

	for i := range 3 {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validSET(t, subjectURI)))
		rec := httptest.NewRecorder()

		handler(rec, req)

		// A deduped event is still accepted — it is a no-op, not a failure.
		if rec.Code != http.StatusAccepted {
			t.Fatalf("event %d: status = %d, want %d", i, rec.Code, http.StatusAccepted)
		}
	}

	if got := principals(t, client); len(got) != 2 {
		t.Errorf("principals = %v, want the seed plus one appended principal", got)
	}
}

// Distinct subjects are not deduped against each other.
func TestEventsHandlerAppendsDistinctSubjects(t *testing.T) {
	client := newFakeMesh()
	handler := eventsHandler(client, &sync.Map{}, testNamespace, testPolicyName)

	for _, subject := range []string{
		"spiffe://example.org/ns/zta-ssf/sa/service-a",
		"spiffe://example.org/ns/zta-ssf/sa/service-c",
	} {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validSET(t, subject)))
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status = %d, want %d", subject, rec.Code, http.StatusAccepted)
		}
	}

	if got := principals(t, client); len(got) != 3 {
		t.Errorf("principals = %v, want the seed plus two appended principals", got)
	}
}

// attrs turns pipelineSpans' flat key/value slice into a map for assertions.
func attrs(t *testing.T, kv []any) map[string]any {
	t.Helper()

	if len(kv)%2 != 0 {
		t.Fatalf("odd number of slog args: %d", len(kv))
	}
	got := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		got[kv[i].(string)] = kv[i+1]
	}
	return got
}

// The timing spans must come out as microseconds against
// the right pair of endpoints — a transposed pair here silently misattributes
// where the pipeline spends its time.
func TestPipelineSpans(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	at := func(us int) time.Time { return base.Add(time.Duration(us) * time.Microsecond) }

	// t0=0 t1=100 t3=250 t4=900 t5=1000 t6=4000
	got := attrs(t, pipelineSpans(at(0), at(100), at(250), at(900), at(1000), at(4000)))

	for key, want := range map[string]int64{
		"detect_us":    100,  // T1-T0
		"translate_us": 150,  // T3-T1
		"transport_us": 650,  // T4-T3
		"actuate_us":   3000, // T6-T5
		"pipeline_us":  4000, // T6-T0
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %d", key, got[key], want)
		}
	}
	if got["t0_ns"] != base.UnixNano() {
		t.Errorf("t0_ns = %v, want %d", got["t0_ns"], base.UnixNano())
	}
}

// A missing upstream clock must cost only the spans that depend on it. The
// failure this guards against is a zero time being treated as 1970, which turns
// every derived span into a plausible-looking 56-year number.
func TestPipelineSpansOmitsUnknownClocks(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	t4 := base.Add(900 * time.Microsecond)
	t5 := base.Add(time.Millisecond)
	t6 := base.Add(4 * time.Millisecond)

	// No T0/T1/T3: a SET with no event timestamp and no timing headers.
	got := attrs(t, pipelineSpans(time.Time{}, time.Time{}, time.Time{}, t4, t5, t6))

	for _, key := range []string{"t0_ns", "t1_ns", "t3_ns", "detect_us", "translate_us", "transport_us", "pipeline_us"} {
		if _, ok := got[key]; ok {
			t.Errorf("%s = %v, want it omitted when its endpoints are unknown", key, got[key])
		}
	}
	// actuate is entirely actuator-side, so it survives.
	if got["actuate_us"] != int64(3000) {
		t.Errorf("actuate_us = %v, want 3000", got["actuate_us"])
	}
}

func TestHeaderTime(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Time
	}{
		{"nanosecond stamp", "1700000000123456789", time.Unix(0, 1_700_000_000_123_456_789)},
		{"absent", "", time.Time{}},
		{"not a number", "not-a-number", time.Time{}},
		{"zero means unset", "0", time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.value != "" {
				h.Set(headerT1, tt.value)
			}
			if got := headerTime(h, headerT1); !got.Equal(tt.want) {
				t.Errorf("headerTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The end the translator's headers are a means to: the actuator's own log line
// carries the full stage breakdown, which is what the per-trial CSV is built
// from (scripts/trial_record.py) and what the stage metric reads (metrics.go).
func TestEventsHandlerLogsPipelineSpans(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	t1 := time.Unix(1_700_000_000, 200_000_000) // 200ms after the SET's T0
	t3 := t1.Add(3 * time.Millisecond)

	req := httptest.NewRequest(http.MethodPost, "/events",
		strings.NewReader(validSET(t, "spiffe://example.org/ns/zta-ssf/sa/service-a")))
	req.Header.Set(headerT1, strconv.FormatInt(t1.UnixNano(), 10))
	req.Header.Set(headerT3, strconv.FormatInt(t3.UnixNano(), 10))
	rec := httptest.NewRecorder()

	eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}

	logged := buf.String()
	for _, want := range []string{
		"t0_ns=1700000000123456789",
		"detect_us=76543",   // t1 - T0
		"translate_us=3000", // t3 - t1
		"result=revoked",
		"jti=jti-test",
		"transport_us=",
		"actuate_us=",
		"pipeline_us=",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q\ngot: %s", want, logged)
		}
	}
}

func TestEventsHandlerRejectsNonPost(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/events", nil)
			rec := httptest.NewRecorder()

			eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
			}
			if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
				t.Errorf("Allow header = %q, want %q", allow, http.MethodPost)
			}
		})
	}
}

func TestEventsHandlerRejectsMalformedBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"not a jwt", "not-a-jwt"},
		{"two segments", "aaa.bbb"},
		{"garbage payload", "aaa.bbb.ccc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

// A signed SET (alg != none) must be rejected: the actuator decodes via
// caep.DecodeUnsigned, which only accepts alg:none — SETs are unsigned in this
// lab (README, "Lab-only caveats").
func TestEventsHandlerRejectsSignedSET(t *testing.T) {
	subject := caep.SubjectId{Format: "uri", URI: "spiffe://example.org/ns/zta-ssf/sa/service-a"}
	event := caep.CAEPEvent{EventTimeStampNs: 1_700_000_000_123_456_789, InitiatingEntity: "policy"}
	claims := caep.NewSet("translator", "actuator", "jti-signed", time.Unix(1_700_000_000, 0), subject, event)

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("signing HS256 token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(signed))
	rec := httptest.NewRecorder()

	eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// End-to-end over the registered mux, exercising the /events route wiring the
// same way the translator's POST hits it.
func TestEventsRouteViaServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", eventsHandler(newFakeMesh(), &sync.Map{}, testNamespace, testPolicyName))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := validSET(t, "spiffe://example.org/ns/zta-ssf/sa/service-a")
	resp, err := http.Post(srv.URL+"/events", "application/secevent+jwt", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /events error = %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
}

// The property the reset endpoint has to provide, in place of restarting the
// actuator: after a reset, a repeat trial on the same subject actuates again
// instead of being silently deduped. If this breaks, every trial after the first
// in a run reports `deduped` and contributes no latency sample.
func TestResetDedupeAllowsRepeatTrialOnSameSubject(t *testing.T) {
	const subjectURI = "spiffe://example.org/ns/zta-ssf/sa/service-a"

	revoked := &sync.Map{}
	client := newFakeMesh()
	handler := eventsHandler(client, revoked, testNamespace, testPolicyName)

	fire := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(validSET(t, subjectURI)))
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
		}
	}

	fire() // trial 1 — actuates
	fire() // same subject, same trial — deduped
	if got := principals(t, client); len(got) != 2 {
		t.Fatalf("before reset: principals = %v, want the seed plus one", got)
	}

	rec := httptest.NewRecorder()
	resetDedupeHandler(revoked)(rec, httptest.NewRequest(http.MethodPost, resetDedupePath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("reset status = %d, want %d", rec.Code, http.StatusOK)
	}

	fire() // trial 2 — the same subject must actuate again
	if got := principals(t, client); len(got) != 3 {
		t.Errorf("after reset: principals = %v, want a second append for the repeat trial", got)
	}
}

// GET must not clear the set: the endpoint shares a listener with /metrics, and
// a reset triggered by a stray scrape would surface as a phantom re-append
// mid-trial rather than as an error.
func TestResetDedupeRejectsNonPost(t *testing.T) {
	revoked := &sync.Map{}
	revoked.Store("ns/zta-ssf/sa/service-a", struct{}{})

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		rec := httptest.NewRecorder()
		resetDedupeHandler(revoked)(rec, httptest.NewRequest(method, resetDedupePath, nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
		if _, ok := revoked.Load("ns/zta-ssf/sa/service-a"); !ok {
			t.Errorf("%s cleared the dedupe set", method)
		}
	}
}
