package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/encoding/protojson"
)

// loadFixture reads a captured Tetragon event (protojson) from test/fixtures and
// returns its ProcessKprobe plus T0, the response's own timestamp. These are the
// same JSON files the live translator consumes off the gRPC stream, so buildSet
// can be exercised with no cluster.
func loadFixture(t *testing.T, name string) (*tetragon.ProcessKprobe, time.Time) {
	t.Helper()

	path := filepath.Join("..", "..", "test", "fixtures", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}

	var res tetragon.GetEventsResponse
	if err := protojson.Unmarshal(raw, &res); err != nil {
		t.Fatalf("unmarshaling fixture %s: %v", name, err)
	}

	kp := res.GetProcessKprobe()
	if kp == nil {
		t.Fatalf("fixture %s has no process_kprobe event", name)
	}
	if res.GetTime() == nil {
		t.Fatalf("fixture %s has no event timestamp — it cannot carry T0", name)
	}
	return kp, res.GetTime().AsTime()
}

// All three scenario fixtures are Service A compromise signals, so each must
// resolve to the same Service A identity regardless of which hook fired.
const wantSubjectURI = "spiffe://example.org/ns/zta-ssf/sa/service-a"

func TestBuildSetFromFixtures(t *testing.T) {
	// Deliberately not the fixtures' own timestamp: iat is the mint clock, T0 is
	// the kernel's, and the SET must keep them apart.
	iat := time.Unix(1_700_000_000, 0)
	const jti = "jti-fixture"

	fixtures := []string{
		"exec-wget.json",
		"egress-c2-callback.json",
		"token-read-sa-token.json",
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			kp, t0 := loadFixture(t, name)

			set, err := buildSet(kp, t0, iat, jti)
			if err != nil {
				t.Fatalf("buildSet() error = %v", err)
			}

			if set.SubId.Format != "uri" {
				t.Errorf("SubId.Format = %q, want %q", set.SubId.Format, "uri")
			}
			if set.SubId.URI != wantSubjectURI {
				t.Errorf("SubId.URI = %q, want %q", set.SubId.URI, wantSubjectURI)
			}
			if set.Issuer != "translator" {
				t.Errorf("Issuer = %q, want %q", set.Issuer, "translator")
			}
			if len(set.Audience) != 1 || set.Audience[0] != "actuator" {
				t.Errorf("Audience = %v, want [actuator]", set.Audience)
			}
			if set.ID != jti {
				t.Errorf("ID = %q, want %q", set.ID, jti)
			}
			if set.IssuedAt == nil || !set.IssuedAt.Time.Equal(iat) {
				t.Errorf("IssuedAt = %v, want %v", set.IssuedAt, iat)
			}
			// T0 must be the kernel's stamp at full nanosecond precision, not
			// the mint clock and not truncated to seconds — the measurement
			// origin the actuator computes every span against.
			if set.Events.EventTimeStampNs != t0.UnixNano() {
				t.Errorf("Events.EventTimeStampNs = %d, want %d (Tetragon's T0)", set.Events.EventTimeStampNs, t0.UnixNano())
			}
			if set.Events.EventTimeStampNs%int64(time.Second) == 0 {
				t.Errorf("Events.EventTimeStampNs = %d has no sub-second component; fixture T0 was truncated", set.Events.EventTimeStampNs)
			}
			if set.Events.InitiatingEntity != "policy" {
				t.Errorf("Events.InitiatingEntity = %q, want %q", set.Events.InitiatingEntity, "policy")
			}
		})
	}
}

// The SPIFFE ID is ServiceAccount-based and must come from the `app` pod label
// (= "service-a"), not process.pod.workload (= "service-a-trial", the Deployment
// name), which does not equal the SA (test/fixtures/README.md caveat 2).
func TestBuildSetResolvesFromAppLabelNotWorkload(t *testing.T) {
	kp, t0 := loadFixture(t, "exec-wget.json")

	if got := kp.Process.Pod.Workload; got != "service-a-trial" {
		t.Fatalf("fixture precondition: workload = %q, want %q", got, "service-a-trial")
	}

	set, err := buildSet(kp, t0, time.Unix(1_700_000_000, 0), "jti")
	if err != nil {
		t.Fatalf("buildSet() error = %v", err)
	}

	if set.SubId.URI != wantSubjectURI {
		t.Errorf("SubId.URI = %q, want %q (must derive from app label, not workload)", set.SubId.URI, wantSubjectURI)
	}
}

// Egress emits two events per callback — the app's own connect and Envoy's
// upstream connect — carrying identical pod metadata (README caveat 3). Both
// must resolve to the same identity so the pipeline can dedupe per identity.
func TestBuildSetSameIdentityAcrossBinaries(t *testing.T) {
	iat := time.Unix(1_700_000_000, 0)

	appOrigin, t0 := loadFixture(t, "egress-c2-callback.json")
	envoyOrigin, _ := loadFixture(t, "egress-c2-callback.json")
	envoyOrigin.Process.Binary = "/usr/local/bin/envoy"

	appSet, err := buildSet(appOrigin, t0, iat, "jti-app")
	if err != nil {
		t.Fatalf("buildSet(appOrigin) error = %v", err)
	}
	envoySet, err := buildSet(envoyOrigin, t0, iat, "jti-envoy")
	if err != nil {
		t.Fatalf("buildSet(envoyOrigin) error = %v", err)
	}

	if appSet.SubId != envoySet.SubId {
		t.Errorf("subject differs across binaries: app=%+v envoy=%+v", appSet.SubId, envoySet.SubId)
	}
}

// buildSet must be deterministic: same event in, same subject out.
func TestBuildSetDeterministic(t *testing.T) {
	iat := time.Unix(1_700_000_000, 0)
	kp, t0 := loadFixture(t, "token-read-sa-token.json")

	first, err := buildSet(kp, t0, iat, "jti")
	if err != nil {
		t.Fatalf("buildSet() error = %v", err)
	}
	second, err := buildSet(kp, t0, iat, "jti")
	if err != nil {
		t.Fatalf("buildSet() error = %v", err)
	}

	if first.SubId != second.SubId {
		t.Errorf("non-deterministic subject: first=%+v second=%+v", first.SubId, second.SubId)
	}
}

// postSet must forward T1 and stamp T3 as late as it can, because the actuator
// computes `translate` and `transport` from them.
// A T3 taken before the request is built would charge request construction to
// the network hop.
func TestPostSetCarriesTimingHeaders(t *testing.T) {
	var gotT1, gotT3 string
	var serverAt time.Time

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverAt = time.Now()
		gotT1, gotT3 = r.Header.Get(headerT1), r.Header.Get(headerT3)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	t1 := time.Now()
	t3, err := postSet(context.Background(), srv.Client(), srv.URL, "token", t1)
	if err != nil {
		t.Fatalf("postSet() error = %v", err)
	}

	if got, err := strconv.ParseInt(gotT1, 10, 64); err != nil || got != t1.UnixNano() {
		t.Errorf("%s = %q, want %d", headerT1, gotT1, t1.UnixNano())
	}
	if got, err := strconv.ParseInt(gotT3, 10, 64); err != nil || got != t3.UnixNano() {
		t.Errorf("%s = %q, want the returned T3 %d", headerT3, gotT3, t3.UnixNano())
	}

	// T3 must sit between the caller's T1 and the moment the server saw the
	// request — i.e. inside the hop it is supposed to bound.
	if t3.Before(t1) || t3.After(serverAt) {
		t.Errorf("T3 = %v, want it within [T1 %v, server receipt %v]", t3, t1, serverAt)
	}
}

// A failed POST still returns the T3 it stamped: the request left this process,
// so the sample is real even though the trial failed.
func TestPostSetReturnsT3OnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	t3, err := postSet(context.Background(), srv.Client(), srv.URL, "token", time.Now())
	if err == nil {
		t.Fatal("postSet() = nil error, want an error for a non-202 response")
	}
	if t3.IsZero() {
		t.Error("T3 is the zero time; want the stamp taken before the request went out")
	}
}

// An exec performed directly by `kubectl exec` lands with an empty pod object and
// cannot be resolved to a SPIFFE ID; buildSet must return an error rather than
// crash or mint an SVID for an unattributed workload (README caveat 1).
func TestBuildSetMissingAttribution(t *testing.T) {
	tests := []struct {
		name string
		kp   *tetragon.ProcessKprobe
	}{
		{
			name: "nil kprobe",
			kp:   nil,
		},
		{
			name: "nil process",
			kp:   &tetragon.ProcessKprobe{Process: nil},
		},
		{
			name: "nil pod (kubectl exec / runc, no pod attribution)",
			kp:   &tetragon.ProcessKprobe{Process: &tetragon.Process{Binary: "/bin/wget"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t0 := time.Unix(1_699_999_999, 500_000_000)
			if _, err := buildSet(tt.kp, t0, time.Unix(1_700_000_000, 0), "jti"); err == nil {
				t.Error("buildSet() = nil error, want error for unresolvable event")
			}
		})
	}
}
