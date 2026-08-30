package metrics

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The endpoint is the whole deliverable of the metric spec, and
// nothing downstream fails loudly if it is not up — a dead listener shows as an
// empty Grafana panel, which looks the same as a trial where nothing happened.
func TestServeExposesMetrics(t *testing.T) {
	// Port 0 so the test never collides with a real :9091.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	Serve(addr)

	// Serve returns before the listener is up; poll rather than sleep.
	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	// The default registry's process collector: this is what makes the
	// translator's otherwise metric-less endpoint worth scraping.
	if !strings.Contains(string(body), "process_start_time_seconds") {
		t.Errorf("/metrics is missing the default collectors\ngot: %s", body)
	}
}

// An empty addr must be a no-op rather than a listener on :80 — it is how unit
// tests and local `go run` opt out.
func TestServeDisabledOnEmptyAddr(t *testing.T) {
	Serve("")
}

// The default client_golang buckets start at 5ms, which would put the entire
// in-code pipeline in the first two buckets.
func TestBucketsResolveSubMillisecond(t *testing.T) {
	if Buckets[0] >= 0.001 {
		t.Errorf("first bucket bound = %v, want something below 1ms", Buckets[0])
	}
	for i := 1; i < len(Buckets); i++ {
		if Buckets[i] <= Buckets[i-1] {
			t.Fatalf("buckets must be strictly increasing: %v at index %d", Buckets, i)
		}
	}
}

// The regression this guards made every quantile panel wrong on an early run:
// the observed pipeline distribution (11.8-25.6ms) fell entirely inside a single
// 10ms-25ms bucket, so histogram_quantile reported a p95 of 42.1ms against a
// true maximum of 25.6ms. Boundaries have to be dense
// enough across the range actually being measured for interpolation to mean
// anything — see Buckets for the measured stage/pipeline figures they came from.
func TestBucketsResolveThePipelineRange(t *testing.T) {
	const lo, hi = 0.008, 0.030 // the measured pipeline range, with headroom

	var inRange []float64
	for _, b := range Buckets {
		if b >= lo && b <= hi {
			inRange = append(inRange, b)
		}
	}

	if len(inRange) < 6 {
		t.Errorf("only %d bucket boundaries in [%v, %v]: %v\n"+
			"too coarse to resolve a p50/p95 over the measured pipeline range", len(inRange), lo, hi, inRange)
	}
	for i := 1; i < len(inRange); i++ {
		if w := inRange[i] - inRange[i-1]; w > 0.005+1e-9 {
			t.Errorf("bucket %v-%v is %.1fms wide; a quantile landing in it interpolates across too much",
				inRange[i-1], inRange[i], w*1000)
		}
	}
}

// Serve's extra routes are how the actuator's dedupe reset reaches the one port
// that is already outside the mesh. A route that silently fails to mount would
// make `make trial-reset` a no-op and every trial after the first dedupe.
func TestServeMountsExtraRoutes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	var called bool
	Serve(addr, Route{
		Pattern: "/admin/test",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
	})

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = http.Post("http://"+addr+"/admin/test", "", nil)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("POST /admin/test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || !called {
		t.Errorf("status = %d, handler called = %v; want 200 and true", resp.StatusCode, called)
	}

	// Mounting a route must not displace the scrape endpoint.
	m, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer m.Body.Close()
	if m.StatusCode != http.StatusOK {
		t.Errorf("/metrics status = %d, want %d", m.StatusCode, http.StatusOK)
	}
}
