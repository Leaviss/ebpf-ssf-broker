package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Leaviss/ebpf-ssf-broker/internal/metrics"
)

// Steady-state cadence. Trials override it via PROBE_INTERVAL: "first request
// denied" (T8) is quantised to this interval, so at 1s the measurement error
// dwarfs the pipeline being measured. Run trials at 10-50ms.
const defaultInterval = 1 * time.Second

func main() {
	// T8 is joined offline against Tetragon's UTC nanosecond timestamps
	// (scripts/trial_record.py). slog's default text time is millisecond
	// resolution and local; neither survives that join.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	})))

	target := os.Getenv("TARGET_URL")
	if target == "" {
		target = "https://service-b:8080/"
	}

	interval := defaultInterval
	if raw := os.Getenv("PROBE_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		switch {
		case err != nil:
			slog.Error("Invalid PROBE_INTERVAL, using default", "value", raw, "error", err, "interval", interval)
		case d <= 0:
			slog.Error("PROBE_INTERVAL must be positive, using default", "value", raw, "interval", interval)
		default:
			interval = d
		}
	}

	// Its own port, so the probe loop's target port and the scrape port stay
	// separate concerns.
	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = ":9091"
	}
	metrics.Serve(metricsAddr)

	client := &http.Client{Timeout: 5 * time.Second}

	slog.Info("Prober up", "target", target, "interval", interval)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		call(client, target)
		<-tick.C
	}
}

func call(client *http.Client, target string) {
	start := time.Now()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		slog.Error("request", "error", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		probeRequests.WithLabelValues("error").Inc()
		slog.Error("do", "error", err)
		return
	}
	defer resp.Body.Close()

	// Counted off the status line, before the body read: the deny is the status,
	// and a read failure must not lose the sample marking the transition.
	probeRequests.WithLabelValues(strconv.Itoa(resp.StatusCode)).Inc()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("read", "error", err)
		return
	}

	slog.Info("recv", "status", resp.StatusCode, "body", string(body), "rtt_us", time.Since(start).Microseconds())
}
