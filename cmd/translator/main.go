package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Leaviss/ebpf-ssf-broker/internal/caep"
	"github.com/Leaviss/ebpf-ssf-broker/internal/metrics"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Timing headers on the POST to the actuator. T0 rides inside the SET as a
// genuine CAEP event property; T1 and T3 are measurement-only, so they travel as
// transport metadata instead. Carrying them lets the actuator compute every
// pipeline span in one process.
const (
	headerT1 = "X-Zta-T1-Ns"
	headerT3 = "X-Zta-T3-Ns"
)

func main() {
	// Spans are sub-second; slog's default whole-second local stamps will not
	// join with the other logs. RFC3339Nano, UTC — same
	// handler as cmd/service-a.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	})))

	slog.Info("Translator entry point.")

	// No metrics of its own: the actuator computes every span, so observing
	// `detect`/`translate` here too would double-count under `sum by (stage)`.
	// The endpoint is still worth scraping for process_start_time_seconds, which
	// makes a mid-trial translator restart visible rather than inferred from a
	// gap in events.
	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = ":9091"
	}
	metrics.Serve(metricsAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	addr := os.Getenv("TETRAGON_GRPC_ADDR")
	if addr == "" {
		addr = "localhost:54321"
	}

	actuatorURL := os.Getenv("ACTUATOR_URL")
	if actuatorURL == "" {
		actuatorURL = "http://actuator.zta-ssf.svc.cluster.local:9090/events"
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("Invalid Tetragon gRPC target", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	slog.Info("Tetragon gRPC client created (not yet connected)", "addr", addr)

	for ctx.Err() == nil {
		stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			slog.Error("Failed to open GetEvents stream", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		slog.Info("GetEvents stream opened, waiting for events...")

		for {
			res, err := stream.Recv()
			// T1 — event off the wire. Taken before any error handling so the
			// `detect` span (T1-T0) is not inflated by this loop's own work.
			recv := time.Now()
			if err == io.EOF {
				slog.Info("Tetragon event stream closed (EOF), reconnecting...")
				break
			}
			if err != nil {
				slog.Error("Error receiving event, reconnecting...", "error", err)
				break
			}

			switch event := res.Event.(type) {
			case *tetragon.GetEventsResponse_ProcessKprobe:
				kp := event.ProcessKprobe
				// Process (and downstream Process.Pod, which SPIFFE-ID
				// construction needs) is nil-able — guard before deref.
				if kp == nil || kp.Process == nil {
					continue
				}
				// T0 — the kernel policy match, stamped by Tetragon. Falls back
				// to the receive time when the event carries no stamp, which
				// costs the `detect` span rather than the whole trial.
				t0 := recv
				if ts := res.GetTime(); ts != nil {
					t0 = ts.AsTime()
				}

				slog.Info("Received ProcessKprobe event",
					"binary", kp.Process.Binary,
					"function", kp.FunctionName,
					"t0_ns", t0.UnixNano(),
					"detect_us", recv.Sub(t0).Microseconds(),
				)

				finalSet, err := buildSet(kp, t0, time.Now(), uuid.NewString())
				if err != nil {
					slog.Warn("Skipping event without pod attribution", "error", err)
					continue
				}

				token, err := finalSet.EncodeUnsigned()
				if err != nil {
					slog.Error("Failed to encode SET as unsigned JWT", "error", err)
					continue
				}
				// T2 — SET minted and encoded.
				t2 := time.Now()
				slog.Info("Minted CAEP SET",
					"jti", finalSet.ID,
					"sub", finalSet.SubId.URI,
					"jwt", token,
				)

				// T3 comes back from postSet: it is stamped immediately before the
				// request goes on the wire, so the `transport` span the actuator
				// computes excludes this process's own request-building.
				t3, err := postSet(ctx, httpClient, actuatorURL, token, recv)
				if err != nil {
					slog.Error("Failed to POST SET to actuator",
						"error", err,
						"url", actuatorURL,
						"jti", finalSet.ID,
					)
					continue
				}
				slog.Info("POSTed SET to actuator",
					"jti", finalSet.ID,
					"url", actuatorURL,
					"t0_ns", t0.UnixNano(),
					"t1_ns", recv.UnixNano(),
					"t2_ns", t2.UnixNano(),
					"t3_ns", t3.UnixNano(),
					"detect_us", recv.Sub(t0).Microseconds(),
					"mint_us", t2.Sub(recv).Microseconds(),
					"translate_us", t3.Sub(recv).Microseconds(),
				)
			default:
				// Handle or ignore other event types
			}
		}

		// Small backoff before attempting to reconnect
		time.Sleep(2 * time.Second)
	}
}

// buildSet transforms a Tetragon ProcessKprobe into a CAEP SET. It is pure — no
// gRPC or HTTP — so it can be unit-tested against captured fixtures with no live
// cluster. The subject comes from the naming convention
// spiffe://<trust-domain>/ns/<namespace>/sa/<workload> (docs/architecture.md).
//
// t0 (the kernel policy match, and the measurement origin carried in the SET)
// and iat (the mint time) are injected separately on purpose: using the mint
// time for both folds the detect and translate spans to zero.
func buildSet(kp *tetragon.ProcessKprobe, t0, iat time.Time, jti string) (caep.SetClaims, error) {
	if kp == nil || kp.Process == nil || kp.Process.Pod == nil {
		return caep.SetClaims{}, fmt.Errorf("event missing process/pod attribution")
	}

	namespace := kp.Process.Pod.Namespace
	workload := kp.Process.Pod.PodLabels["app"]

	subject := caep.SubjectId{
		Format: "uri",
		URI:    fmt.Sprintf("spiffe://example.org/ns/%s/sa/%s", namespace, workload),
	}
	event := caep.CAEPEvent{
		EventTimeStampNs: t0.UnixNano(),
		InitiatingEntity: "policy",
	}
	return caep.NewSet("translator", "actuator", jti, iat, subject, event), nil
}

// postSet pushes an encoded SET to the actuator's RFC 8935 receiver as a compact
// JWT with the RFC 8936 media type; the actuator answers 202 on success.
//
// t1, the stream-receive clock, is forwarded as a header so the actuator can
// compute `detect` and `translate` itself. The returned time is T3, taken as
// late as possible before the request reaches the transport.
func postSet(ctx context.Context, client *http.Client, url, token string, t1 time.Time) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(token))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set(headerT1, strconv.FormatInt(t1.UnixNano(), 10))

	// T3 — request on the wire.
	t3 := time.Now()
	req.Header.Set(headerT3, strconv.FormatInt(t3.UnixNano(), 10))

	resp, err := client.Do(req)
	if err != nil {
		return t3, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		return t3, fmt.Errorf("actuator returned %s", resp.Status)
	}
	return t3, nil
}
