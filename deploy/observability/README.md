# deploy/observability

Prometheus and Grafana are a **prerequisite**, installed via the
kube-prometheus-stack Helm chart (86.2.0) — see [`docs/reproduce.md`](../../docs/reproduce.md)
§4 for the install. This directory holds only what this project adds.

| File | What it does |
|---|---|
| `podmonitor-workloads.yaml` | Scrapes `:9091/metrics` on actuator, translator, service-a — the revocation metrics (`cmd/actuator/metrics.go`) plus the Go/process collectors. |
| `podmonitor-istio-proxy.yaml` | Scrapes service-b's sidecar on `:15090/stats/prometheus` for `istio_requests_total` — the deny observed at the enforcement point rather than self-reported by the actuator. |
| `servicemonitor-istiod.yaml` | Scrapes istiod on `:15014/metrics` for `pilot_xds_pushes` and friends — T7, the config-push half of the `enforce` span. Lives in `istio-system`, not `zta-ssf`. |
| `dashboard-revocation.json` | The `ZTA Revocation` Grafana dashboard. Not a Kubernetes object — see below. |

```sh
make observability-apply     # monitors + dashboard
make observability-targets   # five targets, all 'up'
```

`kubectl apply -f deploy/observability/` fails on the directory as a whole —
`dashboard-revocation.json` is not a Kubernetes object. The Makefile applies
the YAML files individually.

## The dashboard

The JSON file is the source of truth; Grafana is downstream.
`make dashboard-apply` wraps it in a ConfigMap labelled `grafana_dashboard=1`,
which Grafana's sidecar (`LABEL=grafana_dashboard`, `NAMESPACE=ALL`)
provisions. The dashboard is version-controlled rather than living in
Grafana's SQLite, so **a panel edited in the Grafana UI is discarded on the
next apply** — export it back into the file first.

```sh
make grafana-open     # port-forward + print the admin password
make dashboard-diff   # does the cluster still match the file?
```

## Three ways this silently produces nothing

1. **Missing `release: prometheus`** on a PodMonitor — no error, just an
   empty graph (the Prometheus CR's `podMonitorSelector` requires it).
2. **STRICT mTLS on the scrape port** — Prometheus is outside the mesh, so
   its plaintext GET to pod-IP:9091 is reset by the sidecar. The three pod
   templates carry `traffic.sidecar.istio.io/excludeInboundPorts: "9091"`
   for this; a fourth scrape target would need the annotation too.
3. **An empty `METRICS_ADDR`** disables the listener entirely
   (`internal/metrics`) — only bites if a manifest sets it to `""`, since the
   binaries default to `:9091`.

## Confirm targets before trusting a panel

```sh
kubectl -n monitoring port-forward svc/prometheus-operated 19090:9090 &
curl -s 'http://localhost:19090/api/v1/targets?state=active' \
  | jq -r '.data.activeTargets[] | select(.scrapePool|test("zta|istio-proxy|istiod"))
           | "\(.scrapePool)\t\(.labels.pod)\t\(.health)\t\(.lastError)"'
```

Expect **five** targets, all `up`: actuator, translator, service-a,
service-b's istio-proxy, and istiod — three workload targets (not four:
`service-a-trial` has no `metrics` port) and exactly one istiod row
(two istiod Services carry `istio: pilot`; the monitor excludes the
`istio.io/tag` one so every `pilot_*` rate isn't doubled).

## A fourth way this produces a wrong number

Not an empty graph — a plausible-looking zero. `increase()` over
`zta_revocation_stage_seconds_*` silently returns 0 on a fresh
`HistogramVec` child (the series doesn't exist until first observation, so
there is no 0→1 rise to count). And since the actuator is deliberately not
restarted per trial, a bare lifetime total would over-count — every
per-trial panel uses a `max_over_time − min_over_time` delta instead.
