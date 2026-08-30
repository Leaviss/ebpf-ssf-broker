SHELL := /bin/bash
BIN   := bin
PKGS  := ./...

NAMESPACE ?= zta-ssf
KUBECTL   ?= kubectl
HELM      ?= helm
DOCKER    ?= docker
IMAGE_TAG ?= dev

# Grafana lives in the kube-prometheus-stack release, not in this repo.
MONITORING_NS ?= monitoring
DASHBOARD_CM  ?= zta-revocation-dashboard
DASHBOARD_JSON = deploy/observability/dashboard-revocation.json

CMDS := service-a service-b translator actuator

.PHONY: all build images test vet fmt tidy clean \
        lab-up lab-down \
        tetragon-apply tetragon-delete \
        workloads-apply workloads-delete \
        observability-apply observability-delete observability-targets \
        dashboard-apply dashboard-delete dashboard-diff grafana-open \
        trial-reset trial-verify trial-run trial-smoke actuator-reset

all: build

build: $(addprefix build-,$(CMDS))

build-%:
	@mkdir -p $(BIN)
	go build -o $(BIN)/$* ./cmd/$*

images: $(addprefix image-,$(CMDS))

image-%:
	$(DOCKER) build --build-arg SERVICE=$* -t $*:$(IMAGE_TAG) .

test:
	go test $(PKGS)

vet:
	go vet $(PKGS)

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

clean:
	rm -rf $(BIN)

# --- cluster ---

# Stand up the whole lab on the current kubectl context: SPIRE, Istio,
# Tetragon, Prometheus, images, workloads, policies, scrape targets — the
# pinned versions from docs/reproduce.md, end state ready for docs/demo.md.
lab-up:
	@scripts/lab-up.sh

# Tear the whole lab down, reverse install order — the same commands as
# docs/reproduce.md §7 (see there for what is lost, and for the CRD cleanup
# on a truly empty cluster). `-` prefixes: keep going through a partially
# built lab. Does not touch locally recorded trial CSVs or raw logs.
lab-down:
	-@$(MAKE) --no-print-directory workloads-delete
	-istioctl uninstall -y --purge
	-$(KUBECTL) delete ns istio-system --ignore-not-found
	-$(HELM) uninstall tetragon -n tetragon-system
	-$(KUBECTL) delete ns tetragon-system --ignore-not-found
	-$(HELM) uninstall prometheus -n $(MONITORING_NS)
	-$(KUBECTL) delete ns $(MONITORING_NS) --ignore-not-found
	-$(HELM) uninstall spire -n spire-system
	-$(KUBECTL) delete ns spire-system --ignore-not-found

tetragon-apply:
	$(KUBECTL) apply -f deploy/tetragon/

tetragon-delete:
	$(KUBECTL) delete -f deploy/tetragon/ --ignore-not-found

workloads-apply:
	$(KUBECTL) apply -f deploy/workloads/

workloads-delete:
	$(KUBECTL) delete -f deploy/workloads/ --ignore-not-found

# -f per file rather than -f on the directory: dashboard-revocation.json lives
# here too and is not a Kubernetes object, so `apply -f deploy/observability/`
# fails validation on it.
OBSERVABILITY_YAML = $(wildcard deploy/observability/*.yaml)

observability-apply: dashboard-apply
	$(KUBECTL) apply $(addprefix -f ,$(OBSERVABILITY_YAML))

observability-delete: dashboard-delete
	$(KUBECTL) delete $(addprefix -f ,$(OBSERVABILITY_YAML)) --ignore-not-found

# The dashboard is a JSON file in this repo, not a Grafana-side object. Grafana's
# sidecar (LABEL=grafana_dashboard, LABEL_VALUE=1, NAMESPACE=ALL) watches for
# ConfigMaps carrying that label and provisions what it finds, so the repo stays
# the source of truth and an edit in the Grafana UI is discarded on the next
# apply. Export from the UI back into the file before re-applying if you tuned a
# panel there (deploy/observability/README.md).
dashboard-apply:
	$(KUBECTL) -n $(MONITORING_NS) create configmap $(DASHBOARD_CM) \
	  --from-file=$(DASHBOARD_JSON) --dry-run=client -o yaml \
	  | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(MONITORING_NS) label configmap $(DASHBOARD_CM) grafana_dashboard=1 --overwrite

dashboard-delete:
	$(KUBECTL) -n $(MONITORING_NS) delete configmap $(DASHBOARD_CM) --ignore-not-found

# Does the cluster still match the repo? Non-empty output means someone edited
# the dashboard in the Grafana UI, or the ConfigMap predates the last commit.
dashboard-diff:
	@$(KUBECTL) -n $(MONITORING_NS) get configmap $(DASHBOARD_CM) \
	  -o jsonpath='{.data.dashboard-revocation\.json}' 2>/dev/null \
	  | diff - $(DASHBOARD_JSON) && echo "dashboard in sync"

grafana-open:
	@echo "user: admin"
	@echo -n "pass: "; $(KUBECTL) -n $(MONITORING_NS) get secret prometheus-grafana \
	  -o jsonpath='{.data.admin-password}' | base64 -d; echo
	@echo "url:  http://localhost:3000/d/zta-revocation"
	$(KUBECTL) -n $(MONITORING_NS) port-forward svc/prometheus-grafana 3000:80

# Expect five targets, all 'up' — actuator, translator, service-a, service-b's
# istio-proxy, and istiod (T7). An empty panel is usually a DOWN target, not a
# bad query (deploy/observability/README.md). Exactly one istiod row: two Services
# front that pod, and both being scraped would double every pilot_* rate.
observability-targets:
	@$(KUBECTL) -n $(MONITORING_NS) port-forward svc/prometheus-operated 19090:9090 >/dev/null 2>&1 & \
	trap 'kill %1 2>/dev/null' EXIT; sleep 4; \
	curl -s 'http://localhost:19090/api/v1/targets?state=active' \
	  | jq -r '.data.activeTargets[] | select(.scrapePool|test("zta|istio-proxy|istiod")) \
	           | "\(.scrapePool)\t\(.labels.pod)\t\(.health)\t\(.lastError)"'

# --- trials (docs/trial-reset.md) ---

# Return the lab to its pre-trial state between attack scenarios.
#
# The actuator is reset in place rather than restarted. Its in-memory dedupe set
# still has to be cleared — a repeat trial on the same subject is a silent no-op
# otherwise — but rolling the Deployment to do it also resets the Prometheus
# counters, and the replacement pod lives ~12s against the scrape interval, so
# most trials go unscraped after their PATCH and the dashboard disagrees with the
# CSV (docs/trial-reset.md). The actuator has to outlive the run for its
# counters to mean anything.
#
# The other three restarts are load-bearing:
#   service-a / service-a-trial — the actuator strips their SPIRE-managed label,
#     and the prober's log has to start empty so trial-run.sh's "first 403" is
#     this trial's rather than the previous one's.
#   translator — cheapest way to guarantee a clean Tetragon stream per trial.
trial-reset:
	$(KUBECTL) apply -f deploy/istio/authorization-policy-deny-revoked.yaml
	@scripts/actuator-reset.sh
	$(KUBECTL) rollout restart deployment/translator      -n $(NAMESPACE)
	$(KUBECTL) rollout restart deployment/service-a       -n $(NAMESPACE)
	$(KUBECTL) rollout restart deployment/service-a-trial -n $(NAMESPACE)
	$(KUBECTL) rollout status  deployment/translator      -n $(NAMESPACE) --timeout=60s
	$(KUBECTL) rollout status  deployment/service-a       -n $(NAMESPACE) --timeout=60s
	$(KUBECTL) rollout status  deployment/service-a-trial -n $(NAMESPACE) --timeout=60s
	@$(MAKE) --no-print-directory trial-verify

# Clear the actuator's dedupe set on its own, without a full trial-reset. Useful
# when a trial dedupes unexpectedly and you want to retry without rolling pods.
actuator-reset:
	@scripts/actuator-reset.sh

trial-verify:
	@echo "--- revoked set (want: placeholder only) ---"
	@$(KUBECTL) get authorizationpolicy revoked-identities -n $(NAMESPACE) \
	  -o jsonpath='{.spec.rules[0].from[0].source.principals}'; echo
	@echo "--- A pods (want: SPIRE-MANAGED-IDENTITY=true) ---"
	@$(KUBECTL) get pods -n $(NAMESPACE) -l app=service-a \
	  -L spiffe.io/spire-managed-identity,variant
	@echo "--- A->B (want: status=200) ---"
	@# `|| true`: the selector can catch a pod that is still Terminating from the
	@# rollout above, and `kubectl logs` then exits NotFound — a race in the check,
	@# not a failed reset. Re-run `make trial-verify` if this prints nothing.
	@$(KUBECTL) logs -n $(NAMESPACE) -l 'app=service-a,variant!=trial' \
	  -c service-a --tail=3 || true

# Run one scenario and append a per-trial CSV row (scripts/trial_record.py).
#   make trial-run SCENARIO=exec COUNT=30
# Prometheus cannot compute end_to_end (T8-T0) — it needs a join between a
# Tetragon stamp and a Service A log line — so the reported percentiles come
# from this CSV, not from histogram_quantile.
SCENARIO ?= exec
COUNT    ?= 1

trial-run:
	@scripts/trial-run.sh $(SCENARIO) -n $(COUNT)

# One trial of each scenario. Validates the harness before a real run: confirms
# all three TracingPolicies still attribute to a SPIFFE ID and that T8 lands.
#
# The summary prints the harness's own default CSV (results/test-trials.csv,
# gitignored — scripts/trial-run.sh), which is where the three rows above were
# just written. Harness defaults are throwaway output; a run worth keeping
# sets CSV= / RAW_ROOT= explicitly.
SMOKE_CSV ?= results/test-trials.csv

trial-smoke:
	@scripts/trial-run.sh exec       -n 1 --note smoke
	@scripts/trial-run.sh egress     -n 1 --note smoke
	@scripts/trial-run.sh token-read -n 1 --note smoke
	@echo; column -t -s, $(SMOKE_CSV) | cut -c1-200
