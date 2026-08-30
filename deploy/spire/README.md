# deploy/spire

SPIRE — server, agent, `spire-controller-manager`, and the SPIFFE CSI driver —
is a **prerequisite**, installed as a single Helm release (chart `spire`
0.13.0, server 1.7.2, from https://spiffe.github.io/helm-charts-hardened/)
before Istio and the workloads. See [`docs/reproduce.md`](../../docs/reproduce.md)
§1 for the exact install commands and the values that must line up with the
Istio overlay (trust domain, agent socket name).

The directory holds no manifests: the release runs on chart defaults, with no
`-f` / `--set` overrides. It is where a values file would go if one were ever
needed — see the `podSelector` note in
[`../../docs/trial-reset.md`](../../docs/trial-reset.md).

Workload registration entries are **not** kept here — or anywhere. They are minted
automatically by `spire-controller-manager` from a selector-less `ClusterSPIFFEID`
installed with the SPIRE Helm chart; see
[`../workloads/README.md`](../workloads/README.md) for the details.
