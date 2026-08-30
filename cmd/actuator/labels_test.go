package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// managedPod builds a pod as the workload manifests declare it: a ServiceAccount
// plus the SPIRE-managed label a ClusterSPIFFEID podSelector would key on.
func managedPod(name, serviceAccount string, labelled bool) *unstructured.Unstructured {
	labels := map[string]any{"app": serviceAccount}
	if labelled {
		labels[spireManagedLabel] = "true"
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": testNamespace,
			"labels":    labels,
		},
		"spec": map[string]any{"serviceAccountName": serviceAccount},
	}}
}

// hasSpireLabel reads the label back off a pod in the fake cluster.
func hasSpireLabel(t *testing.T, client dynamic.Interface, name string) bool {
	t.Helper()

	pod, err := client.Resource(podGVR).Namespace(testNamespace).
		Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting pod %s: %v", name, err)
	}
	_, ok := pod.GetLabels()[spireManagedLabel]
	return ok
}

// Revocation is per-identity (docs/architecture.md): every pod running as the
// revoked ServiceAccount loses the label from a single event — the Go prober
// and both trial vehicles at once — while other identities are untouched.
func TestRemoveSpireLabelStripsEveryPodWithTheIdentity(t *testing.T) {
	client := newFakeMesh(
		managedPod("service-a-1", "service-a", true),
		managedPod("service-a-trial-1", "service-a", true),
		managedPod("service-b-1", "service-b", true),
	)

	patched, err := removeSpireLabel(context.Background(), client,
		"spiffe://example.org/ns/zta-ssf/sa/service-a")
	if err != nil {
		t.Fatalf("removeSpireLabel() error = %v", err)
	}
	if patched != 2 {
		t.Errorf("patched = %d, want 2", patched)
	}

	for _, name := range []string{"service-a-1", "service-a-trial-1"} {
		if hasSpireLabel(t, client, name) {
			t.Errorf("pod %s still carries %s", name, spireManagedLabel)
		}
	}
	if !hasSpireLabel(t, client, "service-b-1") {
		t.Errorf("pod service-b-1 lost %s — only the revoked identity should be stripped", spireManagedLabel)
	}
}

// A Tetragon match fires once per process in the attacker's loop, so the same
// subject arrives repeatedly. The second pass has nothing left to strip and must
// report that as a no-op, not an error.
func TestRemoveSpireLabelIsIdempotent(t *testing.T) {
	client := newFakeMesh(managedPod("service-a-1", "service-a", true))
	const subject = "spiffe://example.org/ns/zta-ssf/sa/service-a"

	if _, err := removeSpireLabel(context.Background(), client, subject); err != nil {
		t.Fatalf("first removeSpireLabel() error = %v", err)
	}

	patched, err := removeSpireLabel(context.Background(), client, subject)
	if err != nil {
		t.Fatalf("second removeSpireLabel() error = %v", err)
	}
	if patched != 0 {
		t.Errorf("patched = %d on the repeat event, want 0", patched)
	}
}

// A pod running as the revoked ServiceAccount but never SPIRE-managed is out of
// scope — the label selector, not the ServiceAccount alone, decides.
func TestRemoveSpireLabelIgnoresUnlabelledPods(t *testing.T) {
	client := newFakeMesh(managedPod("service-a-unmanaged", "service-a", false))

	patched, err := removeSpireLabel(context.Background(), client,
		"spiffe://example.org/ns/zta-ssf/sa/service-a")
	if err != nil {
		t.Fatalf("removeSpireLabel() error = %v", err)
	}
	if patched != 0 {
		t.Errorf("patched = %d, want 0", patched)
	}
}

func TestParseWorkloadID(t *testing.T) {
	tests := []struct {
		name     string
		spiffeID string
		wantNS   string
		wantSA   string
		wantErr  bool
	}{
		{name: "conventional id", spiffeID: "spiffe://example.org/ns/zta-ssf/sa/service-a", wantNS: "zta-ssf", wantSA: "service-a"},
		{name: "other trust domain", spiffeID: "spiffe://other.test/ns/prod/sa/api", wantNS: "prod", wantSA: "api"},
		{name: "no scheme", spiffeID: "example.org/ns/zta-ssf/sa/service-a", wantErr: true},
		{name: "not the convention", spiffeID: "spiffe://example.org/workload/service-a", wantErr: true},
		{name: "trailing segment", spiffeID: "spiffe://example.org/ns/zta-ssf/sa/service-a/extra", wantErr: true},
		{name: "empty namespace", spiffeID: "spiffe://example.org/ns//sa/service-a", wantErr: true},
		{name: "empty service account", spiffeID: "spiffe://example.org/ns/zta-ssf/sa/", wantErr: true},
		{name: "empty", spiffeID: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, sa, err := parseWorkloadID(tt.spiffeID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseWorkloadID(%q) error = %v, wantErr = %v", tt.spiffeID, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if ns != tt.wantNS || sa != tt.wantSA {
				t.Errorf("parseWorkloadID(%q) = (%q, %q), want (%q, %q)", tt.spiffeID, ns, sa, tt.wantNS, tt.wantSA)
			}
		})
	}
}

// Both actions must fire off one SET: the mesh deny (the revocation) and the
// label removal (renewal cut off), through the same /events entry point.
func TestEventsHandlerRemovesLabelAndPatchesMesh(t *testing.T) {
	client := newFakeMesh(managedPod("service-a-1", "service-a", true))

	req := httptest.NewRequest(http.MethodPost, "/events",
		strings.NewReader(validSET(t, "spiffe://example.org/ns/zta-ssf/sa/service-a")))
	rec := httptest.NewRecorder()

	eventsHandler(client, &sync.Map{}, testNamespace, testPolicyName)(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body = %q", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if hasSpireLabel(t, client, "service-a-1") {
		t.Errorf("pod service-a-1 still carries %s", spireManagedLabel)
	}
	if got := principals(t, client); len(got) != 2 {
		t.Errorf("principals = %v, want the seed plus the revoked subject", got)
	}
}
