package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// spireManagedLabel is the pod label a ClusterSPIFFEID podSelector would key
// on. The actuator strips it to cut off SVID reissuance, but the chart's
// default ClusterSPIFFEID is selector-less, so the controller-manager keeps
// the registration entry alive regardless — the cutoff only bites once a
// podSelector scopes issuance to this label (docs/trial-reset.md).
const spireManagedLabel = "spiffe.io/spire-managed-identity"

// Pods go through the dynamic client too, so the actuator keeps a single
// Kubernetes client rather than carrying a typed clientset for one resource.
var podGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// removeSpireLabel strips spireManagedLabel from every pod carrying the revoked
// SPIFFE ID, and reports how many pods it patched.
//
// This is the complementary half of the response, not the revocation: an
// already-issued SVID stays valid until its TTL expires, so this only closes off
// reissuance. revokeInMesh is what denies in real time, and the two run in
// parallel so this never sits on that path (docs/architecture.md).
//
// The naming convention supplies the selector — the ID's own ns/sa segments name
// the pods that carry it — so one event covers every replica of Service A,
// trial vehicles included.
//
// Deliberately stateless: a repeated event re-lists, finds nothing left carrying
// the label, and is a no-op. (revokeInMesh needs its own dedupe because
// appending twice would grow the policy; here the cluster state is the dedupe.)
func removeSpireLabel(ctx context.Context, client dynamic.Interface, spiffeID string) (int, error) {
	namespace, serviceAccount, err := parseWorkloadID(spiffeID)
	if err != nil {
		return 0, err
	}

	// Existence selector, not =true: whatever the value, the label is what keeps
	// the entry alive, so anything carrying it is in scope.
	pods, err := client.Resource(podGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: spireManagedLabel,
	})
	if err != nil {
		return 0, fmt.Errorf("list pods in %s: %w", namespace, err)
	}

	// A merge patch setting the key to null: idempotent (unlike a JSON Patch
	// "remove", which 422s when the label is already gone) and it touches only
	// this key, so a concurrent write to other labels is not clobbered.
	patch := fmt.Appendf(nil, `{"metadata":{"labels":{%q:null}}}`, spireManagedLabel)

	var patched int
	var errs []error
	for _, pod := range pods.Items {
		// The API server supports a spec.serviceAccountName field selector, but
		// the fake client used in tests ignores field selectors — filter here so
		// both paths agree.
		sa, found, err := unstructured.NestedString(pod.Object, "spec", "serviceAccountName")
		if err != nil || !found || sa != serviceAccount {
			continue
		}

		if _, err := client.Resource(podGVR).Namespace(namespace).
			Patch(ctx, pod.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			// Keep going: one un-patchable pod should not leave its siblings
			// holding a renewable identity.
			errs = append(errs, fmt.Errorf("patch pod %s/%s: %w", namespace, pod.GetName(), err))
			continue
		}
		patched++
	}

	return patched, errors.Join(errs...)
}

// parseWorkloadID splits spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
// back into the namespace and ServiceAccount that produced it. The naming
// convention is the mapping in both directions (docs/architecture.md): the
// translator builds the ID from the workload, the actuator reads it back out.
func parseWorkloadID(spiffeID string) (namespace, serviceAccount string, err error) {
	path, ok := strings.CutPrefix(spiffeID, "spiffe://")
	if !ok {
		return "", "", fmt.Errorf("subject %q is not a SPIFFE ID", spiffeID)
	}

	// <trust-domain>/ns/<namespace>/sa/<service-account>
	segments := strings.Split(path, "/")
	if len(segments) != 5 || segments[1] != "ns" || segments[3] != "sa" {
		return "", "", fmt.Errorf("subject %q does not match spiffe://<td>/ns/<ns>/sa/<sa>", spiffeID)
	}
	if segments[0] == "" || segments[2] == "" || segments[4] == "" {
		return "", "", fmt.Errorf("subject %q has an empty trust domain, namespace or service account", spiffeID)
	}

	return segments[2], segments[4], nil
}
