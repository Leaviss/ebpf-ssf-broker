package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// AuthorizationPolicy is a CRD, so it's addressed via the dynamic client — that
// keeps istio.io/api out of go.mod for one object.
var authzPolicyGVR = schema.GroupVersionResource{
	Group:    "security.istio.io",
	Version:  "v1",
	Resource: "authorizationpolicies",
}

// revokeInMesh appends a SPIFFE ID to the principals list of the DENY
// AuthorizationPolicy in deploy/istio/authorization-policy-deny-revoked.yaml —
// the chosen actuation path (docs/architecture.md). DENY is evaluated before
// ALLOW and Envoy re-checks RBAC per request, so the append denies the identity
// at Service B's sidecar immediately.
//
// The JSON patch append avoids a read-modify-write: the policy object *is* the
// revoked set. It requires the object to already exist with
// spec.rules[0].from[0].source.principals present — the seeded manifest is that
// starting state.
//
// `revoked` dedupes per identity: one policy match fires on every process in the
// attacker's loop, and each would otherwise append the same principal again. The
// return value says whether this call was the one that revoked, so the measured
// latency belongs to a subject's first event rather than its twentieth.
// Re-applying the manifest resets the cluster side of that state; resetDedupePath
// resets this side (docs/trial-reset.md).
func revokeInMesh(ctx context.Context, client dynamic.Interface, revoked *sync.Map, namespace, policyName, spiffeID string) (bool, error) {
	// Istio matches the peer SVID's URI SAN with the scheme stripped.
	principal := strings.TrimPrefix(spiffeID, "spiffe://")
	if principal == spiffeID || principal == "" {
		return false, fmt.Errorf("subject %q is not a SPIFFE ID", spiffeID)
	}

	if _, dup := revoked.LoadOrStore(principal, struct{}{}); dup {
		return false, nil
	}

	patch, err := json.Marshal([]map[string]any{{
		"op":    "add",
		"path":  "/spec/rules/0/from/0/source/principals/-",
		"value": principal,
	}})
	if err != nil {
		revoked.Delete(principal)
		return false, err
	}

	_, err = client.Resource(authzPolicyGVR).Namespace(namespace).
		Patch(ctx, policyName, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		// Drop it again so a later event for the same subject retries.
		revoked.Delete(principal)
		return false, fmt.Errorf("patch AuthorizationPolicy %s/%s: %w", namespace, policyName, err)
	}
	return true, nil
}
