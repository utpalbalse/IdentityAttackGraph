package k8s

import (
	"encoding/json"
	"fmt"
)

// parseExport decodes a kubectl `-o json` export into a snapshot. It accepts either a List
// (the usual `kubectl get a,b,c -A -o json` output) or a single object, dispatching each item by
// its `kind`. Unknown kinds are ignored so the export can be broad.
func parseExport(data []byte) (snapshot, error) {
	var snap snapshot

	var top struct {
		Kind  string            `json:"kind"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		return snap, fmt.Errorf("k8s: parse export: %w", err)
	}

	items := top.Items
	if len(items) == 0 && top.Kind != "" && top.Kind != "List" {
		// A single object was provided rather than a List.
		items = []json.RawMessage{json.RawMessage(data)}
	}
	if len(items) == 0 {
		return snap, fmt.Errorf("k8s: export contains no items (expected a kubectl List)")
	}

	for _, raw := range items {
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		switch probe.Kind {
		case "ServiceAccount":
			var sa serviceAccount
			if json.Unmarshal(raw, &sa) == nil {
				snap.serviceAccounts = append(snap.serviceAccounts, sa)
			}
		case "Role":
			var r role
			if json.Unmarshal(raw, &r) == nil {
				r.cluster = false
				snap.roles = append(snap.roles, r)
			}
		case "ClusterRole":
			var r role
			if json.Unmarshal(raw, &r) == nil {
				r.cluster = true
				snap.roles = append(snap.roles, r)
			}
		case "RoleBinding":
			var rb roleBinding
			if json.Unmarshal(raw, &rb) == nil {
				rb.cluster = false
				snap.roleBindings = append(snap.roleBindings, rb)
			}
		case "ClusterRoleBinding":
			var rb roleBinding
			if json.Unmarshal(raw, &rb) == nil {
				rb.cluster = true
				snap.roleBindings = append(snap.roleBindings, rb)
			}
		case "Pod":
			var p pod
			if json.Unmarshal(raw, &p) == nil {
				snap.pods = append(snap.pods, p)
			}
		case "Secret":
			var s secret
			if json.Unmarshal(raw, &s) == nil {
				snap.secrets = append(snap.secrets, s)
			}
		}
	}
	return snap, nil
}
