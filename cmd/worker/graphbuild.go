package main

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/store"
)

// blastMaxHops bounds capability traversal for blast-radius and attack-path computation.
const blastMaxHops = 5

// projectGraph reads the normalized entities and (re)projects them into graph_nodes/graph_edges.
// Idempotent: nodes are keyed by (node_type, entity_id) and edges by (src, dst, type).
func projectGraph(ctx context.Context, s *store.Store, logger *slog.Logger) error {
	idents, err := s.Identities.List(ctx, store.IdentityFilter{Limit: 20000})
	if err != nil {
		return err
	}
	roles, err := s.Roles.ListAll(ctx)
	if err != nil {
		return err
	}
	bindings, err := s.Bindings.ListAll(ctx)
	if err != nil {
		return err
	}
	trust, err := s.TrustEdges.ListAll(ctx)
	if err != nil {
		return err
	}
	workloads, err := s.Workloads.ListAll(ctx)
	if err != nil {
		return err
	}

	nodeID := map[uuid.UUID]uuid.UUID{} // entity id -> graph node id

	// identity nodes
	for _, id := range idents {
		eid := id.ID
		nid, err := s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "identity", EntityID: &eid, AccountRef: id.Prov.AccountRef,
			Label: id.Name, Criticality: models.CritLow,
			Attributes: map[string]any{"kind": string(id.Kind), "provider": id.Provider, "is_ai_agent": id.IsAIAgent},
		})
		if err != nil {
			continue
		}
		nodeID[id.ID] = nid
	}

	// role (permission-set) nodes; admin/privileged roles are high-criticality targets
	for _, r := range roles {
		crit := models.CritLow
		if r.PrivilegeLevel == "admin" || r.PrivilegeLevel == "privileged" {
			crit = models.CritHigh
		}
		eid := r.ID
		nid, err := s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "role", EntityID: &eid, AccountRef: r.AccountRef,
			Label: r.Name, Criticality: crit,
			Attributes: map[string]any{"privilege_level": r.PrivilegeLevel},
		})
		if err != nil {
			continue
		}
		nodeID[r.ID] = nid
	}

	// resource nodes (deduped by URN, rolled up to max criticality)
	urnCrit := map[string]models.Criticality{}
	urnAcct := map[string]string{}
	for _, b := range bindings {
		if models.CriticalityRank(b.ResourceCriticality) > models.CriticalityRank(urnCrit[b.ResourceURN]) {
			urnCrit[b.ResourceURN] = b.ResourceCriticality
		}
		urnAcct[b.ResourceURN] = b.AccountRef
	}
	urnNode := map[string]uuid.UUID{}
	for urn, crit := range urnCrit {
		eid := models.DeterministicID("resource", urn)
		nid, err := s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "resource", EntityID: &eid, AccountRef: urnAcct[urn],
			Label: urn, Criticality: crit,
		})
		if err != nil {
			continue
		}
		urnNode[urn] = nid
	}

	// workload nodes
	for _, w := range workloads {
		eid := w.ID
		nid, err := s.Graph.UpsertNode(ctx, models.GraphNode{
			NodeType: "workload", EntityID: &eid, AccountRef: w.AccountRef, Label: w.Name,
		})
		if err != nil {
			continue
		}
		nodeID[w.ID] = nid
	}

	edges := 0
	upsert := func(src, dst uuid.UUID, et string, observed bool) {
		if src == uuid.Nil || dst == uuid.Nil {
			return
		}
		if err := s.Graph.UpsertEdge(ctx, models.GraphEdge{
			SrcNodeID: src, DstNodeID: dst, EdgeType: et, Weight: 1, Observed: observed,
		}); err == nil {
			edges++
		}
	}

	// assume/impersonate/federate edges (principal -> role/identity)
	for _, t := range trust {
		var src uuid.UUID
		if t.SrcIdentityID != nil {
			src = nodeID[*t.SrcIdentityID]
		}
		if src == uuid.Nil && t.SrcRoleID != nil {
			src = nodeID[*t.SrcRoleID]
		}
		var dst uuid.UUID
		if t.DstRoleID != nil {
			dst = nodeID[*t.DstRoleID]
		}
		if dst == uuid.Nil && t.DstIdentityID != nil {
			dst = nodeID[*t.DstIdentityID]
		}
		upsert(src, dst, capabilityEdgeType(t.EdgeType), t.Observed)
	}

	// binds_to edges (principal/role -> resource)
	for _, b := range bindings {
		var src uuid.UUID
		if b.IdentityID != nil {
			src = nodeID[*b.IdentityID]
		}
		if src == uuid.Nil && b.RoleID != nil {
			src = nodeID[*b.RoleID]
		}
		upsert(src, urnNode[b.ResourceURN], "binds_to", false)
	}

	// uses edges (workload -> identity)
	for _, w := range workloads {
		if w.IdentityID != nil {
			upsert(nodeID[w.ID], nodeID[*w.IdentityID], "uses", false)
		}
	}

	logger.Info("graph projected", "nodes", len(nodeID)+len(urnNode), "edges", edges)
	return nil
}

// capabilityEdgeType maps trust-edge types onto the graph engine's capability vocabulary.
func capabilityEdgeType(t string) string {
	switch t {
	case "can_assume":
		return "assumes"
	case "can_impersonate":
		return "impersonates"
	default:
		return t // can_mint_token, federated_from pass through
	}
}

// loadGraph loads the persisted graph into memory and precomputes the peer reachable-count P90.
func loadGraph(ctx context.Context, s *store.Store) (*graph.Graph, int, error) {
	nodes, edges, err := s.Graph.LoadAll(ctx)
	if err != nil {
		return nil, 0, err
	}
	g := graph.FromModels(nodes, edges)
	return g, g.ReachableCountP90(blastMaxHops), nil
}
