package store

import (
	"context"
	"encoding/json"

	"github.com/nhiid/nhiid/internal/models"
)

// This file holds the "list all" reads the graph-projection job needs, plus a graph LoadAll that
// ignores account scope (cross-account attack paths are the interesting case).

// LoadAll loads the entire persisted graph into memory (bounded working set assumption applies).
func (r *GraphRepo) LoadAll(ctx context.Context) ([]models.GraphNode, []models.GraphEdge, error) {
	nrows, err := r.pool.Query(ctx, `
		SELECT id,node_type,entity_id,account_ref,label,criticality,attributes FROM graph_nodes`)
	if err != nil {
		return nil, nil, err
	}
	defer nrows.Close()
	var nodes []models.GraphNode
	for nrows.Next() {
		var n models.GraphNode
		var attrs []byte
		if err := nrows.Scan(&n.ID, &n.NodeType, &n.EntityID, &n.AccountRef, &n.Label, &n.Criticality, &attrs); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(attrs, &n.Attributes)
		nodes = append(nodes, n)
	}
	if err := nrows.Err(); err != nil {
		return nil, nil, err
	}

	erows, err := r.pool.Query(ctx, `
		SELECT id,src_node_id,dst_node_id,edge_type,weight,observed,attributes FROM graph_edges`)
	if err != nil {
		return nil, nil, err
	}
	defer erows.Close()
	var edges []models.GraphEdge
	for erows.Next() {
		var e models.GraphEdge
		var attrs []byte
		if err := erows.Scan(&e.ID, &e.SrcNodeID, &e.DstNodeID, &e.EdgeType, &e.Weight, &e.Observed, &attrs); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal(attrs, &e.Attributes)
		edges = append(edges, e)
	}
	return nodes, edges, erows.Err()
}

// ListAll returns all roles (capped) for graph projection.
func (r *RoleRepo) ListAll(ctx context.Context) ([]models.Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,provider,external_id,account_ref,name,privilege_level,is_assumable,
		       permission_count,wildcard_action_count,wildcard_resource_count
		FROM roles LIMIT 20000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Role
	for rows.Next() {
		var r models.Role
		if err := rows.Scan(&r.ID, &r.Provider, &r.ExternalID, &r.AccountRef, &r.Name,
			&r.PrivilegeLevel, &r.IsAssumable, &r.PermissionCount,
			&r.WildcardActionCount, &r.WildcardResourceCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAll returns all resource bindings (capped) for graph projection.
func (r *BindingRepo) ListAll(ctx context.Context) ([]models.ResourceBinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,identity_id,role_id,resource_urn,resource_kind,resource_criticality,actions,effect,account_ref
		FROM resource_bindings LIMIT 50000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ResourceBinding
	for rows.Next() {
		var b models.ResourceBinding
		if err := rows.Scan(&b.ID, &b.IdentityID, &b.RoleID, &b.ResourceURN, &b.ResourceKind,
			&b.ResourceCriticality, &b.Actions, &b.Effect, &b.AccountRef); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListAll returns all trust edges (capped) for graph projection.
func (r *TrustEdgeRepo) ListAll(ctx context.Context) ([]models.TrustEdge, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,src_identity_id,src_role_id,dst_identity_id,dst_role_id,edge_type,condition,observed,account_ref
		FROM trust_edges LIMIT 50000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.TrustEdge
	for rows.Next() {
		var e models.TrustEdge
		var cond []byte
		if err := rows.Scan(&e.ID, &e.SrcIdentityID, &e.SrcRoleID, &e.DstIdentityID, &e.DstRoleID,
			&e.EdgeType, &cond, &e.Observed, &e.AccountRef); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cond, &e.Condition)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAll returns all workloads (capped) for graph projection.
func (r *WorkloadRepo) ListAll(ctx context.Context) ([]models.Workload, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id,kind,external_id,account_ref,name,environment,identity_id
		FROM workloads LIMIT 50000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Workload
	for rows.Next() {
		var w models.Workload
		if err := rows.Scan(&w.ID, &w.Kind, &w.ExternalID, &w.AccountRef, &w.Name, &w.Environment, &w.IdentityID); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
