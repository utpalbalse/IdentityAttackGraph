// Package api provides REST handlers for NHIID.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/export"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/risk"
	"github.com/nhiid/nhiid/internal/store"
)

type Handler struct {
	Store      *store.Store
	RiskEngine *risk.Engine
	Logger     *slog.Logger
}

// ---------- version / health ------------------------------------------------

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"version":        "0.1.0",
		"schema_version": "1",
	})
}

// ---------- identities -----------------------------------------------------

func (h *Handler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	f := store.IdentityFilter{
		Provider:   r.URL.Query().Get("provider"),
		AccountRef: r.URL.Query().Get("account"),
		Kind:       r.URL.Query().Get("kind"),
		Q:          r.URL.Query().Get("q"),
		Limit:      50,
	}
	ids, err := h.Store.Identities.List(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"identities": ids})
}

func (h *Handler) GetIdentity(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ident, err := h.Store.Identities.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	creds, _ := h.Store.Credentials.ForIdentity(r.Context(), id)
	roles, _ := h.Store.Roles.ForIdentity(r.Context(), id)
	bindings, _ := h.Store.Bindings.ForIdentity(r.Context(), id)
	trust, _ := h.Store.TrustEdges.ForIdentity(r.Context(), id)
	workloads, _ := h.Store.Workloads.ForIdentity(r.Context(), id)
	exposures, _ := h.Store.Exposures.ForIdentity(r.Context(), id)
	findings, _ := h.Store.Findings.List(r.Context(), store.FindingFilter{IdentityID: &id})
	remediations, _ := h.Store.Remediation.ForIdentity(r.Context(), id)
	usage, _ := h.Store.Usage.RecentForIdentity(r.Context(), id, time.Now().Add(-90*24*time.Hour))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"identity":          ident,
		"credentials":       nonNil(creds),
		"roles":             nonNil(roles),
		"resource_bindings": nonNil(bindings),
		"trust_edges":       nonNil(trust),
		"workloads":         nonNil(workloads),
		"exposures":         nonNil(exposures),
		"findings":          nonNil(findings),
		"remediations":      nonNil(remediations),
		"usage_sample":      lastN(usage, 10),
	})
}

// GetRiskReduction reports the measurable risk removed by completed remediations.
func (h *Handler) GetRiskReduction(w http.ResponseWriter, r *http.Request) {
	total, done, err := h.Store.Remediation.RiskReductionDone(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"risk_reduced": total, "completed_actions": done})
}

// UpdateRemediation sets a remediation action's workflow status (planned/in_progress/done/wont_fix).
func (h *Handler) UpdateRemediation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.Store.Remediation.UpdateStatus(r.Context(), id, req.Status, req.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "updated"})
}

// lastN returns up to the last n elements of s without panicking on short slices.
func lastN[T any](s []T, n int) []T {
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return nonNil(s)
}

// nonNil guarantees a JSON array ([]) rather than null for empty/nil slices.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (h *Handler) GetIdentityRisk(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ident, err := h.Store.Identities.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ident.RiskBreakdown)
}

func (h *Handler) GetAttackPaths(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	g, ok := h.loadGraph(r, w)
	if !ok {
		return
	}
	out := []graph.PathView{}
	if nid, ok := g.NodeIDForEntity(id); ok {
		out = g.Explain(g.AttackPaths(nid, 5, 10))
	}
	writeJSON(w, map[string]any{"paths": out})
}

func (h *Handler) GetBlastRadius(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	g, ok := h.loadGraph(r, w)
	if !ok {
		return
	}
	var br graph.BlastRadius
	if nid, ok := g.NodeIDForEntity(id); ok {
		br = g.ComputeBlastRadius(nid, 5)
	}
	writeJSON(w, br)
}

// graphNodeDTO / graphEdgeDTO are the Cytoscape-friendly projection returned to the UI.
type graphNodeDTO struct {
	ID          string `json:"id"`
	EntityID    string `json:"entity_id,omitempty"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	Criticality string `json:"criticality"`
}

type graphEdgeDTO struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

// GetGraph returns the whole identity graph (capped) for the Attack Graph view.
func (h *Handler) GetGraph(w http.ResponseWriter, r *http.Request) {
	nodes, edges, err := h.Store.Graph.LoadAll(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	const cap = 2000
	if len(nodes) > cap {
		nodes = nodes[:cap]
	}
	present := map[uuid.UUID]bool{}
	dn := make([]graphNodeDTO, 0, len(nodes))
	for _, n := range nodes {
		present[n.ID] = true
		dn = append(dn, nodeDTO(n))
	}
	de := make([]graphEdgeDTO, 0, len(edges))
	for _, e := range edges {
		if !present[e.SrcNodeID] || !present[e.DstNodeID] {
			continue // drop edges to capped-out nodes
		}
		de = append(de, graphEdgeDTO{ID: e.ID.String(), Source: e.SrcNodeID.String(), Target: e.DstNodeID.String(), Type: e.EdgeType})
	}
	writeJSON(w, map[string]any{"nodes": dn, "edges": de})
}

// GetNeighborhood returns the subgraph within `depth` hops of an entity (identity) node.
func (h *Handler) GetNeighborhood(w http.ResponseWriter, r *http.Request) {
	entityID, err := uuid.Parse(r.URL.Query().Get("node"))
	if err != nil {
		http.Error(w, "invalid node id", http.StatusBadRequest)
		return
	}
	depth := 2
	if d, err := strconv.Atoi(r.URL.Query().Get("depth")); err == nil && d > 0 && d <= 6 {
		depth = d
	}
	g, ok := h.loadGraph(r, w)
	if !ok {
		return
	}
	dn := []graphNodeDTO{}
	de := []graphEdgeDTO{}
	if nid, ok := g.NodeIDForEntity(entityID); ok {
		ns, es := g.Neighborhood(nid, depth)
		for _, n := range ns {
			dn = append(dn, graphNodeDTO{
				ID: n.ID.String(), EntityID: nonNilUUID(n.EntityID), Type: n.Type,
				Label: n.Label, Criticality: string(n.Criticality),
			})
		}
		for _, e := range es {
			de = append(de, graphEdgeDTO{ID: e.Src.String() + e.Type + e.Dst.String(), Source: e.Src.String(), Target: e.Dst.String(), Type: e.Type})
		}
	}
	writeJSON(w, map[string]any{"nodes": dn, "edges": de})
}

func nodeDTO(n models.GraphNode) graphNodeDTO {
	ent := ""
	if n.EntityID != nil {
		ent = n.EntityID.String()
	}
	return graphNodeDTO{ID: n.ID.String(), EntityID: ent, Type: n.NodeType, Label: n.Label, Criticality: string(n.Criticality)}
}

func nonNilUUID(u uuid.UUID) string {
	if u == uuid.Nil {
		return ""
	}
	return u.String()
}

// loadGraph loads the persisted graph for read endpoints, writing a 500 on failure.
func (h *Handler) loadGraph(r *http.Request, w http.ResponseWriter) (*graph.Graph, bool) {
	nodes, edges, err := h.Store.Graph.LoadAll(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return graph.FromModels(nodes, edges), true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---------- exports (JSON / SARIF / CSV) ----------

func (h *Handler) ExportFindings(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	findings, err := h.Store.Findings.List(r.Context(), store.FindingFilter{Status: r.URL.Query().Get("status"), Limit: 5000})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := h.identityIndex(r)
	rows := make([]export.FindingRow, 0, len(findings))
	for _, f := range findings {
		var name, arn, acct string
		if f.IdentityID != nil {
			if id, ok := names[*f.IdentityID]; ok {
				name, arn, acct = id.Name, id.ARNOrEmail, id.Prov.AccountRef
			}
		}
		rows = append(rows, export.FindingRow{
			Detector: f.Detector, Category: f.Category, Severity: string(f.Severity), Confidence: f.Confidence,
			IdentityName: name, IdentityARN: arn, Account: acct,
			Title: f.Title, Narrative: f.Narrative, Status: f.Status, Evidence: f.Evidence,
			FirstSeen: f.FirstSeenAt, LastSeen: f.LastSeenAt,
		})
	}
	switch format {
	case "sarif":
		setDownload(w, "application/sarif+json", "nhiid-findings.sarif")
		_ = export.FindingsSARIF(w, rows)
	case "csv":
		setDownload(w, "text/csv", "nhiid-findings.csv")
		_ = export.FindingsCSV(w, rows)
	default:
		setDownload(w, "application/json", "nhiid-findings.json")
		_ = export.FindingsJSON(w, rows)
	}
}

func (h *Handler) ExportInventory(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	ids, err := h.Store.Identities.List(r.Context(), store.IdentityFilter{Limit: 5000})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]export.InventoryRow, 0, len(ids))
	for _, i := range ids {
		rows = append(rows, export.InventoryRow{
			Name: i.Name, Kind: string(i.Kind), Provider: i.Provider, Account: i.Prov.AccountRef,
			State: i.State, RiskScore: i.RiskScore, LastSeen: i.LastSeenAt,
		})
	}
	if format == "csv" {
		setDownload(w, "text/csv", "nhiid-inventory.csv")
		_ = export.InventoryCSV(w, rows)
		return
	}
	setDownload(w, "application/json", "nhiid-inventory.json")
	_ = export.InventoryJSON(w, rows)
}

// identityIndex returns a id->identity map for joining names into exports.
func (h *Handler) identityIndex(r *http.Request) map[uuid.UUID]models.Identity {
	ids, _ := h.Store.Identities.List(r.Context(), store.IdentityFilter{Limit: 5000})
	m := make(map[uuid.UUID]models.Identity, len(ids))
	for _, i := range ids {
		m[i.ID] = i
	}
	return m
}

func setDownload(w http.ResponseWriter, contentType, filename string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
}

// ---------- findings -------------------------------------------------------

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	f := store.FindingFilter{
		Detector: r.URL.Query().Get("detector"),
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		Limit:    100,
	}
	findings, err := h.Store.Findings.List(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"findings": findings})
}

func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	f, err := h.Store.Findings.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	remediations, _ := h.Store.Remediation.ForFinding(r.Context(), id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"finding":      f,
		"remediations": remediations,
	})
}

func (h *Handler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Status   string `json:"status"`
		Assignee string `json:"assignee"`
		Notes    string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.Store.Findings.UpdateStatus(r.Context(), id, req.Status, req.Assignee, req.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// ---------- triage ---------------------------------------------------------

func (h *Handler) GetTriage(w http.ResponseWriter, r *http.Request) {
	queue, err := h.Store.Identities.TriageQueue(r.Context(), 25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"triage_queue": queue})
}
