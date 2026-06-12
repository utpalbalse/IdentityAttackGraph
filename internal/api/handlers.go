// Package api provides REST handlers for NHIID.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/risk"
	"github.com/nhiid/nhiid/internal/store"
)

type Handler struct {
	Store       *store.Store
	RiskEngine  *risk.Engine
	Logger      *slog.Logger
}

// ---------- version / health ------------------------------------------------

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"version": "0.1.0",
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
	usage, _ := h.Store.Usage.RecentForIdentity(r.Context(), id, time.Now().Add(-90*24*time.Hour))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"identity": ident,
		"credentials": creds,
		"roles": roles,
		"resource_bindings": bindings,
		"trust_edges": trust,
		"workloads": workloads,
		"exposures": exposures,
		"findings": findings,
		"usage_sample": usage[len(usage)-10:],
	})
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
	_, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	// Load the graph and compute attack paths (stub for MVP).
	// In full impl, load from store and traverse.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"paths": []graph.Path{},
	})
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
		"finding": f,
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
