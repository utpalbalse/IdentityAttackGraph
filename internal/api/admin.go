package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/auth"
	"github.com/nhiid/nhiid/internal/collectors"
	awscollector "github.com/nhiid/nhiid/internal/collectors/aws"
	"github.com/nhiid/nhiid/internal/collectors/fixture"
	gcpcollector "github.com/nhiid/nhiid/internal/collectors/gcp"
	k8scollector "github.com/nhiid/nhiid/internal/collectors/k8s"
	repocollector "github.com/nhiid/nhiid/internal/collectors/repo"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/queue"
	"github.com/nhiid/nhiid/internal/risk"
)

// actor identifies who performed a mutation for the audit log: the authenticated principal's
// subject when auth is enabled, else the X-Actor header (default "anonymous").
func actor(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok && p.Subject != "" {
		return p.Subject
	}
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "anonymous"
}

// audit writes a best-effort audit record; failures are logged, not fatal.
func (h *Handler) audit(r *http.Request, action, targetType, targetID string, before, after map[string]any) {
	if err := h.Store.Audit.Write(r.Context(), models.AuditEntry{
		Actor: actor(r), Action: action, TargetType: targetType, TargetID: targetID, Before: before, After: after,
	}); err != nil && h.Logger != nil {
		h.Logger.Warn("audit write failed", "action", action, "err", err)
	}
}

func limitParam(r *http.Request, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		return v
	}
	return def
}

// ---------- inventory lists ----------

func (h *Handler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Credentials.List(r.Context(), limitParam(r, 200))
	respondList(w, "credentials", rows, err)
}

func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Secrets.List(r.Context(), limitParam(r, 200))
	respondList(w, "secrets", rows, err)
}

func (h *Handler) ListWorkloads(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Workloads.List(r.Context(), limitParam(r, 200))
	respondList(w, "workloads", rows, err)
}

func (h *Handler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Repos.List(r.Context(), limitParam(r, 200))
	respondList(w, "repositories", rows, err)
}

func (h *Handler) GetIdentityCredentials(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	rows, err := h.Store.Credentials.ForIdentity(r.Context(), id)
	respondList(w, "credentials", rows, err)
}

func (h *Handler) GetIdentityUsage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	since := time.Now().Add(-90 * 24 * time.Hour)
	rows, err := h.Store.Usage.RecentForIdentity(r.Context(), id, since)
	respondList(w, "usage", rows, err)
}

func (h *Handler) GetFindingRemediations(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	rows, err := h.Store.Remediation.ForFinding(r.Context(), id)
	respondList(w, "remediations", rows, err)
}

// ---------- jobs & collection ----------

func (h *Handler) ListCollectorRuns(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Collectors.ListRuns(r.Context(), limitParam(r, 100))
	respondList(w, "collector_runs", rows, err)
}

func (h *Handler) ListSnapshots(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Snapshots.List(r.Context(), limitParam(r, 100))
	respondList(w, "snapshots", rows, err)
}

// Collect triggers a collection in the background (in-process; the durable queue is a later step).
func (h *Handler) Collect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider       string `json:"provider"`
		Account        string `json:"account"`
		Project        string `json:"project"`
		Fixture        string `json:"fixture"`
		RoleARN        string `json:"role_arn"`
		ExternalID     string `json:"external_id"`
		Region         string `json:"region"`
		GCPCredentials string `json:"gcp_credentials"`
		Report         string `json:"report"`
		ScanPath       string `json:"scan_path"`
		Repo           string `json:"repo"`
		RepoProvider   string `json:"repo_provider"`
		RepoVisibility string `json:"repo_visibility"`
		Cluster        string `json:"cluster"`
		K8sExport      string `json:"k8s_export"`
		Kubeconfig     string `json:"kubeconfig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Preferred path: enqueue onto NATS JetStream; the worker consumes and runs the collector.
	if h.Queue != nil {
		job := queue.CollectJob{
			Provider: req.Provider, Account: req.Account, Project: req.Project, Fixture: req.Fixture,
			RoleARN: req.RoleARN, ExternalID: req.ExternalID, Region: req.Region,
			GCPCredentials: req.GCPCredentials, Report: req.Report, ScanPath: req.ScanPath, Repo: req.Repo,
			RepoProvider: req.RepoProvider, RepoVisibility: req.RepoVisibility,
			Cluster: req.Cluster, K8sExport: req.K8sExport, Kubeconfig: req.Kubeconfig, RequestedBy: actor(r),
		}
		if err := h.Queue.PublishCollect(job); err == nil {
			h.audit(r, "collect.enqueue", "collector", req.Provider, nil, map[string]any{"account": req.Account, "project": req.Project})
			w.WriteHeader(http.StatusAccepted)
			writeJSON(w, map[string]string{"status": "queued", "provider": req.Provider})
			return
		} else if h.Logger != nil {
			h.Logger.Warn("queue publish failed, running collection in-process", "err", err)
		}
	}

	var coll collectors.Collector
	var account string
	switch req.Provider {
	case "fixture":
		path := req.Fixture
		if path == "" {
			path = "fixtures/demo_env.json"
		}
		coll, account = fixture.New(path), "fixture"
	case "aws":
		region := req.Region
		if region == "" {
			region = "us-east-1"
		}
		coll = awscollector.New(awscollector.Options{RoleARN: req.RoleARN, ExternalID: req.ExternalID, Region: region, CloudTrailLookbackHours: 24}, h.Logger)
		account = orElse(req.Account, "aws")
	case "gcp":
		proj := orElse(req.Project, req.Account)
		if proj == "" {
			http.Error(w, "gcp requires project", http.StatusBadRequest)
			return
		}
		coll = gcpcollector.New(gcpcollector.Options{ProjectID: proj, CredentialsFile: req.GCPCredentials, AuditLookbackHours: 24}, h.Logger)
		account = "gcp:" + proj
	case "repo":
		if req.Report == "" && req.ScanPath == "" {
			http.Error(w, "repo requires a report path or scan path", http.StatusBadRequest)
			return
		}
		coll = repocollector.New(repocollector.Options{ReportPath: req.Report, ScanPath: req.ScanPath, Provider: req.RepoProvider, Repo: req.Repo, Visibility: req.RepoVisibility})
		account = "repo:" + req.Repo
	case "k8s":
		clusterName := orElse(req.Cluster, "default")
		coll = k8scollector.New(k8scollector.Options{ClusterName: clusterName, ExportPath: req.K8sExport, Kubeconfig: req.Kubeconfig}, h.Logger)
		account = "k8s:" + clusterName
	default:
		http.Error(w, "unknown provider (fixture|aws|gcp|k8s|repo)", http.StatusBadRequest)
		return
	}

	h.audit(r, "collect.trigger", "collector", req.Provider, nil, map[string]any{"account": account})

	go func() {
		ctx := context.Background()
		if err := collectors.Run(ctx, h.Store, coll, account, h.Logger); err != nil {
			h.Logger.Error("triggered collection failed", "provider", req.Provider, "err", err)
			return
		}
		if _, err := h.Store.Snapshots.Create(ctx, map[string]any{"provider": req.Provider, "account": account}); err != nil {
			h.Logger.Warn("snapshot create failed", "err", err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]string{"status": "accepted", "provider": req.Provider, "account": account})
}

// ---------- findings: suppress ----------

func (h *Handler) SuppressFinding(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Reason   string `json:"reason"`
		Detector string `json:"detector"`
		Days     int    `json:"expiry_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reason == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}
	f, err := h.Store.Findings.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sup := models.Suppression{Detector: req.Detector, IdentityID: f.IdentityID, Reason: req.Reason, CreatedBy: actor(r)}
	if sup.Detector == "" {
		sup.Detector = f.Detector
	}
	if req.Days > 0 {
		exp := time.Now().Add(time.Duration(req.Days) * 24 * time.Hour)
		sup.ExpiresAt = &exp
	}
	supID, err := h.Store.Suppressions.Create(r.Context(), sup)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// mark the finding suppressed so it leaves the open queue immediately
	_ = h.Store.Findings.UpdateStatus(r.Context(), id, "suppressed", f.Assignee, f.Notes)
	h.audit(r, "finding.suppress", "finding", id.String(),
		map[string]any{"status": f.Status},
		map[string]any{"status": "suppressed", "suppression_id": supID, "reason": req.Reason})
	writeJSON(w, map[string]any{"status": "suppressed", "suppression_id": supID})
}

// ---------- audit ----------

func (h *Handler) ListAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.Audit.List(r.Context(), limitParam(r, 200))
	respondList(w, "audit", rows, err)
}

// ---------- config: risk weights ----------

// effectiveWeights returns the active weights: the DB override if present and valid, else the file.
func (h *Handler) effectiveWeights(ctx context.Context) (*risk.Weights, error) {
	if raw, ok, _ := h.Store.Config.Get(ctx, "risk_weights"); ok {
		if w, err := risk.ParseWeightsJSON(raw); err == nil {
			return w, nil
		}
	}
	return risk.LoadWeights(h.WeightsFile)
}

func (h *Handler) GetRiskWeights(w http.ResponseWriter, r *http.Request) {
	weights, err := h.effectiveWeights(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, weights)
}

func (h *Handler) PutRiskWeights(w http.ResponseWriter, r *http.Request) {
	body, err := readAll(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	weights, err := risk.ParseWeightsJSON(body)
	if err != nil {
		http.Error(w, "invalid weights: "+err.Error(), http.StatusBadRequest)
		return
	}
	normalized, _ := weights.JSON()
	if err := h.Store.Config.Set(r.Context(), "risk_weights", normalized, actor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.audit(r, "config.risk_weights.update", "config", "risk_weights", nil, map[string]any{"weights": weights.Weights})
	writeJSON(w, map[string]any{"status": "updated", "weights": weights})
}

// ---------- helpers ----------

func respondList[T any](w http.ResponseWriter, key string, rows []T, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []T{}
	}
	writeJSON(w, map[string]any{key: rows})
}

func orElse(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	const max = 1 << 20
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) > max {
			return buf[:max], nil
		}
		if err != nil {
			return buf, nil
		}
	}
}
