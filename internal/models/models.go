// Package models defines NHIID's unified domain schema — the canonical, provider-agnostic
// representation that every collector normalizes into. These types mirror the SQL in
// migrations/0001_init.sql and are documented in docs/DATA_MODEL.md.
package models

import (
	"time"

	"github.com/google/uuid"
)

// ----- enums (kept as typed strings for cheap JSON/SQL round-tripping) -----

type IdentityKind string

const (
	KindAWSIAMUser       IdentityKind = "aws_iam_user"
	KindAWSIAMRole       IdentityKind = "aws_iam_role"
	KindAWSSTSSession    IdentityKind = "aws_sts_session"
	KindGCPServiceAcct   IdentityKind = "gcp_service_account"
	KindK8sServiceAcct   IdentityKind = "k8s_service_account"
	KindWorkloadIdentity IdentityKind = "workload_identity"
	KindAPIClient        IdentityKind = "api_client"
	KindAIAgent          IdentityKind = "ai_agent"
	KindOther            IdentityKind = "other"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Criticality string

const (
	CritLow        Criticality = "low"
	CritMedium     Criticality = "medium"
	CritHigh       Criticality = "high"
	CritCrownJewel Criticality = "crown_jewel"
)

// CriticalityRank gives an orderable weight for rollups.
func CriticalityRank(c Criticality) int {
	switch c {
	case CritCrownJewel:
		return 3
	case CritHigh:
		return 2
	case CritMedium:
		return 1
	default:
		return 0
	}
}

// Provenance is embedded into every collected entity. Source-of-truth metadata.
type Provenance struct {
	Source         string     `json:"source"`
	ExternalID     string     `json:"external_id"`
	AccountRef     string     `json:"account_ref"`
	CollectorRunID *uuid.UUID `json:"collector_run_id,omitempty"`
	CollectedAt    *time.Time `json:"collected_at,omitempty"`
	RawHash        string     `json:"raw_hash,omitempty"`
}

// ----- core entities -----

type Identity struct {
	ID              uuid.UUID              `json:"id"`
	Kind            IdentityKind           `json:"kind"`
	Name            string                 `json:"name"`
	ARNOrEmail      string                 `json:"arn_or_email"`
	Provider        string                 `json:"provider"`
	State           string                 `json:"state"`
	OwnerID         *uuid.UUID             `json:"owner_id,omitempty"`
	CreatedAtSource *time.Time             `json:"created_at_source,omitempty"`
	LastSeenAt      *time.Time             `json:"last_seen_at,omitempty"`
	LastRotatedAt   *time.Time             `json:"last_rotated_at,omitempty"`
	IsAIAgent       bool                   `json:"is_ai_agent"`
	AIAgentMeta     map[string]any         `json:"ai_agent_meta,omitempty"`
	RiskScore       int                    `json:"risk_score"`
	RiskBreakdown   map[string]any         `json:"risk_breakdown,omitempty"`
	Attributes      map[string]any         `json:"attributes,omitempty"`
	Prov            Provenance             `json:"provenance"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type Credential struct {
	ID              uuid.UUID  `json:"id"`
	IdentityID      uuid.UUID  `json:"identity_id"`
	CredType        string     `json:"cred_type"`
	ExternalID      string     `json:"external_id"` // AccessKeyId / fingerprint — never the secret
	Status          string     `json:"status"`
	CreatedAtSource *time.Time `json:"created_at_source,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	LastUsedRegion  string     `json:"last_used_region,omitempty"`
	LastUsedService string     `json:"last_used_service,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	AccountRef      string     `json:"account_ref"`
	Source          string     `json:"source"`
}

type Secret struct {
	ID                  uuid.UUID  `json:"id"`
	Store               string     `json:"store"`
	ExternalID          string     `json:"external_id"`
	AccountRef          string     `json:"account_ref"`
	Name                string     `json:"name"`
	LastRotatedAt       *time.Time `json:"last_rotated_at,omitempty"`
	RotationEnabled     bool       `json:"rotation_enabled"`
	VersionCount        int        `json:"version_count"`
	MaterialFingerprint string     `json:"material_fingerprint,omitempty"`
	ReferencedByCount   int        `json:"referenced_by_count"`
	LastAccessedAt      *time.Time `json:"last_accessed_at,omitempty"`
	Source              string     `json:"source"`
}

type Role struct {
	ID                    uuid.UUID      `json:"id"`
	Provider              string         `json:"provider"`
	ExternalID            string         `json:"external_id"`
	AccountRef            string         `json:"account_ref"`
	Name                  string         `json:"name"`
	PolicyDocument        map[string]any `json:"policy_document,omitempty"`
	TrustPolicy           map[string]any `json:"trust_policy,omitempty"`
	PrivilegeLevel        string         `json:"privilege_level"`
	IsAssumable           bool           `json:"is_assumable"`
	PermissionCount       int            `json:"permission_count"`
	WildcardActionCount   int            `json:"wildcard_action_count"`
	WildcardResourceCount int            `json:"wildcard_resource_count"`
	Source                string         `json:"source"`
}

type TrustEdge struct {
	ID            uuid.UUID      `json:"id"`
	SrcIdentityID *uuid.UUID     `json:"src_identity_id,omitempty"`
	SrcRoleID     *uuid.UUID     `json:"src_role_id,omitempty"`
	DstIdentityID *uuid.UUID     `json:"dst_identity_id,omitempty"`
	DstRoleID     *uuid.UUID     `json:"dst_role_id,omitempty"`
	EdgeType      string         `json:"edge_type"`
	Condition     map[string]any `json:"condition,omitempty"`
	Observed      bool           `json:"observed"`
	AccountRef    string         `json:"account_ref"`
	Source        string         `json:"source"`
}

type ResourceBinding struct {
	ID                  uuid.UUID   `json:"id"`
	IdentityID          *uuid.UUID  `json:"identity_id,omitempty"`
	RoleID              *uuid.UUID  `json:"role_id,omitempty"`
	ResourceURN         string      `json:"resource_urn"`
	ResourceKind        string      `json:"resource_kind"`
	ResourceCriticality Criticality `json:"resource_criticality"`
	Actions             []string    `json:"actions"`
	Effect              string      `json:"effect"`
	AccountRef          string      `json:"account_ref"`
	Source              string      `json:"source"`
}

type Workload struct {
	ID          uuid.UUID      `json:"id"`
	Kind        string         `json:"kind"`
	ExternalID  string         `json:"external_id"`
	AccountRef  string         `json:"account_ref"`
	Name        string         `json:"name"`
	Environment string         `json:"environment"`
	IdentityID  *uuid.UUID     `json:"identity_id,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Source      string         `json:"source"`
}

type Repository struct {
	ID            uuid.UUID  `json:"id"`
	Provider      string     `json:"provider"`
	ExternalID    string     `json:"external_id"`
	Org           string     `json:"org"`
	Name          string     `json:"name"`
	Visibility    string     `json:"visibility"`
	DefaultBranch string     `json:"default_branch"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	Source        string     `json:"source"`
}

// Exposure records WHERE credential material was found — never the material itself.
type Exposure struct {
	ID           uuid.UUID  `json:"id"`
	RepositoryID *uuid.UUID `json:"repository_id,omitempty"`
	IdentityID   *uuid.UUID `json:"identity_id,omitempty"`
	SecretID     *uuid.UUID `json:"secret_id,omitempty"`
	Path         string     `json:"path"`
	CommitSHA    string     `json:"commit_sha"`
	Line         int        `json:"line"`
	Pattern      string     `json:"pattern"`
	Fingerprint  string     `json:"fingerprint"`
	Verified     bool       `json:"verified"`
	Source       string     `json:"source"`
}

type UsageEvent struct {
	ID           uuid.UUID `json:"id"`
	IdentityID   uuid.UUID `json:"identity_id"`
	EventTime    time.Time `json:"event_time"`
	EventName    string    `json:"event_name"`
	EventSource  string    `json:"event_source"`
	SrcIP        string    `json:"src_ip,omitempty"`
	SrcASN       int       `json:"src_asn,omitempty"`
	SrcRegion    string    `json:"src_region,omitempty"`
	SrcCountry   string    `json:"src_country,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Runtime      string    `json:"runtime,omitempty"`
	MFAUsed      bool      `json:"mfa_used"`
	ErrorCode    string    `json:"error_code,omitempty"`
	AccountRef   string    `json:"account_ref"`
	Source       string    `json:"source"`
}

type Owner struct {
	ID          uuid.UUID `json:"id"`
	Kind        string    `json:"kind"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Source      string    `json:"source"`
}

type Finding struct {
	ID               uuid.UUID      `json:"id"`
	Detector         string         `json:"detector"`
	Category         string         `json:"category"`
	Severity         Severity       `json:"severity"`
	Confidence       int            `json:"confidence"`
	IdentityID       *uuid.UUID     `json:"identity_id,omitempty"`
	Title            string         `json:"title"`
	Narrative        string         `json:"narrative"`
	Evidence         map[string]any `json:"evidence"`
	Fingerprint      string         `json:"fingerprint"`
	Status           string         `json:"status"`
	RiskContribution int            `json:"risk_contribution"`
	Assignee         string         `json:"assignee,omitempty"`
	Notes            string         `json:"notes,omitempty"`
	FirstSeenAt      time.Time      `json:"first_seen_at"`
	LastSeenAt       time.Time      `json:"last_seen_at"`
}

type RemediationAction struct {
	ID         uuid.UUID `json:"id"`
	FindingID  uuid.UUID `json:"finding_id"`
	Action     string    `json:"action"`
	Status     string    `json:"status"`
	RiskBefore int       `json:"risk_before"`
	RiskAfter  int       `json:"risk_after"`
	RiskDelta  int       `json:"risk_delta"`
	Assignee   string    `json:"assignee,omitempty"`
	Notes      string    `json:"notes,omitempty"`
}

// CollectorRun records provenance + outcome of one collection pass.
type CollectorRun struct {
	ID              uuid.UUID  `json:"id"`
	Collector       string     `json:"collector"`
	AccountRef      string     `json:"account_ref"`
	RecordsIn       int        `json:"records_in"`
	RecordsUpserted int        `json:"records_upserted"`
	Errors          int        `json:"errors"`
	Status          string     `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}

// ----- graph projection -----

type GraphNode struct {
	ID          uuid.UUID      `json:"id"`
	NodeType    string         `json:"node_type"`
	EntityID    *uuid.UUID     `json:"entity_id,omitempty"`
	AccountRef  string         `json:"account_ref"`
	Label       string         `json:"label"`
	Criticality Criticality    `json:"criticality"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

type GraphEdge struct {
	ID         uuid.UUID      `json:"id"`
	SrcNodeID  uuid.UUID      `json:"src_node_id"`
	DstNodeID  uuid.UUID      `json:"dst_node_id"`
	EdgeType   string         `json:"edge_type"`
	Weight     float64        `json:"weight"`
	Observed   bool           `json:"observed"`
	Attributes map[string]any `json:"attributes,omitempty"`
}
