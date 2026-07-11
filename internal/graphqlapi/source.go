// Package graphqlapi exposes the read surface (inventory, findings, attack paths, blast radius) over
// GraphQL, complementing the REST API. It resolves against a DataSource so the schema is unit-
// testable without a database; StoreSource is the production adapter over the pgx store.
package graphqlapi

import (
	"context"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/store"
)

// DataSource is the minimal data access the GraphQL resolvers need.
type DataSource interface {
	ListIdentities(ctx context.Context, f store.IdentityFilter) ([]models.Identity, error)
	GetIdentity(ctx context.Context, id uuid.UUID) (*models.Identity, error)
	ListFindings(ctx context.Context, f store.FindingFilter) ([]models.Finding, error)
	TriageQueue(ctx context.Context, limit int) ([]models.Identity, error)
	LoadGraph(ctx context.Context) (*graph.Graph, error)
}

// StoreSource adapts the pgx store to DataSource.
type StoreSource struct{ S *store.Store }

func (a StoreSource) ListIdentities(ctx context.Context, f store.IdentityFilter) ([]models.Identity, error) {
	return a.S.Identities.List(ctx, f)
}
func (a StoreSource) GetIdentity(ctx context.Context, id uuid.UUID) (*models.Identity, error) {
	return a.S.Identities.Get(ctx, id)
}
func (a StoreSource) ListFindings(ctx context.Context, f store.FindingFilter) ([]models.Finding, error) {
	return a.S.Findings.List(ctx, f)
}
func (a StoreSource) TriageQueue(ctx context.Context, limit int) ([]models.Identity, error) {
	return a.S.Identities.TriageQueue(ctx, limit)
}
func (a StoreSource) LoadGraph(ctx context.Context) (*graph.Graph, error) {
	nodes, edges, err := a.S.Graph.LoadAll(ctx)
	if err != nil {
		return nil, err
	}
	return graph.FromModels(nodes, edges), nil
}
