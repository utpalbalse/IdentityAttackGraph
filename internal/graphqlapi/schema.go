package graphqlapi

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/nhiid/nhiid/internal/graph"
	"github.com/nhiid/nhiid/internal/models"
	"github.com/nhiid/nhiid/internal/store"
)

const maxHops = 6

// ---- per-request graph memoization (load LoadAll once per request, not per field) ----

type gctxKey struct{}

type graphCache struct {
	ds   DataSource
	once sync.Once
	g    *graph.Graph
	err  error
}

func (c *graphCache) get(ctx context.Context) (*graph.Graph, error) {
	c.once.Do(func() { c.g, c.err = c.ds.LoadGraph(ctx) })
	return c.g, c.err
}

func withGraphCache(ctx context.Context, ds DataSource) context.Context {
	return context.WithValue(ctx, gctxKey{}, &graphCache{ds: ds})
}

func graphFrom(ctx context.Context, ds DataSource) (*graph.Graph, error) {
	if c, ok := ctx.Value(gctxKey{}).(*graphCache); ok {
		return c.get(ctx)
	}
	return ds.LoadGraph(ctx)
}

func toIdentity(src any) (models.Identity, bool) {
	switch v := src.(type) {
	case models.Identity:
		return v, true
	case *models.Identity:
		if v != nil {
			return *v, true
		}
	}
	return models.Identity{}, false
}

// NewSchema builds the GraphQL schema bound to a DataSource.
func NewSchema(ds DataSource) (graphql.Schema, error) {
	pathStep := graphql.NewObject(graphql.ObjectConfig{
		Name: "PathStep",
		Fields: graphql.Fields{
			"node":        &graphql.Field{Type: graphql.String, Resolve: field(func(s graph.PathStep) any { return s.Node })},
			"type":        &graphql.Field{Type: graphql.String, Resolve: field(func(s graph.PathStep) any { return s.Type })},
			"via":         &graphql.Field{Type: graphql.String, Resolve: field(func(s graph.PathStep) any { return s.Via })},
			"criticality": &graphql.Field{Type: graphql.String, Resolve: field(func(s graph.PathStep) any { return s.Criticality })},
		},
	})

	attackPath := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPath",
		Fields: graphql.Fields{
			"rank":      &graphql.Field{Type: graphql.Int, Resolve: field(func(p graph.PathView) any { return p.Rank })},
			"impact":    &graphql.Field{Type: graphql.String, Resolve: field(func(p graph.PathView) any { return p.Impact })},
			"hops":      &graphql.Field{Type: graphql.Int, Resolve: field(func(p graph.PathView) any { return p.Hops })},
			"narrative": &graphql.Field{Type: graphql.String, Resolve: field(func(p graph.PathView) any { return p.Narrative })},
			"steps":     &graphql.Field{Type: graphql.NewList(pathStep), Resolve: field(func(p graph.PathView) any { return p.Steps })},
		},
	})

	blastRadius := graphql.NewObject(graphql.ObjectConfig{
		Name: "BlastRadius",
		Fields: graphql.Fields{
			"reachableResources": &graphql.Field{Type: graphql.Int, Resolve: field(func(b graph.BlastRadius) any { return b.ReachableResources })},
			"highCritCount":      &graphql.Field{Type: graphql.Int, Resolve: field(func(b graph.BlastRadius) any { return b.HighCritCount })},
			"crownJewelCount":    &graphql.Field{Type: graphql.Int, Resolve: field(func(b graph.BlastRadius) any { return b.CrownJewelCount })},
			"nearestCrownJewel":  &graphql.Field{Type: graphql.Int, Resolve: field(func(b graph.BlastRadius) any { return b.NearestCrownJewel })},
			"reachesAdmin":       &graphql.Field{Type: graphql.Boolean, Resolve: field(func(b graph.BlastRadius) any { return b.ReachesAdmin })},
		},
	})

	finding := graphql.NewObject(graphql.ObjectConfig{
		Name: "Finding",
		Fields: graphql.Fields{
			"detector":   &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return f.Detector })},
			"category":   &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return f.Category })},
			"severity":   &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return string(f.Severity) })},
			"confidence": &graphql.Field{Type: graphql.Int, Resolve: ffield(func(f models.Finding) any { return f.Confidence })},
			"title":      &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return f.Title })},
			"narrative":  &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return f.Narrative })},
			"status":     &graphql.Field{Type: graphql.String, Resolve: ffield(func(f models.Finding) any { return f.Status })},
		},
	})

	identity := graphql.NewObject(graphql.ObjectConfig{Name: "Identity", Fields: graphql.Fields{}})
	identity.AddFieldConfig("id", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return i.ID.String() })})
	identity.AddFieldConfig("name", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return i.Name })})
	identity.AddFieldConfig("kind", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return string(i.Kind) })})
	identity.AddFieldConfig("provider", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return i.Provider })})
	identity.AddFieldConfig("account", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return i.Prov.AccountRef })})
	identity.AddFieldConfig("state", &graphql.Field{Type: graphql.String, Resolve: ifield(func(i models.Identity) any { return i.State })})
	identity.AddFieldConfig("riskScore", &graphql.Field{Type: graphql.Int, Resolve: ifield(func(i models.Identity) any { return i.RiskScore })})
	identity.AddFieldConfig("isAIAgent", &graphql.Field{Type: graphql.Boolean, Resolve: ifield(func(i models.Identity) any { return i.IsAIAgent })})
	identity.AddFieldConfig("findings", &graphql.Field{
		Type: graphql.NewList(finding),
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, ok := toIdentity(p.Source)
			if !ok {
				return nil, nil
			}
			eid := id.ID
			return ds.ListFindings(p.Context, store.FindingFilter{IdentityID: &eid, Limit: 200})
		},
	})
	identity.AddFieldConfig("attackPaths", &graphql.Field{
		Type: graphql.NewList(attackPath),
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, ok := toIdentity(p.Source)
			if !ok {
				return nil, nil
			}
			g, err := graphFrom(p.Context, ds)
			if err != nil {
				return nil, err
			}
			if nid, ok := g.NodeIDForEntity(id.ID); ok {
				return g.Explain(g.AttackPaths(nid, maxHops, 8)), nil
			}
			return []graph.PathView{}, nil
		},
	})
	identity.AddFieldConfig("blastRadius", &graphql.Field{
		Type: blastRadius,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, ok := toIdentity(p.Source)
			if !ok {
				return nil, nil
			}
			g, err := graphFrom(p.Context, ds)
			if err != nil {
				return nil, err
			}
			if nid, ok := g.NodeIDForEntity(id.ID); ok {
				return g.ComputeBlastRadius(nid, maxHops), nil
			}
			return graph.BlastRadius{NearestCrownJewel: -1}, nil
		},
	})

	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"identities": &graphql.Field{
				Type: graphql.NewList(identity),
				Args: graphql.FieldConfigArgument{
					"provider": &graphql.ArgumentConfig{Type: graphql.String},
					"kind":     &graphql.ArgumentConfig{Type: graphql.String},
					"minRisk":  &graphql.ArgumentConfig{Type: graphql.Int},
					"limit":    &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 50},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return ds.ListIdentities(p.Context, store.IdentityFilter{
						Provider: argStr(p, "provider"), Kind: argStr(p, "kind"),
						MinRisk: argInt(p, "minRisk"), Limit: argInt(p, "limit"),
					})
				},
			},
			"identity": &graphql.Field{
				Type: identity,
				Args: graphql.FieldConfigArgument{"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)}},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					id, err := uuid.Parse(argStr(p, "id"))
					if err != nil {
						return nil, err
					}
					return ds.GetIdentity(p.Context, id)
				},
			},
			"findings": &graphql.Field{
				Type: graphql.NewList(finding),
				Args: graphql.FieldConfigArgument{
					"severity": &graphql.ArgumentConfig{Type: graphql.String},
					"status":   &graphql.ArgumentConfig{Type: graphql.String},
					"detector": &graphql.ArgumentConfig{Type: graphql.String},
					"limit":    &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 100},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return ds.ListFindings(p.Context, store.FindingFilter{
						Severity: argStr(p, "severity"), Status: argStr(p, "status"),
						Detector: argStr(p, "detector"), Limit: argInt(p, "limit"),
					})
				},
			},
			"triage": &graphql.Field{
				Type: graphql.NewList(identity),
				Args: graphql.FieldConfigArgument{"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 25}},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return ds.TriageQueue(p.Context, argInt(p, "limit"))
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{Query: query})
}

// ---- small resolver helpers ----

func ifield(get func(models.Identity) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		if i, ok := toIdentity(p.Source); ok {
			return get(i), nil
		}
		return nil, nil
	}
}

func ffield(get func(models.Finding) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		switch v := p.Source.(type) {
		case models.Finding:
			return get(v), nil
		case *models.Finding:
			if v != nil {
				return get(*v), nil
			}
		}
		return nil, nil
	}
}

func field[T any](get func(T) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		if v, ok := p.Source.(T); ok {
			return get(v), nil
		}
		return nil, nil
	}
}

func argStr(p graphql.ResolveParams, name string) string {
	if v, ok := p.Args[name].(string); ok {
		return v
	}
	return ""
}

func argInt(p graphql.ResolveParams, name string) int {
	if v, ok := p.Args[name].(int); ok {
		return v
	}
	return 0
}
