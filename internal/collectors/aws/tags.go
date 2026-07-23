package aws

import (
	"context"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rgt "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	rgttypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/nhiid/nhiid/internal/models"
)

// DefaultCriticalityTagKey is the resource tag whose value declares a resource's criticality.
// Criticality is a business judgement AWS itself cannot infer (an IAM policy cannot tell that
// prod-billing matters more than dev-scratch), so it is supplied out-of-band via this tag.
const DefaultCriticalityTagKey = "nhiid:criticality"

// critResolver maps AWS resource ARNs that carry a criticality tag to their declared criticality,
// and elevates a policy binding's criticality when the binding can actually act on such a resource.
// A nil *critResolver is valid and elevates nothing, so callers with no tag data (tests, degraded
// collection) need no special-casing.
type critResolver struct {
	// tagged maps a canonical resource ARN to the criticality its tag declares.
	tagged map[string]models.Criticality
}

func newCritResolver() *critResolver {
	return &critResolver{tagged: map[string]models.Criticality{}}
}

// set records a tagged resource, keeping the highest criticality if an ARN is seen twice.
func (r *critResolver) set(arn string, c models.Criticality) {
	if arn == "" {
		return
	}
	if cur, ok := r.tagged[arn]; !ok || models.CriticalityRank(c) > models.CriticalityRank(cur) {
		r.tagged[arn] = c
	}
}

func (r *critResolver) len() int {
	if r == nil {
		return 0
	}
	return len(r.tagged)
}

// criticalityFor returns the highest tag-declared criticality that a binding over `resourceURN`
// with `actions` can reach, or CritLow if none. Both a resource match and an action-that-applies-to
// that resource's service are required, so an ec2 action on Resource "*" is not elevated merely
// because some unrelated S3 bucket is tagged.
func (r *critResolver) criticalityFor(resourceURN string, actions []string) models.Criticality {
	if r.len() == 0 {
		return models.CritLow
	}
	best := models.CritLow
	for arn, crit := range r.tagged {
		if models.CriticalityRank(crit) <= models.CriticalityRank(best) {
			continue
		}
		if !actionsCoverService(actions, serviceOfARN(arn)) {
			continue
		}
		if resourceReaches(resourceURN, arn) {
			best = crit
		}
	}
	return best
}

// criticalityFromTag parses a tag value into a criticality. Several spellings of the top level are
// accepted because operators write it differently; the ranked levels can all be set explicitly.
func criticalityFromTag(v string) (models.Criticality, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "crown_jewel", "crown-jewel", "crownjewel", "crown", "critical":
		return models.CritCrownJewel, true
	case "high":
		return models.CritHigh, true
	case "medium", "med":
		return models.CritMedium, true
	case "low":
		return models.CritLow, true
	}
	return "", false
}

// resourceReaches reports whether an IAM policy Resource pattern covers a tagged resource ARN.
// It matches under IAM wildcard semantics (`*`, `?`) and additionally treats a tagged parent
// resource as reached when the policy targets children under it (e.g. a tagged bucket
// arn:aws:s3:::prod-billing when a policy grants access to arn:aws:s3:::prod-billing/*).
func resourceReaches(policyResource, taggedARN string) bool {
	if policyResource == "" || taggedARN == "" {
		return false
	}
	if globMatch(policyResource, taggedARN) {
		return true
	}
	// Parent tagged, policy scoped to children: compare the policy pattern's literal prefix.
	lit := policyResource
	if i := strings.IndexAny(lit, "*?"); i >= 0 {
		lit = lit[:i]
	}
	return lit != "" && strings.HasPrefix(lit, taggedARN+"/")
}

// serviceOfARN extracts the service field from an ARN (arn:partition:service:...). "*" matches any.
func serviceOfARN(arn string) string {
	if arn == "*" {
		return "*"
	}
	p := strings.SplitN(arn, ":", 4)
	if len(p) >= 3 {
		return strings.ToLower(p[2])
	}
	return ""
}

// actionsCoverService reports whether any action could act on the given service. An unknown service
// ("") is not used to exclude a match. A full "*"/"*:*" action, or one in the same service, counts.
func actionsCoverService(actions []string, svc string) bool {
	if svc == "" || svc == "*" {
		return true
	}
	for _, a := range actions {
		la := strings.ToLower(a)
		if la == "*" || la == "*:*" {
			return true
		}
		if serviceOf(la) == svc {
			return true
		}
	}
	return false
}

// globMatch reports whether s matches an IAM-style pattern where `*` matches any run of characters
// and `?` matches exactly one. Iterative with backtracking; no regexp compilation per call.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == s[sx] || pattern[px] == '?'):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, sx
			px++
		case star != -1:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// collectResourceTags queries the Resource Groups Tagging API for every resource carrying the
// criticality tag and builds a resolver from the results. It is read-only (tag:GetResources) and,
// like the CloudTrail and Secrets Manager phases, non-fatal to the caller: a missing permission
// degrades to action-inferred criticality rather than failing collection.
func (c *clients) collectResourceTags(ctx context.Context, tagKey string) (*critResolver, error) {
	res := newCritResolver()
	if tagKey == "" || c.tagging == nil {
		return res, nil
	}
	p := rgt.NewGetResourcesPaginator(c.tagging, &rgt.GetResourcesInput{
		TagFilters: []rgttypes.TagFilter{{Key: awssdk.String(tagKey)}},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return res, err
		}
		for _, m := range page.ResourceTagMappingList {
			arn := awssdk.ToString(m.ResourceARN)
			for _, t := range m.Tags {
				if !strings.EqualFold(awssdk.ToString(t.Key), tagKey) {
					continue
				}
				if crit, ok := criticalityFromTag(awssdk.ToString(t.Value)); ok {
					res.set(arn, crit)
				}
			}
		}
	}
	return res, nil
}
