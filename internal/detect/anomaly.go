package detect

import (
	"fmt"
	"math"
	"net"
	"time"

	"github.com/nhiid/nhiid/internal/models"
)

// egressAllowed reports whether ip falls within any allowlisted CIDR (known VPN/egress ranges).
func egressAllowed(ip string, cidrs []string) bool {
	if ip == "" || len(cidrs) == 0 {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(p) {
			return true
		}
	}
	return false
}

// filterEgress drops events from allowlisted egress/VPN ranges so they don't trip geo/ASN anomalies
// (a documented false-positive control). Returns the input unchanged when no allowlist is set.
func filterEgress(evs []models.UsageEvent, cidrs []string) []models.UsageEvent {
	if len(cidrs) == 0 {
		return evs
	}
	out := make([]models.UsageEvent, 0, len(evs))
	for _, e := range evs {
		if !egressAllowed(e.SrcIP, cidrs) {
			out = append(out, e)
		}
	}
	return out
}

// ---- impossible_travel -------------------------------------------------------

type impossibleTravel struct{}

func (impossibleTravel) ID() string { return "impossible_travel" }
func (impossibleTravel) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	usage := filterEgress(s.Usage, cfg.EgressAllowlist)
	if len(usage) < 2 || len(usage) < cfg.AnomalyWarmupEvents/5 {
		return nil
	}
	events := usageWithGeo(usage)
	for i := 1; i < len(events); i++ {
		a, b := events[i-1], events[i]
		if a.SrcCountry == "" || b.SrcCountry == "" || a.SrcCountry == b.SrcCountry {
			continue
		}
		dt := b.EventTime.Sub(a.EventTime).Hours()
		if dt <= 0 {
			continue
		}
		dist := approxDistKM(a.SrcCountry, b.SrcCountry)
		if dist <= 0 {
			continue
		}
		speed := dist / dt
		if speed > cfg.ImpossibleTravelKMH {
			ev := map[string]any{
				"event_a":     map[string]any{"time": a.EventTime, "country": a.SrcCountry, "ip": a.SrcIP},
				"event_b":     map[string]any{"time": b.EventTime, "country": b.SrcCountry, "ip": b.SrcIP},
				"distance_km": dist, "elapsed_hours": dt, "implied_kmh": speed,
			}
			narr := fmt.Sprintf("Identity %q authenticated from %s then %s in %.1f hours (%.0f km, %.0f km/h) — impossible travel.",
				s.Identity.Name, a.SrcCountry, b.SrcCountry, dt, dist, speed)
			return []models.Finding{finding(s, "impossible_travel", "anomaly", models.SevHigh, 82,
				"Impossible travel detected", narr, ev,
				a.SrcCountry, b.SrcCountry)}
		}
	}
	return nil
}

// ---- unusual_geo / new_region -----------------------------------------------

type unusualGeo struct{}

func (unusualGeo) ID() string { return "unusual_geo" }
func (unusualGeo) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	usage := filterEgress(s.Usage, cfg.EgressAllowlist)
	if len(usage) < cfg.AnomalyWarmupEvents {
		return nil
	}
	baseline := baselineCountries(usage[:len(usage)-1])
	recent := usage[len(usage)-1]
	if recent.SrcCountry == "" || baseline[recent.SrcCountry] {
		return nil
	}
	ev := map[string]any{
		"new_country": recent.SrcCountry, "known_countries": keys(baseline),
		"event_time": recent.EventTime, "src_ip": recent.SrcIP,
	}
	narr := fmt.Sprintf("Identity %q was used from %s for the first time (baseline: %v).",
		s.Identity.Name, recent.SrcCountry, keys(baseline))
	return []models.Finding{finding(s, "unusual_geo", "anomaly", models.SevMedium, 65,
		"First use from new country", narr, ev, recent.SrcCountry)}
}

// ---- new_asn_or_runtime -----------------------------------------------------

type newASNOrRuntime struct{}

func (newASNOrRuntime) ID() string { return "new_asn_or_runtime" }
func (newASNOrRuntime) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	usage := filterEgress(s.Usage, cfg.EgressAllowlist)
	if len(usage) < cfg.AnomalyWarmupEvents {
		return nil
	}
	hist := usage[:len(usage)-1]
	cur := usage[len(usage)-1]
	baseASN := map[int]bool{}
	baseRT := map[string]bool{}
	for _, e := range hist {
		baseASN[e.SrcASN] = true
		if e.Runtime != "" {
			baseRT[e.Runtime] = true
		}
	}
	var signals []string
	if cur.SrcASN != 0 && !baseASN[cur.SrcASN] {
		signals = append(signals, fmt.Sprintf("new_asn:%d", cur.SrcASN))
	}
	if cur.Runtime != "" && !baseRT[cur.Runtime] {
		signals = append(signals, "new_runtime:"+cur.Runtime)
	}
	if len(signals) == 0 {
		return nil
	}
	ev := map[string]any{"signals": signals, "event_time": cur.EventTime, "src_ip": cur.SrcIP}
	narr := fmt.Sprintf("Identity %q accessed from unrecognised ASN/runtime: %v.", s.Identity.Name, signals)
	return []models.Finding{finding(s, "new_asn_or_runtime", "anomaly", models.SevLow, 55,
		"New ASN or runtime observed", narr, ev, signals...)}
}

// ---- usage_spike ------------------------------------------------------------

type usageSpike struct{}

func (usageSpike) ID() string { return "usage_spike" }
func (usageSpike) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	if len(s.Usage) < cfg.AnomalyWarmupEvents {
		return nil
	}
	// Split into hourly buckets over last 30 days.
	buckets := hourlyBuckets(s.Usage, 30*24)
	if len(buckets) < 24 {
		return nil
	}
	latest := buckets[len(buckets)-1]
	hist := buckets[:len(buckets)-1]
	mean, sigma := meanSigma(hist)
	if sigma == 0 || float64(latest) < mean+cfg.UsageSpikeSigma*sigma {
		return nil
	}
	ev := map[string]any{
		"bucket_count": latest, "baseline_mean": mean, "baseline_sigma": sigma,
		"z_score": (float64(latest) - mean) / sigma,
	}
	narr := fmt.Sprintf("Identity %q produced %.0f events in the latest hour (mean %.1f, σ %.1f) — %.1fσ spike.",
		s.Identity.Name, float64(latest), mean, sigma, (float64(latest)-mean)/sigma)
	return []models.Finding{finding(s, "usage_spike", "anomaly", models.SevMedium, 70,
		"Anomalous usage volume spike", narr, ev)}
}

// ---- first_use_sensitive_action --------------------------------------------

type firstUseSensitive struct{}

var sensitiveActions = map[string]bool{
	"iam:CreateUser": true, "iam:AttachRolePolicy": true, "iam:PassRole": true,
	"iam:CreatePolicyVersion": true, "sts:AssumeRole": true,
	"kms:Decrypt": true, "secretsmanager:GetSecretValue": true,
	"iam:CreateAccessKey": true, "organizations:*": true,
}

func (firstUseSensitive) ID() string { return "first_use_sensitive_action" }
func (firstUseSensitive) Detect(s Subject, cfg Config, now time.Time) []models.Finding {
	if len(s.Usage) < 2 {
		return nil
	}
	seenBefore := map[string]bool{}
	for _, e := range s.Usage[:len(s.Usage)-1] {
		seenBefore[e.EventName] = true
	}
	cur := s.Usage[len(s.Usage)-1]
	if !sensitiveActions[cur.EventName] || seenBefore[cur.EventName] {
		return nil
	}
	ev := map[string]any{"action": cur.EventName, "event_time": cur.EventTime, "src_ip": cur.SrcIP, "region": cur.SrcRegion}
	narr := fmt.Sprintf("Identity %q invoked sensitive action %q for the first time. "+
		"First-time sensitive-action use often marks the pivot point in an intrusion.",
		s.Identity.Name, cur.EventName)
	return []models.Finding{finding(s, "first_use_sensitive_action", "anomaly", models.SevHigh, 78,
		"First use of sensitive action", narr, ev, cur.EventName)}
}

// ---- privilege_creep --------------------------------------------------------

type privilegeCreep struct{}

func (privilegeCreep) ID() string { return "privilege_creep" }
func (privilegeCreep) Detect(s Subject, _ Config, now time.Time) []models.Finding {
	if s.PeerPermissionP90 == 0 {
		return nil
	}
	total := 0
	for _, r := range s.Roles {
		total += r.PermissionCount
	}
	if total <= s.PeerPermissionP90 {
		return nil
	}
	ev := map[string]any{
		"permission_count": total, "peer_p90": s.PeerPermissionP90,
		"excess": total - s.PeerPermissionP90,
	}
	narr := fmt.Sprintf("Identity %q has %d permissions, exceeding the peer-group P90 of %d. "+
		"Permissions were likely granted over time without commensurate review.",
		s.Identity.Name, total, s.PeerPermissionP90)
	return []models.Finding{finding(s, "privilege_creep", "privilege", models.SevMedium, 65,
		"Privilege creep beyond peer baseline", narr, ev)}
}

// ---- helpers ----------------------------------------------------------------

func usageWithGeo(evs []models.UsageEvent) []models.UsageEvent {
	var out []models.UsageEvent
	for _, e := range evs {
		if e.SrcCountry != "" {
			out = append(out, e)
		}
	}
	return out
}

func baselineCountries(evs []models.UsageEvent) map[string]bool {
	m := map[string]bool{}
	for _, e := range evs {
		if e.SrcCountry != "" {
			m[e.SrcCountry] = true
		}
	}
	return m
}

// approxDistKM returns a very rough inter-country distance using hardcoded centroids for the
// most common countries. Unknown pairs return 0 (suppresses the check). A production
// implementation would use a full geo-IP database.
func approxDistKM(a, b string) float64 {
	centroids := map[string][2]float64{
		"US": {37.09, -95.71}, "GB": {55.38, -3.44}, "DE": {51.17, 10.45},
		"CN": {35.86, 104.19}, "RU": {61.52, 105.32}, "IN": {20.59, 78.96},
		"BR": {-14.24, -51.93}, "AU": {-25.27, 133.77}, "JP": {36.20, 138.25},
		"FR": {46.23, 2.21}, "CA": {56.13, -106.35}, "NG": {9.08, 8.67},
		"ZA": {-30.56, 22.94}, "SG": {1.35, 103.82}, "KR": {35.91, 127.77},
	}
	ca, okA := centroids[a]
	cb, okB := centroids[b]
	if !okA || !okB {
		return 0
	}
	return haversineKM(ca[0], ca[1], cb[0], cb[1])
}

func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func hourlyBuckets(evs []models.UsageEvent, hours int) []int {
	if len(evs) == 0 {
		return nil
	}
	end := evs[len(evs)-1].EventTime.Truncate(time.Hour).Add(time.Hour)
	buckets := make(map[time.Time]int)
	for _, e := range evs {
		h := e.EventTime.Truncate(time.Hour)
		buckets[h]++
	}
	out := make([]int, hours)
	for i := range out {
		t := end.Add(-time.Duration(hours-i) * time.Hour)
		out[i] = buckets[t]
	}
	return out
}

func meanSigma(vals []int) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += float64(v)
	}
	mean := sum / float64(len(vals))
	var variance float64
	for _, v := range vals {
		d := float64(v) - mean
		variance += d * d
	}
	return mean, math.Sqrt(variance / float64(len(vals)))
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
