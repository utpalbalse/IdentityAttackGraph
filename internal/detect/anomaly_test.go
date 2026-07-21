package detect

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nhiid/nhiid/internal/models"
)

var anomalyBase = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// usageSubject builds a subject whose usage window is ascending by time, as the worker supplies it.
func usageSubject(evs ...models.UsageEvent) Subject {
	return Subject{
		Identity: models.Identity{ID: uuid.New(), Name: "svc-billing-export", State: "active"},
		Usage:    evs,
	}
}

// ---- unusual_geo -------------------------------------------------------------

func TestUnusualGeoFiresOnFirstSightingOfANewCountry(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(3 * time.Hour), SrcCountry: "RU"},
	)
	cfg := Config{AnomalyWarmupEvents: 3}

	f := onlyFinding(t, unusualGeo{}.Detect(s, cfg, ruleNow))
	if f.Severity != models.SevMedium || f.Detector != "unusual_geo" {
		t.Errorf("got %s/%s, want unusual_geo/medium", f.Detector, f.Severity)
	}
	if f.Evidence["new_country"] != "RU" {
		t.Errorf("evidence new_country = %v, want RU", f.Evidence["new_country"])
	}
}

func TestUnusualGeoQuietForKnownCountry(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcCountry: "DE"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(3 * time.Hour), SrcCountry: "DE"},
	)
	if fs := (unusualGeo{}).Detect(s, Config{AnomalyWarmupEvents: 3}, ruleNow); len(fs) != 0 {
		t.Errorf("a country already in the baseline should not fire, got %d", len(fs))
	}
}

// TestUnusualGeoRespectsWarmup covers the documented cold-start control: with too little history
// every country looks new, so the detector must stay silent.
func TestUnusualGeoRespectsWarmup(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcCountry: "US"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcCountry: "RU"},
	)
	if fs := (unusualGeo{}).Detect(s, Config{AnomalyWarmupEvents: 10}, ruleNow); len(fs) != 0 {
		t.Errorf("below the warm-up threshold nothing should fire, got %d", len(fs))
	}
}

func TestUnusualGeoRespectsEgressAllowlist(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcCountry: "US", SrcIP: "198.51.100.1"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcCountry: "US", SrcIP: "198.51.100.2"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), SrcCountry: "US", SrcIP: "198.51.100.3"},
		models.UsageEvent{EventTime: anomalyBase.Add(3 * time.Hour), SrcCountry: "SG", SrcIP: "203.0.113.7"},
	)
	cfg := Config{AnomalyWarmupEvents: 3}
	if fs := (unusualGeo{}).Detect(s, cfg, ruleNow); len(fs) != 1 {
		t.Fatalf("expected the new-country finding without an allowlist, got %d", len(fs))
	}

	// The corporate VPN egresses from Singapore; allowlisting it drops the event entirely.
	cfg.EgressAllowlist = []string{"203.0.113.0/24"}
	if fs := (unusualGeo{}).Detect(s, cfg, ruleNow); len(fs) != 0 {
		t.Errorf("allowlisted egress should suppress the geo anomaly, got %d", len(fs))
	}
}

// ---- new_asn_or_runtime ------------------------------------------------------

func TestNewASNOrRuntime(t *testing.T) {
	history := []models.UsageEvent{
		{EventTime: anomalyBase, SrcASN: 64500, Runtime: "ecs"},
		{EventTime: anomalyBase.Add(time.Hour), SrcASN: 64500, Runtime: "ecs"},
		{EventTime: anomalyBase.Add(2 * time.Hour), SrcASN: 64500, Runtime: "ecs"},
	}
	cfg := Config{AnomalyWarmupEvents: 3}

	cases := map[string]models.UsageEvent{
		"new asn":     {EventTime: anomalyBase.Add(3 * time.Hour), SrcASN: 64999, Runtime: "ecs"},
		"new runtime": {EventTime: anomalyBase.Add(3 * time.Hour), SrcASN: 64500, Runtime: "lambda"},
	}
	for name, cur := range cases {
		s := usageSubject(append(append([]models.UsageEvent{}, history...), cur)...)
		f := onlyFinding(t, newASNOrRuntime{}.Detect(s, cfg, ruleNow))
		if f.Severity != models.SevLow {
			t.Errorf("%s: severity = %s, want low (weak signal on its own)", name, f.Severity)
		}
	}

	// Same ASN and runtime as always: nothing to report.
	same := models.UsageEvent{EventTime: anomalyBase.Add(3 * time.Hour), SrcASN: 64500, Runtime: "ecs"}
	s := usageSubject(append(append([]models.UsageEvent{}, history...), same)...)
	if fs := (newASNOrRuntime{}).Detect(s, cfg, ruleNow); len(fs) != 0 {
		t.Errorf("familiar ASN+runtime should not fire, got %d", len(fs))
	}
}

func TestNewASNOrRuntimeReportsBothSignals(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcASN: 64500, Runtime: "ecs"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcASN: 64500, Runtime: "ecs"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), SrcASN: 64999, Runtime: "lambda"},
	)
	f := onlyFinding(t, newASNOrRuntime{}.Detect(s, Config{AnomalyWarmupEvents: 3}, ruleNow))
	signals, _ := f.Evidence["signals"].([]string)
	if len(signals) != 2 {
		t.Errorf("evidence signals = %v, want both the ASN and the runtime", f.Evidence["signals"])
	}
}

// ---- usage_spike -------------------------------------------------------------

func TestUsageSpikeFiresBeyondSigmaThreshold(t *testing.T) {
	var evs []models.UsageEvent
	// A quiet baseline: one call in each of ten earlier hours.
	for h := 20; h >= 11; h-- {
		evs = append(evs, models.UsageEvent{EventTime: anomalyBase.Add(-time.Duration(h) * time.Hour), EventName: "GetObject"})
	}
	// Then a burst inside the final hour.
	for i := 0; i < 20; i++ {
		evs = append(evs, models.UsageEvent{EventTime: anomalyBase.Add(time.Duration(i) * time.Minute), EventName: "GetObject"})
	}

	cfg := Config{AnomalyWarmupEvents: 10, UsageSpikeSigma: 3}
	f := onlyFinding(t, usageSpike{}.Detect(usageSubject(evs...), cfg, ruleNow))
	if f.Severity != models.SevMedium {
		t.Errorf("severity = %s, want medium", f.Severity)
	}
	if f.Evidence["bucket_count"] != 20 {
		t.Errorf("evidence bucket_count = %v, want 20", f.Evidence["bucket_count"])
	}
	if z, _ := f.Evidence["z_score"].(float64); z < 3 {
		t.Errorf("z_score = %v, want >= the configured sigma", z)
	}
}

// TestUsageSpikeNeedsABaseline: with every event in a single hour there is no historical variance,
// so calling it a spike would be meaningless.
func TestUsageSpikeNeedsABaseline(t *testing.T) {
	var evs []models.UsageEvent
	for i := 0; i < 30; i++ {
		evs = append(evs, models.UsageEvent{EventTime: anomalyBase.Add(time.Duration(i) * time.Minute)})
	}
	cfg := Config{AnomalyWarmupEvents: 10, UsageSpikeSigma: 3}
	if fs := (usageSpike{}).Detect(usageSubject(evs...), cfg, ruleNow); len(fs) != 0 {
		t.Errorf("zero-variance history should not produce a spike, got %d", len(fs))
	}
}

func TestUsageSpikeRespectsWarmup(t *testing.T) {
	evs := []models.UsageEvent{
		{EventTime: anomalyBase}, {EventTime: anomalyBase.Add(time.Minute)},
	}
	cfg := Config{AnomalyWarmupEvents: 50, UsageSpikeSigma: 3}
	if fs := (usageSpike{}).Detect(usageSubject(evs...), cfg, ruleNow); len(fs) != 0 {
		t.Errorf("below warm-up nothing should fire, got %d", len(fs))
	}
}

// ---- first_use_sensitive_action ---------------------------------------------

func TestFirstUseSensitiveActionFires(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, EventName: "s3:GetObject"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), EventName: "s3:GetObject"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), EventName: "kms:Decrypt"},
	)
	f := onlyFinding(t, firstUseSensitive{}.Detect(s, Config{}, ruleNow))
	if f.Severity != models.SevHigh {
		t.Errorf("severity = %s, want high (this is the classic intrusion pivot)", f.Severity)
	}
	if f.Evidence["action"] != "kms:Decrypt" {
		t.Errorf("evidence action = %v, want kms:Decrypt", f.Evidence["action"])
	}
}

func TestFirstUseSensitiveActionOnlyOnce(t *testing.T) {
	// Already part of this identity's normal behaviour.
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, EventName: "sts:AssumeRole"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), EventName: "s3:GetObject"},
		models.UsageEvent{EventTime: anomalyBase.Add(2 * time.Hour), EventName: "sts:AssumeRole"},
	)
	if fs := (firstUseSensitive{}).Detect(s, Config{}, ruleNow); len(fs) != 0 {
		t.Errorf("a previously-seen action is not a first use, got %d", len(fs))
	}
}

func TestFirstUseSensitiveActionIgnoresRoutineCalls(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, EventName: "s3:GetObject"},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), EventName: "s3:ListBucket"},
	)
	if fs := (firstUseSensitive{}).Detect(s, Config{}, ruleNow); len(fs) != 0 {
		t.Errorf("a first-time benign call is not sensitive, got %d", len(fs))
	}

	// A single event has no history to compare against.
	single := usageSubject(models.UsageEvent{EventTime: anomalyBase, EventName: "kms:Decrypt"})
	if fs := (firstUseSensitive{}).Detect(single, Config{}, ruleNow); len(fs) != 0 {
		t.Errorf("one event is not enough to establish a first use, got %d", len(fs))
	}
}

// ---- privilege_creep ---------------------------------------------------------

func TestPrivilegeCreepAgainstPeerBaseline(t *testing.T) {
	s := activeSubject()
	s.Roles = []models.Role{{PermissionCount: 200}, {PermissionCount: 100}}
	s.PeerPermissionP90 = 100

	f := onlyFinding(t, privilegeCreep{}.Detect(s, Config{}, ruleNow))
	if f.Severity != models.SevMedium {
		t.Errorf("severity = %s, want medium", f.Severity)
	}
	if f.Evidence["permission_count"] != 300 || f.Evidence["excess"] != 200 {
		t.Errorf("evidence should quantify the excess, got %v", f.Evidence)
	}
}

func TestPrivilegeCreepNeedsABaseline(t *testing.T) {
	s := activeSubject()
	s.Roles = []models.Role{{PermissionCount: 5000}}
	// P90 of 0 means the cohort has not been computed; firing here would flag everyone.
	if fs := (privilegeCreep{}).Detect(s, Config{}, ruleNow); len(fs) != 0 {
		t.Errorf("without a peer baseline nothing should fire, got %d", len(fs))
	}
}

func TestPrivilegeCreepQuietAtOrBelowBaseline(t *testing.T) {
	s := activeSubject()
	s.PeerPermissionP90 = 100
	s.Roles = []models.Role{{PermissionCount: 100}} // exactly at P90 is not creep
	if fs := (privilegeCreep{}).Detect(s, Config{}, ruleNow); len(fs) != 0 {
		t.Errorf("an identity at the peer baseline should not fire, got %d", len(fs))
	}
}

// ---- robustness --------------------------------------------------------------

// TestAnomalyDetectorsSurviveThinUsageWindows is a regression guard. Every anomaly detector indexes
// the tail of the usage window, and that indexing used to be protected only by the warm-up
// threshold — which is operator-tunable and may legitimately be 0. An identity with no usage (most
// identities, on a fresh install) must yield no findings rather than panic the detection worker.
func TestAnomalyDetectorsSurviveThinUsageWindows(t *testing.T) {
	detectors := []Detector{
		impossibleTravel{}, unusualGeo{}, newASNOrRuntime{}, usageSpike{},
		firstUseSensitive{}, privilegeCreep{}, suspiciousRoleChain{},
	}
	windows := map[string][]models.UsageEvent{
		"nil":          nil,
		"empty":        {},
		"single event": {{EventTime: anomalyBase, SrcCountry: "US", SrcASN: 64500, Runtime: "ecs"}},
	}
	for name, evs := range windows {
		for _, d := range detectors {
			s := usageSubject(evs...)
			if fs := d.Detect(s, Config{}, ruleNow); len(fs) != 0 {
				t.Errorf("%s fired on a %s usage window: %+v", d.ID(), name, fs)
			}
		}
	}
}

// TestAnomalyDetectorsSurviveFullyFilteredUsage covers the realistic path to an empty window: the
// identity has events, but every one of them came from an allowlisted egress range.
func TestAnomalyDetectorsSurviveFullyFilteredUsage(t *testing.T) {
	s := usageSubject(
		models.UsageEvent{EventTime: anomalyBase, SrcIP: "203.0.113.1", SrcCountry: "US", SrcASN: 64500},
		models.UsageEvent{EventTime: anomalyBase.Add(time.Hour), SrcIP: "203.0.113.2", SrcCountry: "RU", SrcASN: 64999},
	)
	cfg := Config{EgressAllowlist: []string{"203.0.113.0/24"}, ImpossibleTravelKMH: 900}

	for _, d := range []Detector{impossibleTravel{}, unusualGeo{}, newASNOrRuntime{}} {
		if fs := d.Detect(s, cfg, ruleNow); len(fs) != 0 {
			t.Errorf("%s fired after every event was allowlisted away: %+v", d.ID(), fs)
		}
	}
}

// ---- helpers -----------------------------------------------------------------

func TestEgressAllowed(t *testing.T) {
	cidrs := []string{"203.0.113.0/24", "10.0.0.0/8"}
	if !egressAllowed("203.0.113.7", cidrs) || !egressAllowed("10.4.2.1", cidrs) {
		t.Error("IPs inside an allowlisted CIDR must match")
	}
	if egressAllowed("198.51.100.1", cidrs) {
		t.Error("an IP outside every CIDR must not match")
	}
	if egressAllowed("", cidrs) || egressAllowed("not-an-ip", cidrs) {
		t.Error("empty or malformed IPs must not match")
	}
	if egressAllowed("10.0.0.1", nil) {
		t.Error("an empty allowlist matches nothing")
	}
	if egressAllowed("10.0.0.1", []string{"garbage"}) {
		t.Error("an unparseable CIDR must be skipped, not matched")
	}
}

func TestFilterEgressPreservesInputWhenUnconfigured(t *testing.T) {
	evs := []models.UsageEvent{{SrcIP: "10.0.0.1"}, {SrcIP: "203.0.113.1"}}
	if got := filterEgress(evs, nil); len(got) != 2 {
		t.Errorf("no allowlist should pass everything through, got %d", len(got))
	}
	if got := filterEgress(evs, []string{"10.0.0.0/8"}); len(got) != 1 || got[0].SrcIP != "203.0.113.1" {
		t.Errorf("allowlisted events should be dropped, got %+v", got)
	}
}

func TestApproxDistKM(t *testing.T) {
	// London to Washington is roughly 6,000-7,000 km on a great circle.
	if d := approxDistKM("US", "GB"); d < 5000 || d > 8000 {
		t.Errorf("US->GB = %.0f km, outside the plausible range", d)
	}
	if d := approxDistKM("US", "US"); d != 0 {
		t.Errorf("same-country distance = %.0f, want 0", d)
	}
	// Unknown countries return 0, which suppresses the impossible-travel check rather than
	// inventing a distance.
	if d := approxDistKM("US", "ZZ"); d != 0 {
		t.Errorf("unknown country = %.0f, want 0", d)
	}
}

func TestHaversineKM(t *testing.T) {
	if d := haversineKM(0, 0, 0, 0); d != 0 {
		t.Errorf("identical points = %.4f, want 0", d)
	}
	// A quarter of the way around the equator is about 10,000 km.
	if d := haversineKM(0, 0, 0, 90); math.Abs(d-10007) > 50 {
		t.Errorf("equatorial quarter = %.0f km, want ~10007", d)
	}
}

func TestMeanSigma(t *testing.T) {
	if m, s := meanSigma(nil); m != 0 || s != 0 {
		t.Errorf("empty = %.2f/%.2f, want 0/0", m, s)
	}
	if m, s := meanSigma([]int{2, 2, 2}); m != 2 || s != 0 {
		t.Errorf("constant series = %.2f/%.2f, want 2/0", m, s)
	}
	m, s := meanSigma([]int{1, 2, 3})
	if m != 2 || math.Abs(s-0.8165) > 0.001 {
		t.Errorf("got %.4f/%.4f, want 2/0.8165", m, s)
	}
}

func TestBaselineCountriesSkipsUnknownGeo(t *testing.T) {
	got := baselineCountries([]models.UsageEvent{
		{SrcCountry: "US"}, {SrcCountry: ""}, {SrcCountry: "DE"}, {SrcCountry: "US"},
	})
	if len(got) != 2 || !got["US"] || !got["DE"] {
		t.Errorf("baseline = %v, want just US and DE", got)
	}
}

func TestHourlyBuckets(t *testing.T) {
	if got := hourlyBuckets(nil, 24); got != nil {
		t.Errorf("no events = %v, want nil", got)
	}
	evs := []models.UsageEvent{
		{EventTime: anomalyBase.Add(-2 * time.Hour)},
		{EventTime: anomalyBase},
		{EventTime: anomalyBase.Add(10 * time.Minute)},
	}
	b := hourlyBuckets(evs, 24)
	if len(b) != 24 {
		t.Fatalf("got %d buckets, want 24", len(b))
	}
	// The final bucket is the hour containing the most recent event.
	if b[23] != 2 {
		t.Errorf("latest bucket = %d, want 2", b[23])
	}
	if b[21] != 1 {
		t.Errorf("bucket two hours back = %d, want 1", b[21])
	}
}
