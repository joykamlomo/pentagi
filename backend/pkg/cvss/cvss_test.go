package cvss

import (
	"strings"
	"testing"
)

// Expected scores come from published NVD/FIRST data, not from this package.
func TestParse_PublishedScores(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		score  float64
		sev    Severity
	}{
		{"classic unauthenticated RCE (Shellshock CVE-2014-6271)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, SeverityCritical},
		{"Log4Shell CVE-2021-44228 (scope changed)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, SeverityCritical},
		{"EternalBlue CVE-2017-0144", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, SeverityHigh},
		{"reflected XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, SeverityMedium},
		{"local privilege escalation", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, SeverityHigh},
		{"authenticated low-impact", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 6.3, SeverityMedium},
		{"physical, high complexity, tiny impact", "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, SeverityLow},
		{"no impact scores zero", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, SeverityNone},
		{"scope-changed PR:L uses the higher weight", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, SeverityCritical},
		{"v3.0 prefix accepted", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.vector)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.vector, err)
			}
			if got.Score != tt.score {
				t.Errorf("Parse(%q).Score = %v, want %v", tt.vector, got.Score, tt.score)
			}
			if got.Severity != tt.sev {
				t.Errorf("Parse(%q).Severity = %v, want %v", tt.vector, got.Severity, tt.sev)
			}
		})
	}
}

func TestParse_NormalizesMetricOrder(t *testing.T) {
	got, err := Parse("  CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N  ")
	if err != nil {
		t.Fatal(err)
	}
	if want := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; got.Vector != want {
		t.Errorf("Vector = %q, want %q", got.Vector, want)
	}
	if got.Score != 9.8 {
		t.Errorf("Score = %v, want 9.8", got.Score)
	}
}

func TestParse_Rejects(t *testing.T) {
	const ok = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	tests := map[string]string{
		"empty":               "",
		"no prefix":           ok,
		"v2 vector":           "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"v4 prefix":           "CVSS:4.0/" + ok,
		"missing metric":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"duplicate metric":    "CVSS:3.1/AV:N/AV:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"bad value":           "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"multi-char value":    "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"temporal metric":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/E:F",
		"extra metric":        "CVSS:3.1/" + ok + "/E:F",
		"not a metric":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/garbage",
		"lowercase value":     "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"swapped value group": "CVSS:3.1/AV:H/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	for name, vec := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse(vec); err == nil {
				t.Errorf("Parse(%q) = %+v, want error", vec, got)
			}
		})
	}
}

func TestRatingFor_Boundaries(t *testing.T) {
	tests := map[float64]Severity{
		0: SeverityNone, 0.1: SeverityLow, 3.9: SeverityLow, 4.0: SeverityMedium, 6.9: SeverityMedium,
		7.0: SeverityHigh, 8.9: SeverityHigh, 9.0: SeverityCritical, 10.0: SeverityCritical,
	}
	for score, want := range tests {
		if got := RatingFor(score); got != want {
			t.Errorf("RatingFor(%v) = %v, want %v", score, got, want)
		}
	}
}

// Exhaustive sanity check: every valid vector scores within [0,10] to one
// decimal, and impact-free vectors score zero.
func TestParse_AllVectorsInRange(t *testing.T) {
	count := 0
	for _, av := range "NALP" {
		for _, ac := range "LH" {
			for _, pr := range "NLH" {
				for _, ui := range "NR" {
					for _, s := range "UC" {
						for _, c := range "HLN" {
							for _, i := range "HLN" {
								for _, a := range "HLN" {
									vec := strings.Join([]string{
										"CVSS:3.1", "AV:" + string(av), "AC:" + string(ac), "PR:" + string(pr),
										"UI:" + string(ui), "S:" + string(s), "C:" + string(c), "I:" + string(i), "A:" + string(a),
									}, "/")
									r, err := Parse(vec)
									if err != nil {
										t.Fatalf("Parse(%q): %v", vec, err)
									}
									if r.Score < 0 || r.Score > 10 {
										t.Fatalf("%s scored %v", vec, r.Score)
									}
									if tenths := r.Score * 10; tenths != float64(int(tenths+0.5)) {
										t.Fatalf("%s score %v has more than one decimal", vec, r.Score)
									}
									if c == 'N' && i == 'N' && a == 'N' && r.Score != 0 {
										t.Fatalf("%s has no impact but scored %v", vec, r.Score)
									}
									count++
								}
							}
						}
					}
				}
			}
		}
	}
	if count != 4*2*3*2*2*27 {
		t.Fatalf("checked %d vectors, want %d", count, 4*2*3*2*2*27)
	}
}
