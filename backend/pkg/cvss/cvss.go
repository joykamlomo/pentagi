// Package cvss computes CVSS v3.x base scores from vector strings.
//
// Language models are unreliable at CVSS arithmetic, so agents supply only the
// vector ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") and the score and
// severity are derived here, deterministically, following the FIRST.org
// CVSS v3.1 specification. Only base metrics are supported.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Severity is the qualitative rating of a CVSS score.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Result is a parsed and scored vector.
type Result struct {
	Vector   string // normalized: version prefix plus the eight base metrics in canonical order
	Score    float64
	Severity Severity
}

var metricOrder = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

var metricValues = map[string]string{
	"AV": "NALP",
	"AC": "LH",
	"PR": "NLH",
	"UI": "NR",
	"S":  "UC",
	"C":  "HLN",
	"I":  "HLN",
	"A":  "HLN",
}

// Parse validates a CVSS v3.0/v3.1 base vector and computes its score.
func Parse(vector string) (Result, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) != len(metricOrder)+1 {
		return Result{}, fmt.Errorf("CVSS vector must have a version prefix and %d base metrics", len(metricOrder))
	}

	version := ""
	switch parts[0] {
	case "CVSS:3.1":
		version = "3.1"
	case "CVSS:3.0":
		version = "3.0"
	default:
		return Result{}, fmt.Errorf("unsupported CVSS version %q (use CVSS:3.1)", parts[0])
	}

	m := make(map[string]byte, len(metricOrder))
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok || len(v) != 1 {
			return Result{}, fmt.Errorf("malformed CVSS metric %q", p)
		}
		allowed, known := metricValues[k]
		if !known {
			return Result{}, fmt.Errorf("unknown or unsupported CVSS metric %q (only base metrics are accepted)", k)
		}
		if !strings.Contains(allowed, v) {
			return Result{}, fmt.Errorf("invalid value %q for CVSS metric %s (allowed: %s)", v, k, allowed)
		}
		if _, dup := m[k]; dup {
			return Result{}, fmt.Errorf("duplicate CVSS metric %s", k)
		}
		m[k] = v[0]
	}
	for _, k := range metricOrder {
		if _, ok := m[k]; !ok {
			return Result{}, fmt.Errorf("missing CVSS metric %s", k)
		}
	}

	score := baseScore(m, version)

	norm := make([]string, 0, len(metricOrder)+1)
	norm = append(norm, "CVSS:"+version)
	for _, k := range metricOrder {
		norm = append(norm, k+":"+string(m[k]))
	}

	return Result{Vector: strings.Join(norm, "/"), Score: score, Severity: RatingFor(score)}, nil
}

// RatingFor maps a base score to its qualitative severity.
func RatingFor(score float64) Severity {
	switch {
	case score <= 0:
		return SeverityNone
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

func baseScore(m map[string]byte, version string) float64 {
	scopeChanged := m["S"] == 'C'

	av := map[byte]float64{'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[m["AV"]]
	ac := map[byte]float64{'L': 0.77, 'H': 0.44}[m["AC"]]
	ui := map[byte]float64{'N': 0.85, 'R': 0.62}[m["UI"]]

	var pr float64
	switch m["PR"] {
	case 'N':
		pr = 0.85
	case 'L':
		pr = 0.62
		if scopeChanged {
			pr = 0.68
		}
	case 'H':
		pr = 0.27
		if scopeChanged {
			pr = 0.5
		}
	}

	cia := map[byte]float64{'H': 0.56, 'L': 0.22, 'N': 0}
	iss := 1 - (1-cia[m["C"]])*(1-cia[m["I"]])*(1-cia[m["A"]])

	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	round := roundUp31
	if version == "3.0" {
		round = roundUp30
	}
	if scopeChanged {
		return round(math.Min(1.08*(impact+exploitability), 10))
	}
	return round(math.Min(impact+exploitability, 10))
}

// roundUp31 is the CVSS v3.1 Roundup: the smallest one-decimal value >= x,
// computed on integers to avoid floating-point artifacts (spec appendix A).
func roundUp31(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return float64(i/10000+1) / 10.0
}

// roundUp30 is the CVSS v3.0 rounding: ceiling to one decimal.
func roundUp30(x float64) float64 {
	return math.Ceil(x*10) / 10
}
