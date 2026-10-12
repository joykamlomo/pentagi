// Package findings holds the validation and normalization rules for security
// findings, shared by the agent tool that records them and the API through
// which a consultant reviews them, so both enforce exactly the same rules.
package findings

import (
	"errors"
	"fmt"
	"strings"

	"pentagi/pkg/cvss"
)

const (
	MaxTitleLen    = 200
	MaxAssetLen    = 300
	MaxTextLen     = 20_000
	MaxEvidenceLen = 50_000
	MaxRefs        = 20
	MaxRefLen      = 300

	truncatedMarker = "\n[truncated]"
)

// Severity and status values as stored.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	StatusConfirmed     = "confirmed"
	StatusPotential     = "potential"
	StatusFalsePositive = "false_positive"
)

// Input is an unvalidated finding as supplied by an agent or a reviewer.
type Input struct {
	Title       string
	Asset       string
	Severity    string
	Status      string
	Description string
	Impact      string
	Evidence    string
	Remediation string
	CVSSVector  string
	References  []string
}

// Options selects who is submitting the finding.
type Options struct {
	// Reviewer marks a submission from a person. Their explicit severity wins
	// over the CVSS-derived one (a business judgment), and they may mark a
	// finding as a false positive. For agents the computed CVSS severity is
	// authoritative, because models are unreliable at scoring.
	Reviewer bool
}

// Result is a validated, normalized finding.
type Result struct {
	Title       string
	Asset       string
	Severity    string
	Status      string
	Description string
	Impact      string
	Evidence    string
	Remediation string
	CVSSVector  string // normalized; empty when none was given
	CVSSScore   float64
	References  []string
	Notes       []string // adjustments made on the submitter's behalf, to echo back
}

// Normalize validates a finding and applies the shared rules: confirmed
// findings need evidence, a CVSS vector must parse (the score is computed, never
// taken on trust), text is made safe for storage and size-bounded. All fixable
// problems are returned together in one error.
func Normalize(in Input, opt Options) (Result, error) {
	r := Result{
		Title:       cleanText(in.Title),
		Asset:       cleanText(in.Asset),
		Description: cleanText(in.Description),
		Impact:      cleanText(in.Impact),
		Evidence:    cleanText(in.Evidence),
		Remediation: cleanText(in.Remediation),
	}

	var problems []string

	var missing []string
	for _, f := range []struct{ name, value string }{
		{"title", r.Title}, {"asset", r.Asset}, {"description", r.Description},
		{"impact", r.Impact}, {"remediation", r.Remediation},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		problems = append(problems, "missing required field(s): "+strings.Join(missing, ", "))
	}
	if len(r.Title) > MaxTitleLen {
		problems = append(problems, fmt.Sprintf("title is too long (%d > %d characters)", len(r.Title), MaxTitleLen))
	}
	if len(r.Asset) > MaxAssetLen {
		problems = append(problems, fmt.Sprintf("asset is too long (%d > %d characters)", len(r.Asset), MaxAssetLen))
	}

	severity, severityGiven, severityOK := parseSeverity(in.Severity)
	if severityGiven && !severityOK {
		problems = append(problems, fmt.Sprintf("severity %q is invalid (use critical, high, medium, low or info)", in.Severity))
	}

	switch strings.ToLower(strings.TrimSpace(in.Status)) {
	case StatusConfirmed:
		r.Status = StatusConfirmed
		if r.Evidence == "" {
			problems = append(problems, "status 'confirmed' requires evidence (the exact command/request and output that prove it); "+
				"use status 'potential' if it has not been reproduced")
		}
	case StatusPotential, "":
		r.Status = StatusPotential
	case StatusFalsePositive:
		if !opt.Reviewer {
			problems = append(problems, "status 'false_positive' can only be set by a reviewer (use confirmed or potential)")
		}
		r.Status = StatusFalsePositive
	default:
		problems = append(problems, fmt.Sprintf("status %q is invalid (use confirmed or potential)", in.Status))
	}

	derived := ""
	if vec := strings.TrimSpace(in.CVSSVector); vec != "" {
		res, err := cvss.Parse(vec)
		if err != nil {
			problems = append(problems, fmt.Sprintf("invalid cvss_vector: %v", err))
		} else {
			r.CVSSVector = res.Vector
			r.CVSSScore = res.Score
			derived = severityFromCVSS(res.Severity)
		}
	}

	switch {
	case derived != "" && opt.Reviewer && severityOK:
		r.Severity = severity // the reviewer's explicit call stands
	case derived != "":
		if severityOK && severity != derived {
			r.Notes = append(r.Notes, fmt.Sprintf("severity set to %s to match CVSS %.1f", derived, r.CVSSScore))
		}
		r.Severity = derived
	case severityOK:
		r.Severity = severity
	case !severityGiven:
		problems = append(problems, "severity is required (critical, high, medium, low or info)")
	}

	if len(problems) > 0 {
		return Result{}, errors.New(strings.Join(problems, "; "))
	}

	for _, f := range []struct {
		name  string
		val   *string
		limit int
	}{
		{"description", &r.Description, MaxTextLen},
		{"impact", &r.Impact, MaxTextLen},
		{"remediation", &r.Remediation, MaxTextLen},
		{"evidence", &r.Evidence, MaxEvidenceLen},
	} {
		if capped, note := capText(*f.val, f.limit, f.name); note != "" {
			*f.val = capped
			r.Notes = append(r.Notes, note)
		}
	}

	refs, note := normalizeRefs(in.References)
	r.References = refs
	if note != "" {
		r.Notes = append(r.Notes, note)
	}

	return r, nil
}

// parseSeverity returns the canonical severity, whether one was supplied at
// all, and whether the supplied value is valid.
func parseSeverity(s string) (severity string, given, ok bool) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return "", false, false
	}
	switch v {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return v, true, true
	case "informational":
		return SeverityInfo, true, true
	}
	return "", true, false
}

func severityFromCVSS(s cvss.Severity) string {
	switch s {
	case cvss.SeverityCritical:
		return SeverityCritical
	case cvss.SeverityHigh:
		return SeverityHigh
	case cvss.SeverityMedium:
		return SeverityMedium
	case cvss.SeverityLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// cleanText trims and makes text storable: PostgreSQL rejects NUL bytes and
// invalid UTF-8, and terminal output pasted as evidence can contain both.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

func capText(s string, limit int, field string) (string, string) {
	if len(s) <= limit {
		return s, ""
	}
	cut := limit - len(truncatedMarker)
	// do not split a multi-byte character
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + truncatedMarker, fmt.Sprintf("%s truncated to %d characters", field, limit)
}

// TruncatedMarker is appended to text that was cut to fit its limit.
const TruncatedMarker = truncatedMarker

func normalizeRefs(in []string) ([]string, string) {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	dropped := 0

	for _, r := range in {
		r = cleanText(r)
		if r == "" {
			continue
		}
		if len(r) > MaxRefLen {
			r = strings.ToValidUTF8(r[:MaxRefLen], "")
		}
		key := strings.ToLower(r)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if len(out) >= MaxRefs {
			dropped++
			continue
		}
		out = append(out, r)
	}

	if dropped > 0 {
		return out, fmt.Sprintf("only the first %d references were kept", MaxRefs)
	}
	return out, ""
}
