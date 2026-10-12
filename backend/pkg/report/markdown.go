package report

import (
	"fmt"
	"strings"
)

// Markdown renders the report as a Markdown document.
func (d Document) Markdown() string {
	var b strings.Builder

	title := "Penetration Test Report"
	fmt.Fprintf(&b, "# %s\n\n", title)
	if t := oneLine(d.Title); t != "" {
		fmt.Fprintf(&b, "**Engagement:** %s  \n", mdInline(t))
	}
	if c := oneLine(d.Client); c != "" {
		fmt.Fprintf(&b, "**Client:** %s  \n", mdInline(c))
	}
	if c := oneLine(d.Company); c != "" {
		fmt.Fprintf(&b, "**Prepared by:** %s  \n", mdInline(c))
	}
	if !d.TestStart.IsZero() {
		end := d.TestEnd
		if end.IsZero() || end.Before(d.TestStart) {
			end = d.TestStart
		}
		fmt.Fprintf(&b, "**Testing period:** %s to %s  \n", d.TestStart.UTC().Format("2006-01-02"), end.UTC().Format("2006-01-02"))
	}
	if !d.GeneratedAt.IsZero() {
		fmt.Fprintf(&b, "**Report date:** %s  \n", d.GeneratedAt.UTC().Format("2006-01-02"))
	}
	b.WriteString("\n")

	if n := d.ReviewNotice(); n != "" {
		fmt.Fprintf(&b, "> **%s**\n\n", mdInline(n))
	}

	b.WriteString("## Executive summary\n\n")
	b.WriteString(mdInline(d.Summary()) + "\n\n")

	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, s := range severityOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", severityLabel[s], d.Counts[s])
	}
	b.WriteString("\n")

	b.WriteString("## Scope and methodology\n\n")
	if len(d.Scope) > 0 {
		b.WriteString("**In scope:**\n\n")
		for _, s := range d.Scope {
			fmt.Fprintf(&b, "- %s\n", mdCode(s))
		}
		b.WriteString("\n")
	}
	b.WriteString(Methodology + "\n\n")

	b.WriteString("## Findings overview\n\n")
	if len(d.Findings) == 0 {
		b.WriteString("No findings.\n\n")
	} else {
		b.WriteString("| ID | Severity | Title | Asset | Status | CVSS |\n|---|---|---|---|---|---|\n")
		for _, e := range d.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				e.Number, e.Label, mdCell(e.Title), mdCell(e.Asset), statusLabel(e.Status), scoreLabel(e))
		}
		b.WriteString("\n")
	}

	if len(d.Findings) > 0 {
		b.WriteString("## Detailed findings\n\n")
	}
	for _, e := range d.Findings {
		fmt.Fprintf(&b, "### %s: %s\n\n", e.Number, mdInline(oneLine(e.Title)))
		fmt.Fprintf(&b, "- **Severity:** %s\n", e.Label)
		fmt.Fprintf(&b, "- **Status:** %s\n", statusLabel(e.Status))
		fmt.Fprintf(&b, "- **Affected asset:** %s\n", mdCell(e.Asset))
		if e.CVSSVector != "" {
			fmt.Fprintf(&b, "- **CVSS v3.1:** %.1f (%s)\n", e.CVSSScore, mdCode(e.CVSSVector))
		}
		b.WriteString("\n")

		mdSection(&b, "Description", e.Description)
		mdSection(&b, "Impact", e.Impact)
		if strings.TrimSpace(e.Evidence) != "" {
			b.WriteString("**Evidence**\n\n")
			b.WriteString(codeBlock(e.Evidence))
			b.WriteString("\n")
		}
		mdSection(&b, "Remediation", e.Remediation)

		if refs := cleanRefs(e.References); len(refs) > 0 {
			b.WriteString("**References**\n\n")
			for _, r := range refs {
				fmt.Fprintf(&b, "- %s\n", mdInline(oneLine(r)))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Disclaimer\n\n" + Disclaimer + "\n")
	return b.String()
}

func mdSection(b *strings.Builder, heading, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	fmt.Fprintf(b, "**%s**\n\n%s\n\n", heading, mdBlock(body))
}

// mdInline neutralizes raw HTML in text placed in Markdown prose: a renderer
// that passes HTML through would otherwise execute markup quoted from a target.
func mdInline(s string) string {
	return strings.ReplaceAll(s, "<", "&lt;")
}

// mdBlock does the same for multi-line prose and keeps agent-written text from
// opening a fenced block of its own.
func mdBlock(s string) string {
	s = mdInline(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		t := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			lines[i] = "\\" + t
		}
	}
	return strings.Join(lines, "\n")
}

// mdCode renders a short single-line value as an inline code span. These fields
// (scope entries, CVSS vectors) never legitimately contain backticks or angle
// brackets, so both are neutralized rather than preserved.
func mdCode(s string) string {
	s = strings.ReplaceAll(oneLine(s), "`", "'")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return "`" + s + "`"
}

// mdCell makes a value safe inside a single table cell.
func mdCell(s string) string {
	s = mdInline(oneLine(s))
	s = strings.ReplaceAll(s, "|", "\\|")
	if s == "" {
		return "-"
	}
	return s
}

// codeBlock fences evidence with a fence longer than any backtick run inside
// it, so quoted content can never close the block early.
func codeBlock(s string) string {
	s = strings.Trim(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	fence := strings.Repeat("`", max(3, longestBacktickRun(s)+1))
	return fence + "\n" + s + "\n" + fence + "\n"
}

func longestBacktickRun(s string) int {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

func statusLabel(status string) string {
	if status == "confirmed" {
		return "Confirmed"
	}
	return "Potential (not verified)"
}

func scoreLabel(e Entry) string {
	if e.CVSSVector == "" {
		return "-"
	}
	return fmt.Sprintf("%.1f", e.CVSSScore)
}

func cleanRefs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		if r = oneLine(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}
