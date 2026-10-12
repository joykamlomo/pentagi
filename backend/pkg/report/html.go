package report

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"regexp"
	"strings"
)

var (
	cveRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	cweRe = regexp.MustCompile(`(?i)^CWE-(\d{1,5})$`)
)

type refView struct {
	Text string
	URL  string // empty when the reference is not a safe link
}

type findingView struct {
	Entry
	CVSS       string
	StatusText string
	Refs       []refView
}

type htmlData struct {
	Document
	Title        string
	Summary      string
	ReviewNotice string
	CountRows    []countRow
	Views        []findingView
	Methodology  string
	Disclaimer   string
	Generated    string
	Period       string
}

type countRow struct {
	Class string
	Label string
	N     int
}

// HTML renders the report as a single self-contained HTML page with no
// scripts. It is meant to be opened in a browser and printed to PDF.
func (d Document) HTML() (string, error) {
	data := htmlData{
		Document:     d,
		Title:        "Penetration Test Report",
		Summary:      d.Summary(),
		ReviewNotice: d.ReviewNotice(),
		Methodology:  Methodology,
		Disclaimer:   Disclaimer,
	}
	if !d.GeneratedAt.IsZero() {
		data.Generated = d.GeneratedAt.UTC().Format("2006-01-02")
	}
	if !d.TestStart.IsZero() {
		end := d.TestEnd
		if end.IsZero() || end.Before(d.TestStart) {
			end = d.TestStart
		}
		data.Period = fmt.Sprintf("%s to %s", d.TestStart.UTC().Format("2006-01-02"), end.UTC().Format("2006-01-02"))
	}

	for _, s := range severityOrder {
		data.CountRows = append(data.CountRows, countRow{Class: s, Label: severityLabel[s], N: d.Counts[s]})
	}

	for _, e := range d.Findings {
		v := findingView{Entry: e, StatusText: statusLabel(e.Status), CVSS: scoreLabel(e)}
		for _, r := range cleanRefs(e.References) {
			v.Refs = append(v.Refs, newRefView(r))
		}
		data.Views = append(data.Views, v)
	}

	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render report: %w", err)
	}
	return buf.String(), nil
}

// newRefView turns a reference into a link only when it is a well-formed
// http(s) URL or a recognized CVE/CWE id; anything else is shown as plain text.
func newRefView(r string) refView {
	v := refView{Text: r}

	switch {
	case cveRe.MatchString(r):
		v.URL = "https://nvd.nist.gov/vuln/detail/" + strings.ToUpper(r)
	case cweRe.MatchString(r):
		m := cweRe.FindStringSubmatch(r)
		v.URL = "https://cwe.mitre.org/data/definitions/" + m[1] + ".html"
	default:
		if u, err := url.Parse(r); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			v.URL = u.String()
		}
	}
	return v
}

var reportTemplate = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}{{with .Meta.Title}} - {{.}}{{end}}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1b1f24; background: #fff; margin: 0; }
  main { max-width: 860px; margin: 0 auto; padding: 40px 28px 64px; }
  h1 { font-size: 30px; margin: 0 0 6px; }
  h2 { font-size: 21px; margin: 38px 0 12px; padding-bottom: 6px; border-bottom: 2px solid #d8dde3; }
  h3 { font-size: 17px; margin: 0; }
  .meta { color: #4a5360; margin: 0 0 18px; }
  .meta div { margin: 2px 0; }
  .notice { border-left: 4px solid #b45309; background: #fff7ed; padding: 10px 14px; margin: 18px 0; font-weight: 600; }
  .notice.final { border-color: #15803d; background: #f0fdf4; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0 4px; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #e3e7ec; vertical-align: top; }
  th { background: #f4f6f8; font-size: 13px; text-transform: uppercase; letter-spacing: .03em; color: #4a5360; }
  td.n { text-align: right; width: 70px; font-variant-numeric: tabular-nums; }
  td.id { white-space: nowrap; }
  .badge { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 12px; font-weight: 700; color: #fff; white-space: nowrap; }
  .critical { background: #7f1d1d; } .high { background: #c2410c; } .medium { background: #b45309; }
  .low { background: #1d4ed8; } .info { background: #4b5563; }
  .finding { border: 1px solid #d8dde3; border-radius: 8px; padding: 18px 20px; margin: 18px 0; break-inside: avoid-page; page-break-inside: avoid; }
  .finding header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
  dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: 3px 16px; margin: 0 0 8px; }
  dl.facts dt { color: #4a5360; font-weight: 600; } dl.facts dd { margin: 0; overflow-wrap: anywhere; }
  .label { font-weight: 700; margin: 14px 0 4px; }
  .prose { white-space: pre-wrap; overflow-wrap: anywhere; }
  pre { background: #0f172a; color: #e2e8f0; padding: 12px 14px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 4px 0; }
  code { font: 12.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #f1f3f5; padding: 1px 5px; border-radius: 4px; }
  ul { margin: 6px 0; padding-left: 22px; }
  a { color: #1d4ed8; }
  .disclaimer { color: #4a5360; font-size: 13px; }
  .watermark { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none; z-index: 10;
    font-size: 150px; font-weight: 800; letter-spacing: .1em; color: rgba(180, 83, 9, .10); transform: rotate(-30deg); }
  @media print {
    @page { margin: 16mm; }
    main { max-width: none; padding: 0; }
    pre { white-space: pre-wrap; }
    a { color: inherit; text-decoration: none; }
    h2 { break-after: avoid; }
  }
</style>
</head>
<body>
{{if .Draft}}<div class="watermark" aria-hidden="true">DRAFT</div>{{end}}
<main>
  <h1>{{.Title}}</h1>
  <div class="meta">
    {{with .Meta.Title}}<div><strong>Engagement:</strong> {{.}}</div>{{end}}
    {{with .Client}}<div><strong>Client:</strong> {{.}}</div>{{end}}
    {{with .Company}}<div><strong>Prepared by:</strong> {{.}}</div>{{end}}
    {{with .Period}}<div><strong>Testing period:</strong> {{.}}</div>{{end}}
    {{with .Generated}}<div><strong>Report date:</strong> {{.}}</div>{{end}}
  </div>
  {{if .ReviewNotice}}<div class="notice{{if not .Draft}} final{{end}}">{{.ReviewNotice}}</div>{{end}}

  <h2>Executive summary</h2>
  <p>{{.Summary}}</p>
  <table>
    <tr><th>Severity</th><th class="n">Count</th></tr>
    {{range .CountRows}}<tr><td><span class="badge {{.Class}}">{{.Label}}</span></td><td class="n">{{.N}}</td></tr>
    {{end}}
  </table>

  <h2>Scope and methodology</h2>
  {{if .Scope}}<div class="label">In scope</div>
  <ul>{{range .Scope}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
  <p>{{.Methodology}}</p>

  <h2>Findings overview</h2>
  {{if .Views}}
  <table>
    <tr><th>ID</th><th>Severity</th><th>Title</th><th>Asset</th><th>Status</th><th>CVSS</th></tr>
    {{range .Views}}<tr><td class="id">{{.Number}}</td><td><span class="badge {{.Severity}}">{{.Label}}</span></td><td>{{.Title}}</td><td>{{.Asset}}</td><td>{{.StatusText}}</td><td>{{.CVSS}}</td></tr>
    {{end}}
  </table>
  {{else}}<p>No findings.</p>{{end}}

  {{if .Views}}<h2>Detailed findings</h2>{{end}}
  {{range .Views}}
  <section class="finding" id="{{.Number}}">
    <header><span class="badge {{.Severity}}">{{.Label}}</span><h3>{{.Number}}: {{.Title}}</h3></header>
    <dl class="facts">
      <dt>Status</dt><dd>{{.StatusText}}</dd>
      <dt>Affected asset</dt><dd>{{.Asset}}</dd>
      {{if .CVSSVector}}<dt>CVSS v3.1</dt><dd>{{.CVSS}} <code>{{.CVSSVector}}</code></dd>{{end}}
    </dl>
    {{if .Description}}<div class="label">Description</div><div class="prose">{{.Description}}</div>{{end}}
    {{if .Impact}}<div class="label">Impact</div><div class="prose">{{.Impact}}</div>{{end}}
    {{if .Evidence}}<div class="label">Evidence</div><pre>{{.Evidence}}</pre>{{end}}
    {{if .Remediation}}<div class="label">Remediation</div><div class="prose">{{.Remediation}}</div>{{end}}
    {{if .Refs}}<div class="label">References</div>
    <ul>{{range .Refs}}<li>{{if .URL}}<a href="{{.URL}}" rel="noopener noreferrer">{{.Text}}</a>{{else}}{{.Text}}{{end}}</li>{{end}}</ul>{{end}}
  </section>
  {{end}}

  <h2>Disclaimer</h2>
  <p class="disclaimer">{{.Disclaimer}}</p>
</main>
</body>
</html>
`))
