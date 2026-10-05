# kev-epss-triage

Turn a vulnerability scanner export into a ranked remediation queue using **evidence of real-world exploitation** instead of CVSS alone.

Point it at any CSV of findings. It cross-references every CVE against the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and the [FIRST EPSS](https://www.first.org/epss/) exploitation-probability model, then emits a per-asset detail file and a deduplicated summary you can actually run a meeting from.

```
[1/4] Reading findings...
      10 rows | columns -> Asset=hostname, Severity=risk_factor, Cve=cve_ids, Finding=plugin_name
[2/4] Loading CISA KEV catalog...
      1734 known-exploited CVEs.
[3/4] Scoring with EPSS...
      6 of 6 unique CVEs scored.
[4/4] Prioritizing...

=== Triage result ===
  Records: 12  |  Unique vulns: 8
  P1        9
  P1-Watch  1
  P3        2
  KEV past due: 5
  Ransomware-linked: 4
```

---

## Why not just sort by CVSS?

A CVSS 9.8 that nobody has ever exploited and a CVSS 9.8 under active ransomware use look identical in a severity-sorted queue. Most scanner exports hand you hundreds of Critical/High findings with no way to tell which ones matter *this week*.

Two public datasets fix that, and they answer different questions:

- **CISA KEV** — *is this being exploited right now?* Authoritative, but backward-looking. A CVE lands on KEV only after exploitation is confirmed.
- **EPSS** — *how likely is exploitation in the next 30 days?* Predictive, so it flags things **before** KEV does.

Using only KEV means you're always reacting. Using only EPSS means ignoring confirmed in-the-wild exploitation. This tool combines them:

| Priority | Rule | Meaning |
|----------|------|---------|
| **P1** | On CISA KEV | Confirmed exploited. Patch now; KEV due date is your SLA. |
| **P1-Watch** | Not on KEV, EPSS ≥ threshold (default 0.5) | High predicted exploitation. **The gap a severity-sorted queue misses.** |
| **P2** | Neither, but rated Critical/High | Standard patch cycle. |
| **P3** | Everything else | Backlog. |

`P1-Watch` is the point of the tool. In the live run above, `CVE-2022-3786` is **not** on KEV but carries an EPSS of **0.92** — it sits in the top 8% of CVEs by predicted exploitation while a CVSS-sorted list buries it among hundreds of other Highs.

---

## Quick start

```powershell
# Preview against the bundled sample, no files written
./Invoke-VulnTriage.ps1 -InputCsv ./samples/sample-findings.csv -DryRun

# Real export -> CSVs in ./output
./Invoke-VulnTriage.ps1 -InputCsv ./export.csv -OutDir ./output

# Catch more early-warning items by lowering the EPSS bar
./Invoke-VulnTriage.ps1 -InputCsv ./export.csv -EpssThreshold 0.3
```

Requires **PowerShell 7+**. No external modules. Runs on Windows, macOS, and Linux.

---

## Input

Any CSV with one finding per row. Column names are auto-detected across common scanner spellings:

| Field | Recognized headers | Required |
|-------|--------------------|----------|
| CVE | `cve`, `cve_id`, `cves`, `cve_ids`, `finding_cve` | **yes** |
| Asset | `asset`, `asset_name`, `host`, `hostname`, `ip`, `target`, … | no |
| Finding | `finding`, `title`, `name`, `plugin_name`, `vulnerability`, … | no |
| Severity | `severity`, `risk`, `risk_factor`, `criticality`, … | no |

Anything unusual can be wired up without touching code:

```powershell
./Invoke-VulnTriage.ps1 -InputCsv ./export.csv -ColumnMap @{ Cve = 'vuln_refs'; Asset = 'device_fqdn' }
```

Rows listing several CVEs in one cell are **expanded into one record per CVE**, so a co-listed KEV entry is never masked by a low-risk neighbour. Findings with no CVE (config issues, EOL software) are kept and scored on severity.

---

## Output

**`triage_detail_*.csv`** — one row per asset + CVE. Drives assignment.

**`triage_summary_*.csv`** — one row per CVE, with affected-asset count and worst-case priority. Drives planning.

**`triage_changes_*.csv`** — written only when `-CompareWith` is used. See [Trend](#trend-what-changed-since-last-run).

Both carry: `Priority`, `OnCisaKev`, `KevDueDate`, `KevOverdue`, `KnownRansomware`, `EpssScore`, `EpssPercentile`.

`KevOverdue` compares today against CISA's mandated remediation date — useful even outside federal BOD 22-01 scope, since it's a defensible externally-set deadline.

---

## Trend: what changed since last run

Pass `-CompareWith latest` to diff against the most recent summary in `-OutDir` (or give an explicit path):

```powershell
./Invoke-VulnTriage.ps1 -InputCsv ./export.csv -CompareWith latest
```

```
  ** 1 vulnerability(ies) newly added to CISA KEV **
     CVE-2014-0160  P1-Watch -> P1

  Change summary:
    Escalated     2

Change    Cve           PreviousPriority CurrentPriority AssetDelta Detail
------    ---           ---------------- --------------- ---------- ------
Escalated CVE-2014-0160 P1-Watch         P1                       0 Added to CISA KEV. P1-Watch -> P1
Escalated CVE-2022-3786 P2               P1-Watch                 0 P2 -> P1-Watch. EPSS +0.9039
```

That output is from two real runs, and it's the clearest demonstration of why both feeds matter: **EPSS flagged `CVE-2014-0160` as P1-Watch before CISA added it to KEV.** A KEV-only process would have picked it up at escalation time; a CVSS-only process would still have it sitting among the Highs.

| Classification | Meaning |
|----------------|---------|
| `NewlyKev` | **Headline signal.** Already in your backlog; CISA has now confirmed in-the-wild exploitation. |
| `Escalated` | Priority got worse between runs. |
| `New` | Not present in the previous run. |
| `Resolved` | Gone — remediated, or out of scope. |
| `De-escalated` | Priority improved. |
| `EpssSpike` | EPSS rose by ≥ `-EpssDelta` (default 0.10). |
| `AssetDelta` | Net change in affected assets — catches lateral spread at a steady priority. |

Only changed items are reported; add `-IncludeUnchanged` for the full set. Results are written to `triage_changes_*.csv` and sorted with newly-KEV items first.

Because the diff is just two summary files, it works across any interval — nightly, weekly, or per maintenance window — with no database or server.

---

## Offline / air-gapped use

Both feeds can come from local files, which is also how the test suite stays deterministic:

```powershell
curl -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
./Invoke-VulnTriage.ps1 -InputCsv ./export.csv -KevPath ./kev.json -EpssPath ./epss.json
```

If the EPSS API is unreachable mid-run, the tool warns and continues — KEV membership still produces a valid P1 list. Enrichment failure degrades the ranking; it doesn't abort the run.

---

## Tests

```powershell
Invoke-Pester -Path ./tests
```

54 tests, fully offline via `tests/fixtures`. Covers CVE parsing (delimiters, casing, malformed input), column resolution, priority boundaries, multi-CVE expansion, due-date math, summary rollup, and run-to-run diffing — including the string coercion needed when a previous run is re-read from CSV.

---

## Using it as a library

```powershell
Import-Module ./src/VulnTriage.psm1

$kev  = Get-KevCatalog
$epss = Get-EpssScore -Cve @('CVE-2021-44228', 'CVE-2022-3786')

Get-TriagePriority -OnKev $false -EpssScore $epss['CVE-2022-3786'].Score -Severity 'High'
# -> P1-Watch
```

| Function | Purpose |
|----------|---------|
| `Get-KevCatalog` | CISA KEV → lookup hashtable |
| `Get-EpssScore` | FIRST EPSS scores, auto-batched |
| `Get-CveFromText` | Extract/normalize CVE IDs from free text |
| `Resolve-ColumnMap` | Map logical fields onto CSV headers |
| `Get-TriagePriority` | The ranking rule, in isolation |
| `Invoke-VulnTriage` | Enrich + prioritize |
| `Get-TriageSummary` | Roll up per CVE |
| `Compare-TriageRun` | Diff two runs; surface newly-KEV and escalations |

### Adding a scanner adapter

The core takes plain objects, not CSVs, so pulling from an API directly is just:

```powershell
$findings = Invoke-RestMethod "$BaseUrl/findings" -Headers $Headers
Invoke-VulnTriage -Finding $findings -ColumnMap @{ Cve = 'cve'; Asset = 'host' } -Kev $kev -Epss $epss
```

---

## Roadmap

- [ ] Scanner adapters (Tenable, Qualys, Defender) behind a common interface
- [ ] Optional XLSX output via `ImportExcel`
- [x] Trend tracking — diff successive runs to show what's new, fixed, or newly KEV-listed
- [ ] Container/SBOM input (CycloneDX, SPDX)

---

## License

MIT — see [LICENSE](LICENSE).

Data sources are public and unaffiliated with this project: the CISA KEV catalog is US Government public domain; EPSS is provided by FIRST.org under their terms of use.
