#Requires -Version 7.0
<#
    VulnTriage — scanner-agnostic vulnerability prioritization.

    Enriches a flat list of findings with CISA KEV membership and FIRST EPSS
    exploitation probability, then assigns an action-oriented priority.

    Every function here is pure or injectable: catalog loaders accept a -Path so
    the whole pipeline can be exercised offline against fixtures.
#>

Set-StrictMode -Version Latest

$script:KevUrl  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$script:EpssUrl = 'https://api.first.org/data/v1/epss'

# Common column spellings emitted by various scanners, lowest-friction first.
$script:ColumnAliases = @{
    Asset    = @('asset', 'asset_name', 'host', 'hostname', 'target', 'ip', 'device', 'machine')
    Finding  = @('finding', 'finding_name', 'title', 'name', 'plugin_name', 'vulnerability', 'description')
    Cve      = @('cve', 'cve_id', 'cves', 'finding_cve', 'cve_ids')
    Severity = @('severity', 'finding_severity', 'risk', 'risk_factor', 'criticality')
}

function Resolve-ColumnMap {
<#
.SYNOPSIS
    Maps logical fields (Asset/Finding/Cve/Severity) onto the actual CSV headers.
.DESCRIPTION
    Detects common scanner column names case-insensitively. Explicit overrides in
    -ColumnMap always win, so an unusual export can be wired up without code changes.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Header,
        [hashtable]$ColumnMap = @{}
    )

    $resolved = @{}
    foreach ($field in $script:ColumnAliases.Keys) {
        if ($ColumnMap.ContainsKey($field) -and $ColumnMap[$field]) {
            $explicit = $ColumnMap[$field]
            $match = $Header | Where-Object { $_ -ieq $explicit } | Select-Object -First 1
            if (-not $match) {
                throw "Column '$explicit' (mapped to $field) not found. Available: $($Header -join ', ')"
            }
            $resolved[$field] = $match
            continue
        }

        $match = $null
        foreach ($alias in $script:ColumnAliases[$field]) {
            $match = $Header | Where-Object { $_ -ieq $alias } | Select-Object -First 1
            if ($match) { break }
        }
        $resolved[$field] = $match   # may be $null; only Cve is strictly required
    }

    if (-not $resolved['Cve']) {
        throw "Could not find a CVE column. Pass -ColumnMap @{ Cve = '<header>' }. Available: $($Header -join ', ')"
    }
    $resolved
}

function Get-CveFromText {
<#
.SYNOPSIS
    Extracts unique, normalized CVE IDs from a free-text cell.
.DESCRIPTION
    Scanner exports routinely pack several CVEs into one field with inconsistent
    delimiters, so this matches the CVE pattern directly rather than splitting.
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    [regex]::Matches($Text.ToUpperInvariant(), 'CVE-\d{4}-\d{4,}') |
        ForEach-Object { $_.Value } |
        Select-Object -Unique
}

function Get-KevCatalog {
<#
.SYNOPSIS
    Loads the CISA Known Exploited Vulnerabilities catalog into a lookup hashtable.
.PARAMETER Path
    Read from a local JSON file instead of the network (offline runs and tests).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$Path,
        [string]$Uri = $script:KevUrl
    )

    $raw = if ($Path) {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } else {
        Invoke-RestMethod -Uri $Uri -Method GET -ErrorAction Stop
    }

    $lookup = @{}
    foreach ($v in $raw.vulnerabilities) {
        $lookup[$v.cveID.ToUpperInvariant()] = [pscustomobject]@{
            CveId              = $v.cveID.ToUpperInvariant()
            VulnerabilityName  = $v.vulnerabilityName
            DateAdded          = $v.dateAdded
            DueDate            = $v.dueDate
            KnownRansomwareUse = ($v.knownRansomwareCampaignUse -ieq 'Known')
        }
    }
    Write-Verbose "KEV catalog loaded: $($lookup.Count) CVEs (version $($raw.catalogVersion))."
    $lookup
}

function Get-EpssScore {
<#
.SYNOPSIS
    Retrieves EPSS exploitation probabilities from FIRST.org for the given CVEs.
.DESCRIPTION
    Queries in batches because the API caps results per request. Missing CVEs are
    simply absent from the result; callers treat absence as a score of 0.
.PARAMETER Path
    Read from a local JSON file instead of the network (offline runs and tests).
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string[]]$Cve = @(),
        [string]$Path,
        [string]$Uri = $script:EpssUrl,
        [ValidateRange(1, 100)][int]$BatchSize = 80
    )

    $lookup = @{}

    if ($Path) {
        $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        foreach ($d in $raw.data) {
            $lookup[$d.cve.ToUpperInvariant()] = [pscustomobject]@{
                Score      = [double]$d.epss
                Percentile = [double]$d.percentile
            }
        }
        return $lookup
    }

    $unique = @($Cve | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
    if ($unique.Count -eq 0) { return $lookup }

    for ($i = 0; $i -lt $unique.Count; $i += $BatchSize) {
        $batch = $unique[$i..([Math]::Min($i + $BatchSize - 1, $unique.Count - 1))]
        $query = '{0}?cve={1}&limit={2}' -f $Uri, ($batch -join ','), $batch.Count
        try {
            $resp = Invoke-RestMethod -Uri $query -Method GET -ErrorAction Stop
            foreach ($d in $resp.data) {
                $lookup[$d.cve.ToUpperInvariant()] = [pscustomobject]@{
                    Score      = [double]$d.epss
                    Percentile = [double]$d.percentile
                }
            }
        } catch {
            # Degrade rather than fail: EPSS is enrichment, KEV membership still stands.
            Write-Warning "EPSS batch $([int]($i / $BatchSize) + 1) failed: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 120
    }

    Write-Verbose "EPSS scores resolved for $($lookup.Count)/$($unique.Count) CVEs."
    $lookup
}

function Get-TriagePriority {
<#
.SYNOPSIS
    Applies the prioritization rules to a single enriched CVE.
.DESCRIPTION
    The ordering reflects evidence of real-world exploitation rather than CVSS alone:

      P1        Listed on CISA KEV — confirmed exploited in the wild.
      P1-Watch  Not on KEV, but EPSS >= threshold. This is the gap CVSS-driven
                queues miss: high predicted exploitation before KEV catches up.
      P2        Neither, but the scanner rates it Critical/High.
      P3        Everything else.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [bool]$OnKev,
        [double]$EpssScore,
        [AllowNull()][string]$Severity,
        [double]$EpssThreshold = 0.5,
        [string[]]$EscalateSeverity = @('Critical', 'High')
    )

    if ($OnKev) { return 'P1' }
    if ($EpssScore -ge $EpssThreshold) { return 'P1-Watch' }
    if ($Severity -and ($EscalateSeverity -contains $Severity)) { return 'P2' }
    'P3'
}

function Invoke-VulnTriage {
<#
.SYNOPSIS
    Enriches and prioritizes findings, emitting one record per asset+CVE pair.
.DESCRIPTION
    Findings carrying multiple CVEs are expanded so each CVE is scored on its own
    merits — a single low-risk CVE should not drag a co-listed KEV entry down.
    Findings with no CVE are retained and scored on severity alone.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Finding,
        [Parameter(Mandatory)][hashtable]$ColumnMap,
        [hashtable]$Kev = @{},
        [hashtable]$Epss = @{},
        [double]$EpssThreshold = 0.5,
        [string[]]$EscalateSeverity = @('Critical', 'High')
    )

    $today = (Get-Date).Date
    $out = [System.Collections.Generic.List[object]]::new()

    foreach ($row in $Finding) {
        $get = {
            param($field)
            $col = $ColumnMap[$field]
            if ($col -and $row.PSObject.Properties[$col]) { [string]$row.$col } else { $null }
        }

        $asset    = & $get 'Asset'
        $title    = & $get 'Finding'
        $severity = & $get 'Severity'

        $cves = @(Get-CveFromText (& $get 'Cve'))
        if ($cves.Count -eq 0) { $cves = @($null) }

        foreach ($cve in $cves) {
            $kevEntry  = if ($cve -and $Kev.ContainsKey($cve))  { $Kev[$cve] }  else { $null }
            $epssEntry = if ($cve -and $Epss.ContainsKey($cve)) { $Epss[$cve] } else { $null }

            $onKev     = [bool]$kevEntry
            $epssScore = if ($epssEntry) { $epssEntry.Score } else { 0.0 }

            $priority = Get-TriagePriority -OnKev $onKev -EpssScore $epssScore `
                -Severity $severity -EpssThreshold $EpssThreshold -EscalateSeverity $EscalateSeverity

            $dueDate = if ($kevEntry) { $kevEntry.DueDate } else { $null }
            $overdue = $false
            if ($dueDate) {
                [datetime]$parsed = [datetime]::MinValue
                if ([datetime]::TryParse($dueDate, [ref]$parsed)) { $overdue = $parsed.Date -lt $today }
            }

            $out.Add([pscustomobject]@{
                Asset           = $asset
                Finding         = $title
                Cve             = $cve
                Severity        = $severity
                Priority        = $priority
                OnCisaKev       = $onKev
                KevDateAdded    = if ($kevEntry) { $kevEntry.DateAdded } else { $null }
                KevDueDate      = $dueDate
                KevOverdue      = $overdue
                KnownRansomware = if ($kevEntry) { $kevEntry.KnownRansomwareUse } else { $false }
                EpssScore       = [math]::Round($epssScore, 5)
                EpssPercentile  = if ($epssEntry) { [math]::Round($epssEntry.Percentile, 5) } else { 0.0 }
            })
        }
    }

    $out
}

function Get-TriageSummary {
<#
.SYNOPSIS
    Collapses asset-level records into one row per CVE (or per finding when no CVE).
.DESCRIPTION
    Remediation is planned per vulnerability, not per host, so this rolls up the
    affected-asset count and keeps the worst-case priority and EPSS in the group.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Record)

    $rank = @{ 'P1' = 0; 'P1-Watch' = 1; 'P2' = 2; 'P3' = 3 }

    $Record |
        Group-Object -Property { if ($_.Cve) { $_.Cve } else { "FINDING::$($_.Finding)" } } |
        ForEach-Object {
            $g     = $_.Group
            $worst = $g | Sort-Object { $rank[$_.Priority] } | Select-Object -First 1
            [pscustomobject]@{
                Cve             = $worst.Cve
                Finding         = $worst.Finding
                Severity        = $worst.Severity
                Priority        = $worst.Priority
                OnCisaKev       = $worst.OnCisaKev
                KevDueDate      = $worst.KevDueDate
                KevOverdue      = $worst.KevOverdue
                KnownRansomware = [bool]($g | Where-Object { $_.KnownRansomware })
                MaxEpssScore    = ($g | Measure-Object -Property EpssScore -Maximum).Maximum
                AssetCount      = @($g | Select-Object -ExpandProperty Asset -Unique).Count
                Assets          = (@($g | Select-Object -ExpandProperty Asset -Unique | Sort-Object) -join '; ')
            }
        } |
        Sort-Object @{ Expression = { $rank[$_.Priority] } }, @{ Expression = 'MaxEpssScore'; Descending = $true }
}

function Get-PropertyOrDefault {
    [CmdletBinding()]
    param([object]$InputObject, [string]$Name, $Default = $null)

    if ($null -ne $InputObject -and $InputObject.PSObject.Properties[$Name]) {
        $InputObject.$Name
    } else {
        $Default
    }
}

function ConvertTo-TriageBoolean {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][object]$Value)

    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value)  { return $false }
    ([string]$Value) -iin @('true', '1', 'yes')
}

function ConvertTo-TriageDouble {
    [CmdletBinding()]
    [OutputType([double])]
    param([AllowNull()][object]$Value)

    [double]$parsed = 0.0
    if ($null -ne $Value -and [double]::TryParse([string]$Value,
            [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
        return $parsed
    }
    0.0
}

function ConvertTo-NormalizedSummary {
<#
.SYNOPSIS
    Coerces summary rows into a uniform shape keyed for comparison.
.DESCRIPTION
    A previous run is normally re-read from CSV, where every value is a string,
    while the current run is live objects. Normalizing both sides lets the diff
    compare like with like instead of 'True' against $true.
#>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Row)

    $map = @{}
    foreach ($r in $Row) {
        $cve = [string](Get-PropertyOrDefault $r 'Cve')
        $fnd = [string](Get-PropertyOrDefault $r 'Finding')
        $key = if (-not [string]::IsNullOrWhiteSpace($cve)) { $cve.ToUpperInvariant() } else { "FINDING::$fnd" }

        $map[$key] = [pscustomobject]@{
            Key             = $key
            Cve             = $cve
            Finding         = $fnd
            Severity        = [string](Get-PropertyOrDefault $r 'Severity')
            Priority        = [string](Get-PropertyOrDefault $r 'Priority' 'P3')
            OnCisaKev       = ConvertTo-TriageBoolean (Get-PropertyOrDefault $r 'OnCisaKev')
            KevOverdue      = ConvertTo-TriageBoolean (Get-PropertyOrDefault $r 'KevOverdue')
            KnownRansomware = ConvertTo-TriageBoolean (Get-PropertyOrDefault $r 'KnownRansomware')
            MaxEpssScore    = ConvertTo-TriageDouble  (Get-PropertyOrDefault $r 'MaxEpssScore')
            AssetCount      = [int](ConvertTo-TriageDouble (Get-PropertyOrDefault $r 'AssetCount'))
        }
    }
    $map
}

function Compare-TriageRun {
<#
.SYNOPSIS
    Diffs two triage summaries to show what changed between runs.
.DESCRIPTION
    Answers the question a recurring review meeting actually opens with: what is
    new, what got worse, and what did we actually fix since last time?

    The headline signal is NewlyKev — a CVE you already knew about that CISA has
    since confirmed as exploited in the wild. It was in your backlog yesterday at
    a routine priority; today it is a known-exploited vulnerability on your estate.

    Each item gets one primary Change classification by precedence
    (New > Resolved > Escalated > De-escalated > Unchanged) plus independent
    NewlyKev / EpssSpike flags, since a single item can be several things at once.

.PARAMETER Previous
    Summary rows from the earlier run (live objects or Import-Csv output).

.PARAMETER Current
    Summary rows from this run.

.PARAMETER EpssDelta
    Absolute EPSS increase that counts as a spike worth surfacing.

.PARAMETER IncludeUnchanged
    Emit untouched items too, rather than only what moved.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Previous,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Current,
        [ValidateRange(0.0, 1.0)][double]$EpssDelta = 0.1,
        [switch]$IncludeUnchanged
    )

    $rank = @{ 'P1' = 0; 'P1-Watch' = 1; 'P2' = 2; 'P3' = 3 }
    $prev = ConvertTo-NormalizedSummary -Row $Previous
    $curr = ConvertTo-NormalizedSummary -Row $Current

    $changes = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $curr.Keys) {
        $c = $curr[$key]
        $p = if ($prev.ContainsKey($key)) { $prev[$key] } else { $null }

        $newlyKev  = $c.OnCisaKev -and $p -and -not $p.OnCisaKev
        $epssSpike = $p -and (($c.MaxEpssScore - $p.MaxEpssScore) -ge $EpssDelta)

        $prevRank = if ($p) { $rank[$p.Priority] } else { $null }
        $currRank = $rank[$c.Priority]

        $change =
            if (-not $p)                        { 'New' }
            elseif ($currRank -lt $prevRank)    { 'Escalated' }
            elseif ($currRank -gt $prevRank)    { 'De-escalated' }
            else                                { 'Unchanged' }

        if ($change -eq 'Unchanged' -and -not $IncludeUnchanged -and
            -not $newlyKev -and -not $epssSpike -and
            $c.AssetCount -eq $(if ($p) { $p.AssetCount } else { 0 })) { continue }

        $detail = switch ($change) {
            'New'          { "First seen at $($c.Priority)" }
            'Escalated'    { "$($p.Priority) -> $($c.Priority)" }
            'De-escalated' { "$($p.Priority) -> $($c.Priority)" }
            default        { 'Priority unchanged' }
        }
        if ($newlyKev)  { $detail = "Added to CISA KEV. $detail" }
        if ($epssSpike) { $detail = "$detail. EPSS +$([math]::Round($c.MaxEpssScore - $p.MaxEpssScore, 4))" }

        $changes.Add([pscustomobject]@{
            Change           = $change
            Cve              = $c.Cve
            Finding          = $c.Finding
            Severity         = $c.Severity
            NewlyKev         = $newlyKev
            EpssSpike        = $epssSpike
            PreviousPriority = if ($p) { $p.Priority } else { $null }
            CurrentPriority  = $c.Priority
            PreviousEpss     = if ($p) { $p.MaxEpssScore } else { $null }
            CurrentEpss      = $c.MaxEpssScore
            PreviousAssets   = if ($p) { $p.AssetCount } else { 0 }
            CurrentAssets    = $c.AssetCount
            AssetDelta       = $c.AssetCount - $(if ($p) { $p.AssetCount } else { 0 })
            KnownRansomware  = $c.KnownRansomware
            Detail           = $detail
        })
    }

    foreach ($key in $prev.Keys) {
        if ($curr.ContainsKey($key)) { continue }
        $p = $prev[$key]
        $changes.Add([pscustomobject]@{
            Change           = 'Resolved'
            Cve              = $p.Cve
            Finding          = $p.Finding
            Severity         = $p.Severity
            NewlyKev         = $false
            EpssSpike        = $false
            PreviousPriority = $p.Priority
            CurrentPriority  = $null
            PreviousEpss     = $p.MaxEpssScore
            CurrentEpss      = $null
            PreviousAssets   = $p.AssetCount
            CurrentAssets    = 0
            AssetDelta       = -$p.AssetCount
            KnownRansomware  = $p.KnownRansomware
            Detail           = "No longer present (was $($p.Priority) on $($p.AssetCount) asset(s))"
        })
    }

    # Most actionable first: newly-exploited, then worsening, then new, then wins.
    $order = @{ 'Escalated' = 1; 'New' = 2; 'De-escalated' = 3; 'Resolved' = 4; 'Unchanged' = 5 }
    $changes | Sort-Object `
        @{ Expression = { if ($_.NewlyKev) { 0 } else { 1 } } },
        @{ Expression = { $order[$_.Change] } },
        @{ Expression = 'CurrentEpss'; Descending = $true }
}

Export-ModuleMember -Function Resolve-ColumnMap, Get-CveFromText, Get-KevCatalog,
                              Get-EpssScore, Get-TriagePriority, Invoke-VulnTriage,
                              Get-TriageSummary, Compare-TriageRun
