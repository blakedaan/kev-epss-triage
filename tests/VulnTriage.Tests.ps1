#Requires -Version 7.0
<#
    Offline test suite — no network access required. KEV and EPSS data are loaded
    from tests/fixtures, so results are deterministic and CI-safe.

    Run:  Invoke-Pester -Path .\tests
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:Root 'src' 'VulnTriage.psm1') -Force

    $script:KevFixture  = Join-Path $PSScriptRoot 'fixtures' 'kev-sample.json'
    $script:EpssFixture = Join-Path $PSScriptRoot 'fixtures' 'epss-sample.json'
    $script:SampleCsv   = Join-Path $script:Root  'samples' 'sample-findings.csv'

    $script:Kev  = Get-KevCatalog -Path $script:KevFixture
    $script:Epss = Get-EpssScore  -Path $script:EpssFixture
}

Describe 'Get-CveFromText' {
    It 'extracts a single CVE' {
        Get-CveFromText 'CVE-2021-44228' | Should -Be 'CVE-2021-44228'
    }

    It 'extracts multiple CVEs regardless of delimiter' {
        $r = Get-CveFromText 'CVE-2021-44228, CVE-2017-0144; CVE-2019-0708 CVE-2014-0160'
        $r.Count | Should -Be 4
        $r | Should -Contain 'CVE-2019-0708'
    }

    It 'normalizes case' {
        Get-CveFromText 'cve-2021-44228' | Should -Be 'CVE-2021-44228'
    }

    It 'deduplicates repeats' {
        (Get-CveFromText 'CVE-2021-44228, CVE-2021-44228').Count | Should -Be 1
    }

    It 'returns empty for null, blank, or non-CVE text' {
        @(Get-CveFromText $null).Count   | Should -Be 0
        @(Get-CveFromText '   ').Count   | Should -Be 0
        @(Get-CveFromText 'N/A').Count   | Should -Be 0
    }

    It 'ignores malformed identifiers' {
        @(Get-CveFromText 'CVE-21-1 CVE-2021-ABCD').Count | Should -Be 0
    }

    It 'handles 5-digit CVE sequence numbers' {
        Get-CveFromText 'CVE-2023-12345' | Should -Be 'CVE-2023-12345'
    }
}

Describe 'Resolve-ColumnMap' {
    It 'auto-detects non-obvious scanner headers' {
        $map = Resolve-ColumnMap -Header @('hostname', 'plugin_name', 'cve_ids', 'risk_factor')
        $map['Asset']    | Should -Be 'hostname'
        $map['Finding']  | Should -Be 'plugin_name'
        $map['Cve']      | Should -Be 'cve_ids'
        $map['Severity'] | Should -Be 'risk_factor'
    }

    It 'matches headers case-insensitively' {
        (Resolve-ColumnMap -Header @('CVE', 'Host'))['Cve'] | Should -Be 'CVE'
    }

    It 'lets an explicit mapping override auto-detection' {
        $map = Resolve-ColumnMap -Header @('cve', 'custom_cve') -ColumnMap @{ Cve = 'custom_cve' }
        $map['Cve'] | Should -Be 'custom_cve'
    }

    It 'leaves optional fields null when absent' {
        (Resolve-ColumnMap -Header @('cve'))['Asset'] | Should -BeNullOrEmpty
    }

    It 'throws when no CVE column can be found' {
        { Resolve-ColumnMap -Header @('host', 'title') } | Should -Throw '*Could not find a CVE column*'
    }

    It 'throws when an explicit mapping points at a missing header' {
        { Resolve-ColumnMap -Header @('cve') -ColumnMap @{ Asset = 'nope' } } | Should -Throw "*'nope'*"
    }
}

Describe 'Get-KevCatalog' {
    It 'loads every entry from the fixture' {
        $script:Kev.Count | Should -Be 4
    }

    It 'keys the lookup by uppercase CVE' {
        $script:Kev.ContainsKey('CVE-2021-44228') | Should -BeTrue
    }

    It 'converts the ransomware field to a boolean' {
        $script:Kev['CVE-2021-44228'].KnownRansomwareUse | Should -BeTrue
        $script:Kev['CVE-2021-45046'].KnownRansomwareUse | Should -BeFalse
    }

    It 'preserves the remediation due date' {
        $script:Kev['CVE-2017-0144'].DueDate | Should -Be '2022-03-17'
    }
}

Describe 'Get-EpssScore' {
    It 'loads scores from the fixture' {
        $script:Epss.Count | Should -Be 6
    }

    It 'exposes the score as a number, not a string' {
        $script:Epss['CVE-2021-44228'].Score | Should -BeOfType [double]
        $script:Epss['CVE-2021-44228'].Score | Should -BeGreaterThan 0.9
    }

    It 'returns an empty lookup when given no CVEs' {
        (Get-EpssScore -Cve @()).Count | Should -Be 0
    }
}

Describe 'Get-TriagePriority' {
    It 'rates a KEV-listed CVE as P1 even with a low EPSS score' {
        Get-TriagePriority -OnKev $true -EpssScore 0.001 -Severity 'Low' | Should -Be 'P1'
    }

    It 'rates a high-EPSS non-KEV CVE as P1-Watch' {
        Get-TriagePriority -OnKev $false -EpssScore 0.94 -Severity 'High' | Should -Be 'P1-Watch'
    }

    It 'treats the threshold as inclusive' {
        Get-TriagePriority -OnKev $false -EpssScore 0.5 -Severity 'Low' -EpssThreshold 0.5 | Should -Be 'P1-Watch'
    }

    It 'honours a custom threshold' {
        Get-TriagePriority -OnKev $false -EpssScore 0.31 -Severity 'Low' -EpssThreshold 0.3 | Should -Be 'P1-Watch'
    }

    It 'falls back to severity for low-EPSS findings' {
        Get-TriagePriority -OnKev $false -EpssScore 0.01 -Severity 'Critical' | Should -Be 'P2'
        Get-TriagePriority -OnKev $false -EpssScore 0.01 -Severity 'High'     | Should -Be 'P2'
    }

    It 'rates everything else P3' {
        Get-TriagePriority -OnKev $false -EpssScore 0.01 -Severity 'Medium' | Should -Be 'P3'
        Get-TriagePriority -OnKev $false -EpssScore 0.01 -Severity $null    | Should -Be 'P3'
    }
}

Describe 'Invoke-VulnTriage' {
    BeforeAll {
        $script:Findings = @(Import-Csv -LiteralPath $script:SampleCsv)
        $script:Map      = Resolve-ColumnMap -Header $script:Findings[0].PSObject.Properties.Name
        $script:Records  = @(Invoke-VulnTriage -Finding $script:Findings -ColumnMap $script:Map `
                                -Kev $script:Kev -Epss $script:Epss)
    }

    It 'expands a multi-CVE row into one record per CVE' {
        @($script:Records | Where-Object { $_.Asset -eq 'web-01' }).Count | Should -Be 2
    }

    It 'retains findings that carry no CVE' {
        $r = $script:Records | Where-Object { $_.Asset -eq 'db-01' }
        $r               | Should -Not -BeNullOrEmpty
        $r.Cve           | Should -BeNullOrEmpty
        $r.Priority      | Should -Be 'P3'
    }

    It 'flags KEV membership and ransomware linkage' {
        $r = $script:Records | Where-Object { $_.Asset -eq 'app-01' }
        $r.OnCisaKev       | Should -BeTrue
        $r.KnownRansomware | Should -BeTrue
        $r.Priority        | Should -Be 'P1'
    }

    It 'escalates a high-EPSS CVE that is not on KEV' {
        $r = $script:Records | Where-Object { $_.Cve -eq 'CVE-2014-0160' } | Select-Object -First 1
        $r.OnCisaKev | Should -BeFalse
        $r.Priority  | Should -Be 'P1-Watch'
    }

    It 'marks a past KEV due date as overdue' {
        ($script:Records | Where-Object { $_.Cve -eq 'CVE-2017-0144' } | Select-Object -First 1).KevOverdue |
            Should -BeTrue
    }

    It 'does not mark a future KEV due date as overdue' {
        ($script:Records | Where-Object { $_.Cve -eq 'CVE-2019-0708' } | Select-Object -First 1).KevOverdue |
            Should -BeFalse
    }

    It 'scores an unknown CVE as zero rather than failing' {
        $rec = @(Invoke-VulnTriage -Finding @([pscustomobject]@{ cve = 'CVE-2000-1111' }) `
                    -ColumnMap @{ Cve = 'cve' } -Kev $script:Kev -Epss $script:Epss)
        $rec[0].EpssScore | Should -Be 0
        $rec[0].Priority  | Should -Be 'P3'
    }
}

Describe 'Get-TriageSummary' {
    BeforeAll {
        $findings = @(Import-Csv -LiteralPath $script:SampleCsv)
        $map      = Resolve-ColumnMap -Header $findings[0].PSObject.Properties.Name
        $records  = @(Invoke-VulnTriage -Finding $findings -ColumnMap $map -Kev $script:Kev -Epss $script:Epss)
        $script:Summary = @(Get-TriageSummary -Record $records)
    }

    It 'collapses duplicate CVEs across assets' {
        @($script:Summary | Where-Object { $_.Cve -eq 'CVE-2021-44228' }).Count | Should -Be 1
    }

    It 'counts every affected asset' {
        ($script:Summary | Where-Object { $_.Cve -eq 'CVE-2014-0160' }).AssetCount | Should -Be 2
    }

    It 'lists the affected assets' {
        ($script:Summary | Where-Object { $_.Cve -eq 'CVE-2014-0160' }).Assets | Should -Be 'lb-01; lb-02'
    }

    It 'sorts the most urgent item first' {
        $script:Summary[0].Priority | Should -Be 'P1'
    }

    It 'keeps CVE-less findings as distinct rows' {
        @($script:Summary | Where-Object { -not $_.Cve }).Count | Should -Be 2
    }

    It 'returns nothing for an empty record set' {
        @(Get-TriageSummary -Record @()).Count | Should -Be 0
    }
}
