# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Sanitized Graph fixture contract.

.DESCRIPTION
    Proves every workload has registered sanitized fixtures and that fixture metadata remains baseline/schema aligned.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves every workload has registered sanitized fixtures and that fixture metadata remains baseline/schema aligned.
# Failure significance: A failure here means mocked behavior may stop representing the workload surface it is intended to exercise.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $CatalogPath = Join-Path $ProjectRoot 'Tests\Fixtures\DER-GraphFixtureCatalog.json'
    $SchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-TestFixtureCatalog.schema.json'
    $Catalog = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json -Depth 100
    $Schema = Get-Content -LiteralPath $SchemaPath -Raw | ConvertFrom-Json -Depth 100
}

Describe 'DER sanitized Graph fixture contract' {
    It 'is bound to baseline 1.0.0 and fixture schema 1.0' {
        $Catalog.schemaVersion | Should -Be '1.0'
        $Catalog.generatedForBaseline | Should -Be '1.0.0'
        $Catalog.sanitized | Should -BeTrue
        $Schema.properties.schemaVersion.const | Should -Be '1.0'
    }

    It 'registers all 25 workload modules exactly once' {
        @($Catalog.workloads).Count | Should -Be 25
        @($Catalog.workloads.module | Group-Object | Where-Object Count -ne 1).Count | Should -Be 0
        foreach ($entry in $Catalog.workloads) {
            Test-Path (Join-Path $ProjectRoot ([string]$entry.moduleFile)) | Should -BeTrue
        }
    }

    It 'marks only PasswordProtection and LoggingIntegration as manual-only Graph workloads' {
        $manual = @($Catalog.workloads | Where-Object graphMode -eq 'ManualOnly' | Select-Object -ExpandProperty module | Sort-Object)
        ($manual -join ',') | Should -Be 'LoggingIntegration,PasswordProtection'
        foreach ($entry in @($Catalog.workloads | Where-Object graphMode -eq 'Automatic')) {
            @($entry.interactions).Count | Should -BeGreaterThan 0 -Because "$($entry.module) requires a registered Graph interaction contract"
        }
    }


    It 'matches automatic/manual classification to actual workload Graph usage' {
        foreach ($entry in $Catalog.workloads) {
            $text = Get-Content -LiteralPath (Join-Path $ProjectRoot ([string]$entry.moduleFile)) -Raw
            $hasGraphCall = ($text -match '\bInvoke-DERGraphRequest\b' -or $text -match '\bInvoke-DERGraphCollectionRequest\b')
            if ($entry.graphMode -eq 'Automatic') { $hasGraphCall | Should -BeTrue -Because "$($entry.module) is registered Automatic" }
            else { $hasGraphCall | Should -BeFalse -Because "$($entry.module) is registered ManualOnly" }
        }
    }

    It 'keeps every registered response fixture present and valid JSON' {
        foreach ($fixture in $Catalog.fixtures) {
            $path = Join-Path (Join-Path $ProjectRoot 'Tests\Fixtures') ([string]$fixture.path)
            Test-Path $path | Should -BeTrue
            { Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 100 | Out-Null } | Should -Not -Throw
        }
        foreach ($interaction in @($Catalog.workloads.interactions)) {
            if ($interaction.responseFixture) {
                Test-Path (Join-Path (Join-Path $ProjectRoot 'Tests\Fixtures') ([string]$interaction.responseFixture)) | Should -BeTrue
            }
        }
    }

    It 'contains no obvious real tenant identifiers, bearer tokens, secrets, or routable customer IP data' {
        $all = (Get-ChildItem (Join-Path $ProjectRoot 'Tests\Fixtures') -Recurse -File | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
        $all | Should -Not -Match '(?i)bearer\s+[a-z0-9._-]+'
        $all | Should -Not -Match '(?i)(client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]'
        $all | Should -Not -Match '(?i)@[a-z0-9.-]+\.(com|net|org|gov|edu)\b'
        $all | Should -Not -Match '\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
    }

    It 'uses only synthetic GUIDs when GUID-shaped IDs are present' {
        foreach ($file in Get-ChildItem (Join-Path $ProjectRoot 'Tests\Fixtures\Graph') -Filter '*.json') {
            $text = Get-Content $file.FullName -Raw
            $guids = [regex]::Matches($text,'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
            foreach ($g in $guids) { $g.Value | Should -Match '^00000000-0000-4000-8000-000000000[A-Fa-f0-9]{3}$|^00000000-0000-4000-8000-00000000000[1-9]$' }
        }
    }
}
