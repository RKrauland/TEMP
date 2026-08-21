# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Reporting and manual-action contract.

.DESCRIPTION
    Proves reports, portal guidance, and MAN-ID coverage remain complete enough for operator handoff.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves reports, portal guidance, and MAN-ID coverage remain complete enough for operator handoff.
# Failure significance: A failure here means DER may perform safely yet leave the engineer with incomplete or misleading follow-up guidance.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $CatalogPath = Join-Path $ProjectRoot 'Definitions\Portal\DER-PortalPathCatalog.json'
    $PlannerPath = Join-Path $ProjectRoot 'Core\DER.Planner.psm1'
    $ReportingPath = Join-Path $ProjectRoot 'Core\DER.Reporting.psm1'
    $TemplatesPath = Join-Path $ProjectRoot 'Templates\Reports\DER-ReportTemplates.json'
    $Catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json -Depth 100
    $Templates = Get-Content $TemplatesPath -Raw | ConvertFrom-Json -Depth 100
    Import-Module $ReportingPath -Force
}

Describe 'DER portal-path catalog contract' {
    It 'is baseline aligned and has unique MAN IDs' {
        $Catalog.schemaVersion | Should -Be '1.0'
        $Catalog.generatedForBaseline | Should -Be '1.0.0'
        $ids=@($Catalog.entries.id)
        @($ids|Group-Object|Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'covers every static MAN-ID emitted by the planner' {
        $planner=Get-Content $PlannerPath -Raw
        $plannerIds=@([regex]::Matches($planner,"MAN-[A-Z0-9-]+")|ForEach-Object{$_.Value}|Sort-Object -Unique)
        $catalogIds=@($Catalog.entries.id)
        foreach($id in $plannerIds){$catalogIds | Should -Contain $id}
    }

    It 'has versioned report templates aligned to the baseline' {
        $Templates.schemaVersion | Should -Be '1.0'
        $Templates.generatedForBaseline | Should -Be '1.0.0'
        @($Templates.productionActivationChecklist).Count | Should -BeGreaterThan 0
        $Templates.engineerHandoff.closeRule | Should -Not -BeNullOrEmpty
    }
    It 'uses Microsoft Learn for every exact path source' {
        foreach($entry in $Catalog.entries){
            @($entry.clickPath).Count | Should -BeGreaterThan 0
            @($entry.verification).Count | Should -BeGreaterThan 0
            @($entry.docs).Count | Should -BeGreaterThan 0
            foreach($doc in $entry.docs){$doc.url | Should -Match '^https://learn\.microsoft\.com/'}
        }
    }
}

Describe 'DER manual-action enrichment' {
    It 'expands dynamic metadata into a known manual action' {
        $action=[pscustomobject]@{Id='MAN-SSPR-001';Priority='High';Category='Identity';Title='Enable SSPR';Reason='Test';Metadata=@{Group='ABC - SG - User - 090 - SSPR Pilot'}}
        $enriched=ConvertTo-DEREnrichedManualAction -Action $action -Catalog $Catalog
        $enriched.CatalogMatch | Should -BeTrue
        ($enriched.Steps -join ' ') | Should -Match 'ABC - SG - User - 090 - SSPR Pilot'
        ($enriched.ClickPath -join ' > ') | Should -Match 'Password reset'
    }
    It 'fails safely to generic guidance for generated failure items' {
        $action=[pscustomobject]@{Id='FAIL-DER-COMP-010';Priority='High';Category='Compliance';Title='Failure';Reason='Test';Metadata=$null}
        $enriched=ConvertTo-DEREnrichedManualAction -Action $action -Catalog $Catalog
        $enriched.CatalogMatch | Should -BeFalse
        $enriched.Portal | Should -Be 'Microsoft Intune admin center'
        @($enriched.Verification).Count | Should -BeGreaterThan 0
    }
}

Describe 'DER adoption reporting integration' {
    It 'includes adoption in the machine report, engineer handoff, and report index' {
        $reporting=Get-Content $ReportingPath -Raw
        $parent=Get-Content (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
        $reporting | Should -Match "12 - Adoption Decisions\.html"
        $reporting | Should -Match 'Adoption=\$Adoption'
        $reporting | Should -Match 'Ownership-only customer objects adopted'
        $parent | Should -Match 'New-DERFinalReports[^\r\n]+-Adoption \$adoption'
    }
}
