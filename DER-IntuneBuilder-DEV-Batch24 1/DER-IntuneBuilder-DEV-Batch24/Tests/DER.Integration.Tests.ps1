# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Zero-write integration contract.

.DESCRIPTION
    Proves disposable-tenant integration mode is package-bound, production-blocked, and cryptographically able to prove zero mutations.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves disposable-tenant integration mode is package-bound, production-blocked, and cryptographically able to prove zero mutations.
# Failure significance: A failure here means DER cannot safely use the no-write tenant gate as evidence.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $ParentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
    $GraphPath = Join-Path $ProjectRoot 'Core\DER.Graph.psm1'
    $DryRunPath = Join-Path $ProjectRoot 'Core\DER.DryRun.psm1'
    $IntegrationPath = Join-Path $ProjectRoot 'Core\DER.IntegrationTest.psm1'
    $PolicyPath = Join-Path $ProjectRoot 'Definitions\Integration\DER-TestTenantIntegrationPolicy.json'
    $EvidenceSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-NoWriteEvidence.schema.json'
    $EvidenceSamplePath = Join-Path $ProjectRoot 'Tests\Fixtures\Integration\DER-NoWriteEvidence.sample.json'
    $Parent = Get-Content -LiteralPath $ParentPath -Raw
    $Graph = Get-Content -LiteralPath $GraphPath -Raw
    $DryRun = Get-Content -LiteralPath $DryRunPath -Raw
    $Integration = Get-Content -LiteralPath $IntegrationPath -Raw
    $Policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -Depth 100
    $EvidenceSample = Get-Content -LiteralPath $EvidenceSamplePath -Raw | ConvertFrom-Json -Depth 100
    Import-Module -Name $IntegrationPath -Force -ErrorAction Stop
}

Describe 'DER disposable test-tenant integration policy' {
    It 'is package-bound and explicitly excludes production tenants' {
        $Policy.schemaVersion | Should -Be '1.0'
        $Policy.policyVersion | Should -Be '1.0.0'
        $Policy.generatedForPackage | Should -Be '1.0.0-dev'
        $Policy.generatedForBuild | Should -BeGreaterThan 0
        $Policy.tenantSafety.disposableTestTenantRequired | Should -BeTrue
        $Policy.tenantSafety.productionTenantAllowed | Should -BeFalse
        $Policy.tenantSafety.operatorConfirmationToken | Should -Be 'TEST-TENANT'
    }

    It 'permits only GET at the Graph transport boundary' {
        @($Policy.graphSafety.allowedTransportMethods).Count | Should -Be 1
        @($Policy.graphSafety.allowedTransportMethods) | Should -Contain 'GET'
        @($Policy.graphSafety.mutationMethods).Count | Should -Be 4
        foreach($method in @('POST','PATCH','PUT','DELETE')) { @($Policy.graphSafety.mutationMethods) | Should -Contain $method }
        $Policy.graphSafety.writeGuardMode | Should -Be 'DenyAll'
        $Policy.graphSafety.transportMutationCountMustEqual | Should -Be 0
        $Policy.graphSafety.blockedMutationAttemptCountMustEqual | Should -Be 0
        $Policy.authentication.writeSessionAllowed | Should -BeFalse
    }

    It 'requires the complete no-write evidence check set' {
        @($Policy.evidence.requiredChecks).Count | Should -Be 12
        foreach($id in @('INT-000','INT-001','INT-002','INT-003','INT-004','INT-005','INT-006','INT-007','INT-008','INT-009','INT-010','INT-011')) {
            @($Policy.evidence.requiredChecks) | Should -Contain $id
        }
        Test-Path -LiteralPath $EvidenceSchemaPath | Should -BeTrue
        Test-Path -LiteralPath $EvidenceSamplePath | Should -BeTrue
        $EvidenceSample.passed | Should -BeTrue
        $EvidenceSample.graphAudit.TransportWriteCount | Should -Be 0
    }
}

Describe 'DER integration-mode parent orchestration' {
    It 'forwards the explicit integration switch through PowerShell bootstrap/relaunch' {
        $Parent | Should -Match '\[switch\]\$TenantIntegrationTest'
        $Parent | Should -Match '\$items\.Add\(''-TenantIntegrationTest''\)'
    }

    It 'enables DENY-ALL before discovery authentication and requires test-tenant attestation' {
        $guardIndex = $Parent.IndexOf("Set-DERGraphWriteGuard -Mode DenyAll")
        $authIndex = $Parent.IndexOf('$discoverySession = Connect-DERDiscoverySession')
        $attestIndex = $Parent.IndexOf('$integrationAttestation = Confirm-DERTestTenant')
        $guardIndex | Should -BeGreaterThan -1
        $authIndex | Should -BeGreaterThan $guardIndex
        $attestIndex | Should -BeGreaterThan $authIndex
    }

    It 'never opens a write session in integration mode' {
        $Parent | Should -Match 'if \(-not \$TenantIntegrationTest -and -not \$permissionPlan\.ReportOnly'
        $Parent | Should -Match 'Invoke-DERDryRun[^\r\n]+-IntegrationNoWrite -SkipFinalApproval'
        $Parent | Should -Match 'Test-tenant integration mode skips adoption decisions'
    }

    It 'generates evidence and exits before workload execution' {
        $evidenceIndex = $Parent.IndexOf('$integrationEvidence = New-DERNoWriteEvidence')
        $exitMarker = $Parent.IndexOf('DER TEST-TENANT INTEGRATION RESULT: PASS', $evidenceIndex)
        $workloadIndex = $Parent.IndexOf("'Executing approved DER workload modules...'", $evidenceIndex)
        $evidenceIndex | Should -BeGreaterThan -1
        $exitMarker | Should -BeGreaterThan $evidenceIndex
        $workloadIndex | Should -BeGreaterThan $exitMarker
    }
}

Describe 'DER Graph transport no-write guard' {
    It 'checks DenyAll before session assertion and before Invoke-MgGraphRequest transport' {
        $invokeStart = $Graph.IndexOf('function Invoke-DERGraphRequest')
        $guardIndex = $Graph.IndexOf("WriteGuardMode -eq 'DenyAll'", $invokeStart)
        $sessionIndex = $Graph.IndexOf('$null=Assert-DERGraphSession', $invokeStart)
        $transportIndex = $Graph.IndexOf('$response=Invoke-MgGraphRequest @p', $invokeStart)
        $guardIndex | Should -BeGreaterThan $invokeStart
        $sessionIndex | Should -BeGreaterThan $guardIndex
        $transportIndex | Should -BeGreaterThan $sessionIndex
    }

    It 'records transport counters and a forensic transport event' {
        $Graph | Should -Match 'TransportWriteCount'
        $Graph | Should -Match 'BlockedWriteCount'
        $Graph | Should -Match "phase='transport'"
        $Graph | Should -Match "phase='blocked-write'"
        $Graph | Should -Match "transportInvoked=\$false"
        $Graph | Should -Match 'Get-DERGraphRequestAuditSummary'
    }

    It 'has no direct Graph SDK transport outside DER.Graph in runtime source' {
        $findings = @()
        foreach($folder in @('Core','Workloads')) {
            foreach($file in Get-ChildItem -LiteralPath (Join-Path $ProjectRoot $folder) -File -Filter '*.psm1') {
                if($file.FullName -eq $GraphPath) { continue }
                $raw = Get-Content -LiteralPath $file.FullName -Raw
                if($raw -match '\bInvoke-MgGraphRequest\b') { $findings += $file.FullName }
            }
        }
        @($findings).Count | Should -Be 0
    }

    It 'passes the runtime AST bypass scan across parent, Core, and Workloads' {
        $runtimeFindings = @(Get-DERIntegrationBypassFindings -PackageRoot $ProjectRoot)
        @($runtimeFindings).Count | Should -Be 0
    }
}

Describe 'DER dry-run integration contract' {
    It 'does not require or grant final build approval in integration mode' {
        $DryRun | Should -Match '\[switch\]\$IntegrationNoWrite'
        $DryRun | Should -Match '-and -not \$IntegrationNoWrite'
        $DryRun | Should -Match "IntegrationNoWrite=\[bool\]\$IntegrationNoWrite"
        $DryRun | Should -Match 'Integration no-write mode calculated'
    }

    It 'treats a write-authenticated session as a blocking integration failure' {
        $DryRun | Should -Match 'Integration no-write mode detected a write-authenticated Graph session'
        $DryRun | Should -Match 'Central Graph DENY-ALL write guard is not active'
        $DryRun | Should -Match 'At least one Graph mutation reached transport during integration mode'
    }
}

Describe 'DER no-write evidence engine' {
    It 'contains no Microsoft Graph request or authentication command' {
        $Integration | Should -Not -Match '(?m)^\s*(Connect-MgGraph|Disconnect-MgGraph|Invoke-MgGraphRequest)\b'
    }

    It 'fails evidence if a write was attempted even when the guard blocked it' {
        $Integration | Should -Match "INT-006"
        $Integration | Should -Match 'BlockedWriteCount -eq 0'
        $Integration | Should -Match 'MutationTransportEvents'
        $Integration | Should -Match 'Get-DERIntegrationBypassFindings'
        $Integration | Should -Match 'Get-DERTransactionJournal'
    }
}
