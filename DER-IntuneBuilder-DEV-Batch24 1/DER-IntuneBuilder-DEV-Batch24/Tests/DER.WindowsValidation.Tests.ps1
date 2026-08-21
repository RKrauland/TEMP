# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Windows execution-gate contract.

.DESCRIPTION
    Proves preflight/smoke policy, schema bindings, runtime versions, analyzer/Pester requirements, and tenant-blind Windows checks remain aligned.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves preflight/smoke policy, schema bindings, runtime versions, analyzer/Pester requirements, and tenant-blind Windows checks remain aligned.
# Failure significance: A failure here means the package is not ready to use its Windows execution gate as release evidence.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $ParentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
    $PolicyPath = Join-Path $ProjectRoot 'Definitions\Validation\DER-WindowsValidationPolicy.json'
    $PolicySchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-WindowsValidationPolicy.schema.json'
    $BindingsPath = Join-Path $ProjectRoot 'Definitions\Validation\DER-SchemaBindings.json'
    $BindingsSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-SchemaBindings.schema.json'
    $PreflightPath = Join-Path $ProjectRoot 'Tools\Invoke-DERWindowsPreflight.ps1'
    $SmokePath = Join-Path $ProjectRoot 'Tools\Invoke-DERWindowsSmokeTest.ps1'
    $Parent = Get-Content -LiteralPath $ParentPath -Raw
    $Policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json -Depth 100
    $Bindings = Get-Content -LiteralPath $BindingsPath -Raw | ConvertFrom-Json -Depth 100
    $Preflight = Get-Content -LiteralPath $PreflightPath -Raw
    $Smoke = Get-Content -LiteralPath $SmokePath -Raw
}
Describe 'DER Windows preflight safety contract' {
    It 'is package-bound and tenant-blind' {
        $Policy.schemaVersion | Should -Be '1.0'
        $Policy.policyVersion | Should -Be '1.0.0'
        $Policy.generatedForPackage | Should -Be '1.0.0-dev'
        $Policy.generatedForBuild | Should -BeGreaterThan 0
        $Policy.platform.os | Should -Be 'Windows'
        $Policy.platform.minimumPowerShell | Should -Be '7.4.0'
        $Policy.platform.preferredPowerShell | Should -Be '7.6.4'
        $Policy.safety.tenantBlind | Should -BeTrue
        $Policy.safety.graphAuthenticationAllowed | Should -BeFalse
        $Policy.safety.graphRequestsAllowed | Should -BeFalse
        $Policy.safety.tenantMutationAllowed | Should -BeFalse
        $graphEndpoint = @($Policy.endpoints | Where-Object id -eq 'MicrosoftGraph') | Select-Object -First 1
        $graphEndpoint.checkType | Should -Be 'Tls'
        $graphEndpoint.host | Should -Be 'graph.microsoft.com'
        $Preflight | Should -Match 'Net\.Security\.SslStream'
    }
    It 'runs package integrity and preflight before Graph dependency load/authentication' {
        $packageIndex = $Parent.IndexOf('Test-DERBootstrapPackageIntegrity | Out-Null')
        $preflightIndex = $Parent.IndexOf('$preflightResult = Invoke-DERWindowsPreflightGate')
        $dependencyIndex = $Parent.IndexOf('Initialize-DERGraphAuthenticationModule', $preflightIndex)
        $authIndex = $Parent.IndexOf('$discoverySession = Connect-DERDiscoverySession', $preflightIndex)
        $packageIndex | Should -BeGreaterThan -1
        $preflightIndex | Should -BeGreaterThan $packageIndex
        $dependencyIndex | Should -BeGreaterThan $preflightIndex
        $authIndex | Should -BeGreaterThan $dependencyIndex
    }
    It 'provides explicit no-auth preflight and smoke modes and forwards them through bootstrap' {
        $Parent | Should -Match '\[switch\]\$PreflightOnly'
        $Parent | Should -Match '\[switch\]\$SmokeTestOnly'
        $Parent | Should -Match '\[switch\]\$InstallTestDependencies'
        $Parent | Should -Match '\$items\.Add\(''-PreflightOnly''\)'
        $Parent | Should -Match '\$items\.Add\(''-SmokeTestOnly''\)'
        $Parent | Should -Match 'DER PREFLIGHT-ONLY RESULT: PASS'
        $Parent | Should -Match 'DER SMOKE-TEST-ONLY RESULT: PASS'
    }
    It 'keeps the preflight and smoke tools free of Graph authentication/mutation calls' {
        $Preflight | Should -Not -Match '(?m)^\s*(Connect-MgGraph|Invoke-MgGraphRequest|Disconnect-MgGraph)\b'
        $Smoke | Should -Not -Match '(?m)^\s*(Connect-MgGraph|Invoke-MgGraphRequest|Disconnect-MgGraph)\b'
        $Preflight | Should -Match 'graphAuthenticationPerformed=\$false'
        $Smoke | Should -Match 'graphAuthenticationPerformed=\$false'
    }
}
Describe 'DER Windows smoke-test contract' {
    It 'pins the maintenance Pester 5 line instead of silently using Pester 6' {
        $Policy.smokeTest.pester.majorVersion | Should -Be 5
        $Policy.smokeTest.pester.preferredVersion | Should -Be '5.9.0'
        $Policy.smokeTest.pester.allowPester6 | Should -BeFalse
        $Smoke | Should -Match 'Save-PSResource -Name Pester'
        $Smoke | Should -Match 'New-PesterConfiguration'
        $Smoke | Should -Match 'Invoke-Pester -Configuration'
    }
    It 'pins and executes PSScriptAnalyzer as a separate Windows smoke stage' {
        $Policy.smokeTest.psScriptAnalyzer.preferredVersion | Should -Be '1.24.0'
        $Policy.smokeTest.psScriptAnalyzer.isolatedRuntimeCache | Should -BeTrue
        @($Policy.smokeTest.psScriptAnalyzer.failOnSeverity) | Should -Contain 'Error'
        $Smoke | Should -Match 'Save-PSResource -Name PSScriptAnalyzer'
        $Smoke | Should -Match 'Invoke-ScriptAnalyzer -Path \$ProjectRoot -Recurse'
        $Smoke | Should -Match 'PSScriptAnalyzer-Results\.json'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'PSScriptAnalyzer'
    }
    It 'performs native parser, JSON, schema, module-import, analyzer, and Pester stages' {
        $Smoke | Should -Match 'System\.Management\.Automation\.Language\.Parser'
        $Smoke | Should -Match 'ConvertFrom-Json'
        $Smoke | Should -Match 'Test-Json -LiteralPath .* -SchemaFile'
        $Smoke | Should -Match 'Import-Module -Name \$path'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'PowerShellParse'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'JsonSchema'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'ModuleImport'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'PSScriptAnalyzer'
        @($Policy.smokeTest.requiredStages) | Should -Contain 'Pester'
    }
}
Describe 'DER static JSON Schema binding catalog' {
    It 'has existing unique schema/document bindings' {
        Test-Path $PolicySchemaPath | Should -BeTrue
        Test-Path $BindingsSchemaPath | Should -BeTrue
        $ids=@($Bindings.bindings.id)
        @($ids|Group-Object|Where-Object Count -gt 1).Count | Should -Be 0
        foreach($binding in @($Bindings.bindings)){
            Test-Path (Join-Path $ProjectRoot (([string]$binding.schema).Replace('/',[IO.Path]::DirectorySeparatorChar))) | Should -BeTrue
            foreach($document in @($binding.documents)){
                Test-Path (Join-Path $ProjectRoot (([string]$document).Replace('/',[IO.Path]::DirectorySeparatorChar))) | Should -BeTrue
            }
        }
    }
    It 'explicitly identifies runtime-only schemas that are covered by Pester' {
        @($Bindings.runtimeOnlySchemas.schema) | Should -Contain 'Definitions/Schema/DER-PortableState.schema.json'
        @($Bindings.runtimeOnlySchemas.schema) | Should -Contain 'Definitions/Schema/DER-AdoptionDecisions.schema.json'
        foreach($item in @($Bindings.runtimeOnlySchemas)){
            Test-Path (Join-Path $ProjectRoot (([string]$item.schema).Replace('/',[IO.Path]::DirectorySeparatorChar))) | Should -BeTrue
            Test-Path (Join-Path $ProjectRoot (([string]$item.validatedBy).Replace('/',[IO.Path]::DirectorySeparatorChar))) | Should -BeTrue
        }
    }
}
