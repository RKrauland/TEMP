# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Core package and baseline contract.

.DESCRIPTION
    Proves baseline identity, schemas, package metadata, catalogs, templates, and core helper assumptions stay internally coherent.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves baseline identity, schemas, package metadata, catalogs, templates, and core helper assumptions stay internally coherent.
# Failure significance: A failure here means a foundational package assumption is no longer trustworthy.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $ParentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
    $BaselinePath = Join-Path $ProjectRoot 'Definitions\Baselines\1.0.0\DER-Baseline.json'
    $IndexPath = Join-Path $ProjectRoot 'Definitions\Baselines\1.0.0\DER-Baseline.index.json'
    $ManifestPath = Join-Path $ProjectRoot 'Definitions\Baselines\1.0.0\DER-Baseline.manifest.json'
    $CatalogPath = Join-Path $ProjectRoot 'Definitions\Compatibility\DER-CompatibilityCatalog.json'
    $SchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-Definition.schema.json'
    $PortableSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-PortableState.schema.json'
    $PortalCatalogPath = Join-Path $ProjectRoot 'Definitions\Portal\DER-PortalPathCatalog.json'
    $PortalSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-PortalPathCatalog.schema.json'
    $ReportTemplatesPath = Join-Path $ProjectRoot 'Templates\Reports\DER-ReportTemplates.json'
    $ReportTemplatesSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-ReportTemplates.schema.json'
    $FixtureCatalogPath = Join-Path $ProjectRoot 'Tests\Fixtures\DER-GraphFixtureCatalog.json'
    $FixtureCatalogSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-TestFixtureCatalog.schema.json'
    $AdoptionCatalogPath = Join-Path $ProjectRoot 'Definitions\Adoption\DER-AdoptionCatalog.json'
    $AdoptionCatalogSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-AdoptionCatalog.schema.json'
    $AdoptionDecisionsSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-AdoptionDecisions.schema.json'
    $RecoveryPolicyPath = Join-Path $ProjectRoot 'Definitions\Recovery\DER-RecoveryPolicy.json'
    $RecoveryPolicySchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-RecoveryPolicy.schema.json'
    $PackageManifestPath = Join-Path $ProjectRoot 'Definitions\Package\DER-PackageManifest.json'
    $UpdateManifestPath = Join-Path $ProjectRoot 'Definitions\Package\DER-UpdateManifest.json'
    $DependencyLockPath = Join-Path $ProjectRoot 'Definitions\Package\DER-DependencyLock.json'
    $SigningPolicyPath = Join-Path $ProjectRoot 'Definitions\Package\DER-SigningPolicy.json'
    $PackageManifestSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-PackageManifest.schema.json'
    $UpdateManifestSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-UpdateManifest.schema.json'
    $DependencyLockSchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-DependencyLock.schema.json'
    $SigningPolicySchemaPath = Join-Path $ProjectRoot 'Definitions\Schema\DER-SigningPolicy.schema.json'
    $Baseline = Get-Content $BaselinePath -Raw | ConvertFrom-Json -Depth 100
    $Index = Get-Content $IndexPath -Raw | ConvertFrom-Json -Depth 100
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json -Depth 100
    $Catalog = Get-Content $CatalogPath -Raw | ConvertFrom-Json -Depth 100
    $Schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json -Depth 100
    $PortableSchema = Get-Content $PortableSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $PortalCatalog = Get-Content $PortalCatalogPath -Raw | ConvertFrom-Json -Depth 100
    $PortalSchema = Get-Content $PortalSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $ReportTemplates = Get-Content $ReportTemplatesPath -Raw | ConvertFrom-Json -Depth 100
    $ReportTemplatesSchema = Get-Content $ReportTemplatesSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $FixtureCatalog = Get-Content $FixtureCatalogPath -Raw | ConvertFrom-Json -Depth 100
    $FixtureCatalogSchema = Get-Content $FixtureCatalogSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $AdoptionCatalog = Get-Content $AdoptionCatalogPath -Raw | ConvertFrom-Json -Depth 100
    $AdoptionCatalogSchema = Get-Content $AdoptionCatalogSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $AdoptionDecisionsSchema = Get-Content $AdoptionDecisionsSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $RecoveryPolicy = Get-Content $RecoveryPolicyPath -Raw | ConvertFrom-Json -Depth 100
    $RecoveryPolicySchema = Get-Content $RecoveryPolicySchemaPath -Raw | ConvertFrom-Json -Depth 100
    $PackageManifest = Get-Content $PackageManifestPath -Raw | ConvertFrom-Json -Depth 100
    $UpdateManifest = Get-Content $UpdateManifestPath -Raw | ConvertFrom-Json -Depth 100
    $DependencyLock = Get-Content $DependencyLockPath -Raw | ConvertFrom-Json -Depth 100
    $SigningPolicy = Get-Content $SigningPolicyPath -Raw | ConvertFrom-Json -Depth 100
    $PackageManifestSchema = Get-Content $PackageManifestSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $UpdateManifestSchema = Get-Content $UpdateManifestSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $DependencyLockSchema = Get-Content $DependencyLockSchemaPath -Raw | ConvertFrom-Json -Depth 100
    $SigningPolicySchema = Get-Content $SigningPolicySchemaPath -Raw | ConvertFrom-Json -Depth 100
}
Describe 'DER package contract' {
    It 'contains 19 Core modules and 25 Workload modules' {
        @(Get-ChildItem (Join-Path $ProjectRoot 'Core') -Filter '*.psm1').Count | Should -Be 19
        @(Get-ChildItem (Join-Path $ProjectRoot 'Workloads') -Filter '*.psm1').Count | Should -Be 25
    }
    It 'keeps baseline/schema/catalog versions aligned' {
        $parent = Get-Content $ParentPath -Raw
        $parent | Should -Match "DERBaselineVersion\s*=\s*'1\.0\.0'"
        $parent | Should -Match "DERDefinitionSchema\s*=\s*'1\.0'"
        $parent | Should -Match "DERPortableStateVersion\s*=\s*'1\.0'"
        $Baseline.baselineVersion | Should -Be '1.0.0'
        $Index.baselineVersion | Should -Be '1.0.0'
        $Catalog.generatedForBaseline | Should -Be '1.0.0'
        $Schema.properties.schemaVersion.const | Should -Be '1.0'
        $PortableSchema.properties.PortableStateVersion.const | Should -Be '1.0'
        $PortalCatalog.generatedForBaseline | Should -Be '1.0.0'
        $PortalSchema.properties.schemaVersion.const | Should -Be '1.0'
        $ReportTemplates.generatedForBaseline | Should -Be '1.0.0'
        $ReportTemplatesSchema.properties.schemaVersion.const | Should -Be '1.0'
        $FixtureCatalog.generatedForBaseline | Should -Be '1.0.0'
        $FixtureCatalogSchema.properties.schemaVersion.const | Should -Be '1.0'
        $AdoptionCatalog.generatedForBaseline | Should -Be '1.0.0'
        $AdoptionCatalogSchema.properties.schemaVersion.const | Should -Be '1.0'
        $AdoptionDecisionsSchema.properties.schemaVersion.const | Should -Be '1.0'
        $RecoveryPolicy.generatedForBaseline | Should -Be '1.0.0'
        $RecoveryPolicy.journalVersion | Should -Be '1.1'
        $RecoveryPolicySchema.properties.schemaVersion.const | Should -Be '1.0'
        $PackageManifest.schemaVersion | Should -Be '1.0'
        $PackageManifest.packageVersion | Should -Be '1.0.0-dev'
        $PackageManifest.buildNumber | Should -BeGreaterThan 0
        $PackageManifest.engineVersion | Should -Be '1.0.0-dev'
        $PackageManifest.baselineVersion | Should -Be '1.0.0'
        $UpdateManifest.packageVersion | Should -Be $PackageManifest.packageVersion
        $UpdateManifest.buildNumber | Should -Be $PackageManifest.buildNumber
        $UpdateManifest.dependencies.lockVersion | Should -Be $DependencyLock.lockVersion
        $PackageManifestSchema.properties.schemaVersion.const | Should -Be '1.0'
        $UpdateManifestSchema.properties.schemaVersion.const | Should -Be '1.0'
        $DependencyLockSchema.properties.schemaVersion.const | Should -Be '1.0'
        $SigningPolicySchema.properties.schemaVersion.const | Should -Be '1.0'
        $SigningPolicy.development.unsignedAllowed | Should -BeTrue
        $SigningPolicy.release.authenticodeRequired | Should -BeTrue
    }
    It 'has unique baseline DER IDs' {
        $ids = @($Index.definitions.derId)
        $ids.Count | Should -BeGreaterThan 0
        @($ids | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'keeps the feature-update target mirrored in questionnaire, workload fallback, and baseline' {
        $target = [string]$Baseline.defaults.updates.targetFeatureUpdateVersion
        (Get-Content (Join-Path $ProjectRoot 'Core\DER.Questionnaire.psm1') -Raw) | Should -Match ([regex]::Escape($target))
        (Get-Content (Join-Path $ProjectRoot 'Workloads\DER.Updates.psm1') -Raw) | Should -Match ([regex]::Escape($target))
    }
    It 'has no missing parent child-module files or entry points' {
        $parent = Get-Content $ParentPath -Raw
        $rows = [regex]::Matches($parent, "File = '([^']+)'\s*;\s*EntryPoint = '([^']+)'")
        $rows.Count | Should -Be 44
        foreach ($r in $rows) {
            $file = Join-Path $ProjectRoot $r.Groups[1].Value
            Test-Path $file | Should -BeTrue
            (Get-Content $file -Raw) | Should -Match ("function\s+" + [regex]::Escape($r.Groups[2].Value) + "\b")
        }
    }
    It 'has valid baseline manifest hashes' {
        foreach ($f in $Manifest.files) {
            $path = Join-Path (Split-Path $ManifestPath -Parent) $f.path
            (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() | Should -Be $f.sha256
        }
    }
}
Describe 'DER exported pure helpers' {
    BeforeAll {
        Import-Module (Join-Path $ProjectRoot 'Core\DER.Questionnaire.psm1') -Force
        Import-Module (Join-Path $ProjectRoot 'Core\DER.DryRun.psm1') -Force
    }
    It 'creates a safe acronym' { ConvertTo-DERSafeAcronym 'Adirondack Regional Federal Credit Union' | Should -Be 'ARFCU' }
    It 'limits the computer prefix to seven alphanumeric characters' { (ConvertTo-DERComputerPrefix 'ABC-123456789').Length | Should -BeLessOrEqual 7 }
    It 'accepts a valid Autopilot random computer-name template' { (Test-DERComputerNameTemplate 'ABC-%RAND:7%').Valid | Should -BeTrue }
    It 'rejects an arbitrary colon outside a DER random token' { (Test-DERComputerNameTemplate 'ABC:DEF').Valid | Should -BeFalse }
    It 'rejects an invalid DER random token length' { (Test-DERComputerNameTemplate 'ABC-%RAND:0%').Valid | Should -BeFalse }
}
