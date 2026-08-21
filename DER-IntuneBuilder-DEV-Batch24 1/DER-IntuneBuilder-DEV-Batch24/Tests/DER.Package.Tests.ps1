# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Package trust contract.

.DESCRIPTION
    Proves the parent trust anchor, package manifest, update metadata, dependency lock, and signing policy agree.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves the parent trust anchor, package manifest, update metadata, dependency lock, and signing policy agree.
# Failure significance: A failure here means package bytes or release metadata cannot be trusted as one coherent artifact.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $ParentPath = Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
    $ManifestPath = Join-Path $ProjectRoot 'Definitions\Package\DER-PackageManifest.json'
    $UpdatePath = Join-Path $ProjectRoot 'Definitions\Package\DER-UpdateManifest.json'
    $DependencyPath = Join-Path $ProjectRoot 'Definitions\Package\DER-DependencyLock.json'
    $SigningPath = Join-Path $ProjectRoot 'Definitions\Package\DER-SigningPolicy.json'
    $Parent = Get-Content $ParentPath -Raw
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json -Depth 100
    $Update = Get-Content $UpdatePath -Raw | ConvertFrom-Json -Depth 100
    $Dependency = Get-Content $DependencyPath -Raw | ConvertFrom-Json -Depth 100
    $Signing = Get-Content $SigningPath -Raw | ConvertFrom-Json -Depth 100
}
Describe 'DER package trust anchor and integrity manifest' {
    It 'pins the package-manifest SHA-256 in the parent trust anchor' {
        $match = [regex]::Match($Parent, '(?m)^\$script:DERPackageManifestSHA256\s*=\s*''([0-9a-fA-F]{64})''\s*$')
        $match.Success | Should -BeTrue
        (Get-FileHash -Algorithm SHA256 -LiteralPath $ManifestPath).Hash.ToLowerInvariant() | Should -Be $match.Groups[1].Value.ToLowerInvariant()
    }
    It 'validates every protected file hash and length' {
        @($Manifest.protectedFiles).Count | Should -BeGreaterThan 0
        foreach($entry in $Manifest.protectedFiles){
            $path=Join-Path $ProjectRoot (([string]$entry.path).Replace('/',[IO.Path]::DirectorySeparatorChar))
            Test-Path $path | Should -BeTrue
            (Get-Item $path).Length | Should -Be ([long]$entry.bytes)
            (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() | Should -Be ([string]$entry.sha256).ToLowerInvariant()
        }
    }
    It 'treats the package manifest as an exact file inventory' {
        $known=@{};foreach($entry in $Manifest.protectedFiles){$known[([string]$entry.path).ToLowerInvariant()]=$true}
        $special=@('start-derintunebuilder.ps1','definitions/package/der-packagemanifest.json','sha256sums.txt')
        foreach($f in Get-ChildItem $ProjectRoot -Recurse -File){
            $relative=[IO.Path]::GetRelativePath($ProjectRoot,$f.FullName).Replace('\','/')
            $key=$relative.ToLowerInvariant()
            if($key -in $special -or $relative -match '\.(zip|sha256)$'){continue}
            $known.ContainsKey($key) | Should -BeTrue -Because "$relative must be in the protected package manifest"
        }
    }
}
Describe 'DER version and update metadata' {
    It 'keeps the package/update/dependency contracts aligned' {
        $Manifest.packageVersion | Should -Be $Update.packageVersion
        $Manifest.buildNumber | Should -Be $Update.buildNumber
        $Manifest.engineVersion | Should -Be $Update.engineVersion
        $Manifest.baselineVersion | Should -Be $Update.baselineVersion
        $Update.dependencies.lockVersion | Should -Be $Dependency.lockVersion
        $Manifest.packageVersion | Should -Be '1.0.0-dev'
        $Manifest.buildNumber | Should -BeGreaterThan 0
        $Update.runtime.minimumPowerShell | Should -Be '7.4.0'
        $Update.runtime.bootstrapPowerShell | Should -Be '7.6.4'
        $Parent | Should -Match "DERPinnedPowerShell\s*=\s*'7\.6\.4'"
        $Update.runtime.bootstrapPowerShellMsiSHA256 | Should -Be 'd11942df52fd12470169797abfa4781d9480efdc81000ba4fa55a5b921ed8dd0'
        $Parent | Should -Match "DERPowerShellMsiSHA256\s*=\s*'d11942df52fd12470169797abfa4781d9480efdc81000ba4fa55a5b921ed8dd0'"
        $Parent | Should -Match 'PowerShell MSI SHA-256 validation failed'
        $Update.updatePolicy.automaticCheck | Should -BeFalse
        $Update.updatePolicy.automaticDownload | Should -BeFalse
        $Update.updatePolicy.automaticExecute | Should -BeFalse
    }
}
Describe 'DER dependency hardening' {
    It 'pins Microsoft.Graph.Authentication identity and isolated validated acquisition' {
        $graph=@($Dependency.dependencies|Where-Object name -eq 'Microsoft.Graph.Authentication')|Select-Object -First 1
        $graph.version | Should -Be '2.36.1'
        $graph.moduleGuid | Should -Be '883916f2-9184-46ee-b1f8-b6a2fb784cee'
        $graph.acquisition.preferredCmdlet | Should -Be 'Save-PSResource'
        $graph.acquisition.authenticodeCheckRequired | Should -BeTrue
        $graph.acquisition.saveModuleAllowed | Should -BeFalse
        $graph.runtimeIntegrity.contentLockRequired | Should -BeTrue
        $graph.runtimeIntegrity.manifestSignerSimpleName | Should -Be 'Microsoft Corporation'
        $Parent | Should -Match '\bSave-PSResource\b'
        $Parent | Should -Match '-AuthenticodeCheck'
        $Parent | Should -Not -Match '(?m)^\s*Save-Module\b'
        $Parent | Should -Match 'Test-DERDependencyContentLock'
        $Parent | Should -Match 'Get-AuthenticodeSignature'
        $Parent | Should -Match 'GetNameInfo'
        $Parent | Should -Not -Match "SignerCertificate\.Subject\s+-notmatch\s+'Microsoft'"
    }
}
Describe 'DER signing readiness' {
    It 'allows unsigned development builds but fails closed for release signing' {
        $Signing.development.unsignedAllowed | Should -BeTrue
        $Signing.development.failOnInvalidSignature | Should -BeTrue
        $Signing.release.authenticodeRequired | Should -BeTrue
        $Signing.release.publisherTrustMode | Should -Be 'ExplicitThumbprint'
        $Signing.release.blockIfThumbprintListEmpty | Should -BeTrue
        $Signing.release.timestampRequired | Should -BeTrue
        $Parent | Should -Match 'RequireSignedPackage'
        (Get-Content (Join-Path $ProjectRoot 'Tools\Protect-DERRelease.ps1') -Raw) | Should -Match 'Set-AuthenticodeSignature'
    }
}
