#requires -Version 7.4
<#
.SYNOPSIS
    DER v1 release-signing protector.

.DESCRIPTION
    Applies the configured Authenticode release-signing policy to DER source artifacts and regenerates package trust metadata in the required order. It is a release-engineering tool, not a tenant-workload tool.

.NOTES
    Keep safety boundaries, evidence semantics, and operator-facing behavior explicit
    when editing this tool.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][uri]$TimestampServer,
    [string]$PackageVersion,
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)


# Maintenance notes
# Responsibility: Applies approved Release signing workflow and regenerates trust metadata in the required order.
# Safety: Tooling must honor its documented no-tenant/no-write boundary.
# Evidence: Output should be deterministic, explicit about PASS/FAIL semantics, and must not describe static checks as runtime/Pester success.
# Packaging: Generate trust/release material only from final source bytes.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$thumb=$CertificateThumbprint.Replace(' ','').ToUpperInvariant()
$cert=$null
foreach($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')){
    $candidate=Get-ChildItem -Path $store -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint.Replace(' ','').ToUpperInvariant() -eq $thumb } | Select-Object -First 1
    if($candidate){$cert=$candidate;break}
}
if(-not$cert){throw 'The requested code-signing certificate was not found in CurrentUser or LocalMachine personal stores.'}
if(-not$cert.HasPrivateKey){throw 'The selected code-signing certificate has no accessible private key.'}
$hasCodeSigning=@($cert.EnhancedKeyUsageList | Where-Object {$_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3'}).Count -gt 0
if(-not$hasCodeSigning){throw 'The selected certificate does not have the Code Signing EKU.'}

$signingPath=Join-Path $ProjectRoot 'Definitions\Package\DER-SigningPolicy.json'
$updatePath=Join-Path $ProjectRoot 'Definitions\Package\DER-UpdateManifest.json'
$signing=Get-Content $signingPath -Raw|ConvertFrom-Json -Depth 100
$update=Get-Content $updatePath -Raw|ConvertFrom-Json -Depth 100
$signing.release.allowedCertificateThumbprints=@($thumb)
$update.channel='Release'
if(-not[string]::IsNullOrWhiteSpace($PackageVersion)){$update.packageVersion=$PackageVersion}
$signing|ConvertTo-Json -Depth 30|Set-Content $signingPath -Encoding utf8
$update|ConvertTo-Json -Depth 30|Set-Content $updatePath -Encoding utf8

$parentPath=Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1'
$parent=Get-Content $parentPath -Raw
$replacement = '$script:DERPackageVersion          = ''{0}''' -f [string]$update.packageVersion
$parent=[regex]::Replace($parent,'(?m)^\$script:DERPackageVersion\s*=\s*''[^'']+''\s*$',$replacement,1)
$parent|Set-Content $parentPath -Encoding utf8

$childFiles=@(Get-ChildItem (Join-Path $ProjectRoot 'Core') -Filter '*.psm1' -File)+@(Get-ChildItem (Join-Path $ProjectRoot 'Workloads') -Filter '*.psm1' -File)
if($PSCmdlet.ShouldProcess(('{0} child runtime files' -f $childFiles.Count),'Authenticode sign')){
    foreach($file in $childFiles){
        $result=Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
        if([string]$result.Status -ne 'Valid'){throw ('Failed to sign {0}: {1}' -f $file.FullName,$result.Status)}
    }
}

& (Join-Path $PSScriptRoot 'New-DERPackageManifest.ps1') -ProjectRoot $ProjectRoot | Out-Null

if($PSCmdlet.ShouldProcess($parentPath,'Authenticode sign parent trust anchor')){
    $result=Set-AuthenticodeSignature -LiteralPath $parentPath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer.AbsoluteUri
    if([string]$result.Status -ne 'Valid'){throw ('Failed to sign parent trust anchor: {0}' -f $result.Status)}
}

# Parent signing changes only the trust-anchor file, which is deliberately not
# inside DER-PackageManifest.json. Refresh the outer whole-package sums now.
$sumsPath=Join-Path $ProjectRoot 'SHA256SUMS.txt'
$lines=foreach($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File|Sort-Object FullName){
    $relative=[IO.Path]::GetRelativePath($ProjectRoot,$file.FullName).Replace('\','/')
    if($relative -eq 'SHA256SUMS.txt' -or $relative -match '\.(zip|sha256)$'){continue}
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant(),$relative
}
$lines|Set-Content $sumsPath -Encoding utf8

& (Join-Path $PSScriptRoot 'Test-DERPackage.ps1') -ProjectRoot $ProjectRoot -RequireSigned
