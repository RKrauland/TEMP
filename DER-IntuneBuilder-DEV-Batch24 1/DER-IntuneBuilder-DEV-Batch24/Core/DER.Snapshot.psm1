<#
.SYNOPSIS
    DER pre-build configuration snapshot engine.

.DESCRIPTION
    Creates an immutable, sanitized PRE-BUILD snapshot of the configuration
    discovered by DER, captures assignments for supported policy families,
    stores raw and normalized JSON, and creates a SHA-256 file manifest.

.NOTES
    Required parent entry point: New-DERPreBuildSnapshot
#>


# Maintenance notes
# Responsibility: Captures pre/post tenant evidence used for comparison and recovery; snapshot failure must not silently erase evidence expectations.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERSnapshotCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERSnapshotLog {
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$ActionId,
        $Data
    )
    if (Test-DERSnapshotCommand -Name 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Snapshot' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function New-DERSnapshotActionId {
    param([Parameter(Mandatory)][string]$Name)
    if (Test-DERSnapshotCommand -Name 'New-DERActionId') { return New-DERActionId -Component 'SNAP' }
    return ('DER-SNAP-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0,8).ToUpperInvariant()))
}

function Protect-DERSnapshotData {
    param($InputObject)
    if (Test-DERSnapshotCommand -Name 'Protect-DERLogData') {
        return Protect-DERLogData -InputObject $InputObject
    }
    return $InputObject
}

function ConvertTo-DERStableObject {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]$InputObject,
        [int]$Depth = 0
    )
    process {
        if ($null -eq $InputObject) { return $null }
        if ($Depth -gt 30) { return '[MAX-NORMALIZATION-DEPTH]' }

        if ($InputObject -is [string] -or $InputObject -is [char] -or $InputObject -is [bool] -or
            $InputObject -is [byte] -or $InputObject -is [int16] -or $InputObject -is [int32] -or
            $InputObject -is [int64] -or $InputObject -is [uint16] -or $InputObject -is [uint32] -or
            $InputObject -is [uint64] -or $InputObject -is [single] -or $InputObject -is [double] -or
            $InputObject -is [decimal] -or $InputObject -is [datetime] -or $InputObject -is [guid]) {
            return $InputObject
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($key in @($InputObject.Keys | ForEach-Object {[string]$_} | Sort-Object)) {
                if ($key -in @('@odata.context','@odata.nextLink','@odata.count')) { continue }
                $value = $null
                foreach ($realKey in $InputObject.Keys) {
                    if ([string]$realKey -eq $key) { $value = $InputObject[$realKey]; break }
                }
                $ordered[$key] = ConvertTo-DERStableObject -InputObject $value -Depth ($Depth + 1)
            }
            return [pscustomobject]$ordered
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            $items = @()
            foreach ($item in $InputObject) { $items += ,(ConvertTo-DERStableObject -InputObject $item -Depth ($Depth + 1)) }
            if ($items.Count -le 1) { return $items }

            $canSortById = (@($items | Where-Object {$null -ne $_ -and $_.PSObject.Properties.Name -contains 'id'}).Count -eq $items.Count)
            if ($canSortById) { return @($items | Sort-Object {[string]$_.id}) }
            $canSortByName = (@($items | Where-Object {$null -ne $_ -and $_.PSObject.Properties.Name -contains 'displayName'}).Count -eq $items.Count)
            if ($canSortByName) { return @($items | Sort-Object {[string]$_.displayName}) }
            if (@($items | Where-Object {$_ -isnot [string] -and $_ -isnot [ValueType]}).Count -eq 0) {
                return @($items | Sort-Object)
            }
            return $items
        }

        $properties = @($InputObject.PSObject.Properties | Where-Object {
            $_.MemberType -in @('NoteProperty','Property','AliasProperty','ScriptProperty') -and
            $_.Name -notin @('@odata.context','@odata.nextLink','@odata.count')
        } | Sort-Object Name)

        if ($properties.Count -gt 0) {
            $ordered = [ordered]@{}
            foreach ($property in $properties) {
                try { $ordered[$property.Name] = ConvertTo-DERStableObject -InputObject $property.Value -Depth ($Depth + 1) }
                catch { $ordered[$property.Name] = '[UNREADABLE]' }
            }
            return [pscustomobject]$ordered
        }

        return [string]$InputObject
    }
}

function Write-DERJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$InputObject,
        [switch]$Compress
    )
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $safe = Protect-DERSnapshotData -InputObject $InputObject
    $json = if ($Compress) { $safe | ConvertTo-Json -Depth 80 -Compress } else { $safe | ConvertTo-Json -Depth 80 }
    [System.IO.File]::WriteAllText($Path,$json,[System.Text.UTF8Encoding]::new($false))
    return Get-Item -LiteralPath $Path
}

function Get-DERSnapshotAssignmentCatalog {
    [CmdletBinding()]
    param()
    return [ordered]@{
        CompliancePolicies         = @{Api='beta';Template='deviceManagement/deviceCompliancePolicies/{0}/assignments'}
        DeviceConfigurations       = @{Api='beta';Template='deviceManagement/deviceConfigurations/{0}/assignments'}
        ConfigurationPolicies      = @{Api='beta';Template='deviceManagement/configurationPolicies/{0}/assignments'}
        GroupPolicyConfigurations  = @{Api='beta';Template='deviceManagement/groupPolicyConfigurations/{0}/assignments'}
        EndpointSecurityIntents    = @{Api='beta';Template='deviceManagement/intents/{0}/assignments'}
        DeviceEnrollmentConfigurations = @{Api='beta';Template='deviceManagement/deviceEnrollmentConfigurations/{0}/assignments'}
        AutopilotProfiles          = @{Api='beta';Template='deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assignments'}
        FeatureUpdateProfiles      = @{Api='beta';Template='deviceManagement/windowsFeatureUpdateProfiles/{0}/assignments'}
        DriverUpdateProfiles       = @{Api='beta';Template='deviceManagement/windowsDriverUpdateProfiles/{0}/assignments'}
    }
}

function Get-DERSnapshotResourceData {
    param([Parameter(Mandatory)]$Discovery,[Parameter(Mandatory)][string]$Key)
    if ($Discovery.Collections -is [System.Collections.IDictionary] -and $Discovery.Collections.Contains($Key)) {
        return @($Discovery.Collections[$Key])
    }
    if ($Discovery.Singletons -is [System.Collections.IDictionary] -and $Discovery.Singletons.Contains($Key)) {
        return $Discovery.Singletons[$Key]
    }
    return $null
}

function Invoke-DERSnapshotAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)][string]$AssignmentsRoot,
        [Parameter(Mandatory)][string]$RunId
    )

    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-DERSnapshotCommand -Name 'Invoke-DERGraphCollectionRequest')) {
        Write-DERSnapshotLog -Level WARN -Message 'DER Graph collection request command unavailable; assignment snapshot skipped.'
        return @($results)
    }

    $catalog = Get-DERSnapshotAssignmentCatalog
    foreach ($key in $catalog.Keys) {
        $objects = @(Get-DERSnapshotResourceData -Discovery $Discovery -Key $key)
        if ($objects.Count -eq 0) { continue }
        $spec = $catalog[$key]
        $familyDir = Join-Path $AssignmentsRoot $key
        New-Item -ItemType Directory -Path $familyDir -Force | Out-Null

        foreach ($object in $objects) {
            $id = [string]$object.id
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $actionId = New-DERSnapshotActionId -Name ('Assignments-{0}' -f $key)
            $uri = [string]::Format([string]$spec.Template,$id)
            try {
                $assignments = @(Invoke-DERGraphCollectionRequest -Uri $uri -ApiVersion $spec.Api -ActionId $actionId -Component ('Snapshot.Assignments.{0}' -f $key))
                $rawPath = Join-Path $familyDir ("{0}.json" -f $id)
                Write-DERJsonFile -Path $rawPath -InputObject $assignments | Out-Null
                $results.Add([pscustomobject]@{Resource=$key;ObjectId=$id;Status='Success';Count=$assignments.Count;Path=$rawPath;Error=$null})
            } catch {
                Write-DERSnapshotLog -Level WARN -ActionId $actionId -Message ("Could not snapshot assignments for {0}/{1}: {2}" -f $key,$id,$_.Exception.Message)
                $results.Add([pscustomobject]@{Resource=$key;ObjectId=$id;Status='SkippedOrFailed';Count=0;Path=$null;Error=$_.Exception.Message})
            }
        }
    }
    return @($results)
}

function New-DERSnapshotHashManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SnapshotRoot,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$TenantId
    )

    $files = @(Get-ChildItem -LiteralPath $SnapshotRoot -File -Recurse | Where-Object {$_.Name -ne 'SHA256-MANIFEST.json'} | Sort-Object FullName)
    $entries = foreach ($file in $files) {
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        [pscustomobject][ordered]@{
            RelativePath = $file.FullName.Substring($SnapshotRoot.Length).TrimStart('\','/')
            Size = [int64]$file.Length
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
            SHA256 = $hash.Hash.ToLowerInvariant()
        }
    }

    $manifest = [pscustomobject][ordered]@{
        SchemaVersion='1.0';RunId=$RunId;TenantId=$TenantId;CreatedAt=(Get-Date).ToString('o');Algorithm='SHA256';FileCount=@($entries).Count;Files=@($entries)
    }
    $path = Join-Path $SnapshotRoot 'SHA256-MANIFEST.json'
    Write-DERJsonFile -Path $path -InputObject $manifest | Out-Null
    return $manifest
}

function New-DERPreBuildSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $tenantId = [string]$Discovery.TenantId
    if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'Snapshot cannot start because Discovery.TenantId is empty.' }

    $actionId = New-DERSnapshotActionId -Name 'PreBuild'
    $started = Get-Date
    $snapshotRoot = Join-Path (Join-Path (Join-Path $RuntimeRoot 'Snapshots') $tenantId) (Join-Path $RunId 'PRE-BUILD')
    if (Test-Path -LiteralPath $snapshotRoot) {
        throw "DER refuses to overwrite an existing PRE-BUILD snapshot: $snapshotRoot"
    }

    $rawRoot = Join-Path $snapshotRoot 'Raw'
    $normalizedRoot = Join-Path $snapshotRoot 'Normalized'
    $assignmentsRoot = Join-Path $snapshotRoot 'Assignments'
    New-Item -ItemType Directory -Path $rawRoot,$normalizedRoot,$assignmentsRoot -Force | Out-Null

    Write-DERSnapshotLog -Level STEP -ActionId $actionId -Message 'Creating immutable DER PRE-BUILD configuration snapshot.' -Data @{tenantId=$tenantId;snapshotRoot=$snapshotRoot}

    # Discovery metadata itself is useful for reconstructing what DER knew when
    # the questionnaire started.
    Write-DERJsonFile -Path (Join-Path $rawRoot 'Discovery.json') -InputObject $Discovery | Out-Null
    $normalizedDiscovery = ConvertTo-DERStableObject -InputObject (Protect-DERSnapshotData -InputObject $Discovery)
    Write-DERJsonFile -Path (Join-Path $normalizedRoot 'Discovery.json') -InputObject $normalizedDiscovery | Out-Null

    $resourceResults = New-Object System.Collections.Generic.List[object]
    foreach ($definition in @($Discovery.DiscoveryCatalog)) {
        if (-not [bool]$definition.Snapshot) { continue }
        $key = [string]$definition.Key
        $status = $null
        if ($Discovery.ResourceStatus -is [System.Collections.IDictionary] -and $Discovery.ResourceStatus.Contains($key)) { $status = $Discovery.ResourceStatus[$key] }
        if ($status -and $status.Status -ne 'Success') {
            $resourceResults.Add([pscustomobject]@{Key=$key;Status='Unavailable';RawPath=$null;NormalizedPath=$null;Count=0;Reason=$status.Status})
            continue
        }

        $data = Get-DERSnapshotResourceData -Discovery $Discovery -Key $key
        $rawPath = Join-Path $rawRoot ("{0}.json" -f $key)
        $normalizedPath = Join-Path $normalizedRoot ("{0}.json" -f $key)
        Write-DERJsonFile -Path $rawPath -InputObject $data | Out-Null
        $normalized = ConvertTo-DERStableObject -InputObject (Protect-DERSnapshotData -InputObject $data)
        Write-DERJsonFile -Path $normalizedPath -InputObject $normalized | Out-Null
        $count = if ($definition.Mode -eq 'Collection') {@($data).Count} elseif ($null -eq $data) {0} else {1}
        $resourceResults.Add([pscustomobject]@{Key=$key;Status='Captured';RawPath=$rawPath;NormalizedPath=$normalizedPath;Count=$count;Reason=$null})
    }

    $assignmentResults = @(Invoke-DERSnapshotAssignments -Discovery $Discovery -AssignmentsRoot $assignmentsRoot -RunId $RunId)
    Write-DERJsonFile -Path (Join-Path $rawRoot 'AssignmentCaptureResults.json') -InputObject $assignmentResults | Out-Null

    $metadata = [pscustomobject][ordered]@{
        SchemaVersion='1.0';SnapshotType='PRE-BUILD';RunId=$RunId;TenantId=$tenantId;TenantName=$Discovery.TenantName;
        StartedAt=$started;CompletedAt=Get-Date;DiscoverySchemaVersion=$Discovery.SchemaVersion;
        CapturedResources=@($resourceResults);AssignmentCapture=@($assignmentResults)
    }
    Write-DERJsonFile -Path (Join-Path $snapshotRoot 'SnapshotMetadata.json') -InputObject $metadata | Out-Null
    $hashManifest = New-DERSnapshotHashManifest -SnapshotRoot $snapshotRoot -RunId $RunId -TenantId $tenantId

    $completed = Get-Date
    $result = [pscustomobject][ordered]@{
        SchemaVersion='1.0';SnapshotType='PRE-BUILD';RunId=$RunId;TenantId=$tenantId;TenantName=$Discovery.TenantName;
        RootPath=$snapshotRoot;RawPath=$rawRoot;NormalizedPath=$normalizedRoot;AssignmentsPath=$assignmentsRoot;
        MetadataPath=(Join-Path $snapshotRoot 'SnapshotMetadata.json');HashManifestPath=(Join-Path $snapshotRoot 'SHA256-MANIFEST.json');
        ResourceCount=@($resourceResults | Where-Object {$_.Status -eq 'Captured'}).Count;
        AssignmentObjectCount=@($assignmentResults | Where-Object {$_.Status -eq 'Success'}).Count;
        FileCount=$hashManifest.FileCount;StartedAt=$started;CompletedAt=$completed;DurationMs=[int]($completed-$started).TotalMilliseconds;
        ResourceResults=@($resourceResults);AssignmentResults=@($assignmentResults)
    }

    $assignmentFailures=@($assignmentResults | Where-Object {$_.Status -ne 'Success'})
    if($assignmentFailures.Count -gt 0){
        $snapshotMessage=("DER PRE-BUILD snapshot failed closed: {0} assignment read(s) could not be captured. Snapshot evidence was preserved at '{1}'." -f $assignmentFailures.Count,$snapshotRoot)
        if(Get-Command Write-DERActionFailure -ErrorAction SilentlyContinue){Write-DERActionFailure -Component 'Snapshot' -ActionId $actionId -Message ("PRE-BUILD snapshot is incomplete because {0} assignment read(s) failed. DER will not proceed to tenant writes." -f $assignmentFailures.Count) -Data @{failures=$assignmentFailures;snapshotRoot=$snapshotRoot}}else{Write-DERSnapshotLog -Level ERROR -ActionId $actionId -Message $snapshotMessage -Data @{failures=$assignmentFailures;snapshotRoot=$snapshotRoot}}
        $snapshotException=[System.InvalidOperationException]::new($snapshotMessage)
        $snapshotException.Data['DERFailureKind']='Action';$snapshotException.Data['DERActionId']=$actionId;$snapshotException.Data['DERComponent']='Snapshot'
        throw $snapshotException
    }
    Write-DERSnapshotLog -Level OK -ActionId $actionId -Message ("PRE-BUILD snapshot complete ({0} files, {1} resource families)." -f $result.FileCount,$result.ResourceCount) -Data $result
    return $result
}

Export-ModuleMember -Function @(
    'ConvertTo-DERStableObject','Write-DERJsonFile','Get-DERSnapshotAssignmentCatalog','New-DERSnapshotHashManifest','New-DERPreBuildSnapshot'
)
