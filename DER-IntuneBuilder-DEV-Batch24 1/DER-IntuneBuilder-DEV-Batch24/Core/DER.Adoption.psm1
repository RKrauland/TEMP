<#
.SYNOPSIS
    DER explicit customer-object adoption and comparison workflow.

.DESCRIPTION
    Detects exact-name collisions for adoptable planned objects, captures a
    sanitized read-only snapshot, compares the existing object with the DER
    desired definition where possible, and requires an explicit engineer
    decision tied to the exact Microsoft ObjectId before DER records the object
    as DER-Adopted.

    Adoption is ownership-state only. This module never POSTs, PATCHes, PUTs,
    DELETEs, changes assignments, or reconciles configuration in the tenant.

.NOTES
    Required parent entry point: Invoke-DERAdoptionWorkflow
#>


# Maintenance notes
# Responsibility: Owns read-only collision comparison and explicit Customer-Owned -> DER-Adopted decisions. Adoption itself must not mutate tenant configuration.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:DERAdoptionAcknowledgement = 'I understand DER adoption changes local DER ownership state only and does not modify the tenant object during adoption.'

function Test-DERAdoptionCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERAdoptionLog {
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        $Data,
        [string]$ActionId
    )
    if (Test-DERAdoptionCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Adoption' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function Get-DERAdoptionCatalog {
    [CmdletBinding()]
    param([string]$PackageRoot = (Split-Path -Parent $PSScriptRoot))
    $path = Join-Path $PackageRoot 'Definitions\Adoption\DER-AdoptionCatalog.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "DER adoption catalog is missing: $path" }
    $catalog = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
    if ([string]$catalog.schemaVersion -ne '1.0') { throw "Unsupported DER adoption catalog schema $($catalog.schemaVersion)." }
    return $catalog
}

function Get-DERAdoptionCatalogEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Catalog,[Parameter(Mandatory)]$PlannedObject)
    return @($Catalog.entries | Where-Object {
        [string]$_.module -eq [string]$PlannedObject.Module -and
        @($_.objectTypes) -contains [string]$PlannedObject.ObjectType
    } | Select-Object -First 1)
}

function Get-DERAdoptionPropertyValue {
    param([AllowNull()]$InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $null
}

function Protect-DERAdoptionData {
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if (Test-DERAdoptionCommand 'Protect-DERLogData') { return Protect-DERLogData -InputObject $InputObject }
    return (($InputObject | ConvertTo-Json -Depth 100) | ConvertFrom-Json -Depth 100)
}

function Get-DERAdoptionJsonSha256 {
    param([Parameter(Mandatory)]$InputObject)
    $json = $InputObject | ConvertTo-Json -Depth 100 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-DERAdoptionDesiredProjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)]$PlannedObject,
        [Parameter(Mandatory)]$CatalogEntry
    )

    $profile = [string]$CatalogEntry.comparisonProfile
    $body = $null
    switch ($profile) {
        'Groups' {
            $dynamic = ([string]$PlannedObject.ObjectType -eq 'DynamicSecurityGroup')
            $body = [ordered]@{
                displayName = [string]$PlannedObject.DisplayName
                mailEnabled = $false
                securityEnabled = $true
                groupTypes = if ($dynamic) { @('DynamicMembership') } else { @() }
            }
            if ($dynamic) {
                if (-not (Test-DERAdoptionCommand 'Get-DERDynamicGroupRule')) { throw 'DER group rule helper is unavailable for adoption comparison.' }
                $body.membershipRule = Get-DERDynamicGroupRule -PlannedObject $PlannedObject -BuildPlan $BuildPlan
                $body.membershipRuleProcessingState = 'On'
            }
        }
        'EnrollmentRestriction' {
            if (-not (Test-DERAdoptionCommand 'New-DERWindowsRestrictionBody')) { throw 'DER enrollment restriction helper is unavailable.' }
            $body = New-DERWindowsRestrictionBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'EnrollmentLimit' {
            if (-not (Test-DERAdoptionCommand 'New-DEREnrollmentLimitBody')) { throw 'DER enrollment limit helper is unavailable.' }
            $body = New-DEREnrollmentLimitBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'AutopilotProfile' {
            if (-not (Test-DERAdoptionCommand 'New-DERAutopilotProfileBody')) { throw 'DER Autopilot helper is unavailable.' }
            $usage = if ([string]$PlannedObject.DerId -eq 'DER-AP-030') { 'shared' } else { 'singleUser' }
            $body = New-DERAutopilotProfileBody -BuildPlan $BuildPlan -Planned $PlannedObject -DeviceUsageType $usage
        }
        'EnrollmentStatusPage' {
            if (-not (Test-DERAdoptionCommand 'New-DERESPBody')) { throw 'DER ESP helper is unavailable.' }
            $body = New-DERESPBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'Compliance' {
            if (-not (Test-DERAdoptionCommand 'New-DERWindowsComplianceBody')) { throw 'DER compliance helper is unavailable.' }
            $body = New-DERWindowsComplianceBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'NamedLocation' {
            if (-not (Test-DERAdoptionCommand 'New-DERNamedLocationBody')) { throw 'DER Named Location helper is unavailable.' }
            $body = New-DERNamedLocationBody -PlannedObject $PlannedObject
        }
        'UpdateRing' {
            if (-not (Test-DERAdoptionCommand 'New-DERUpdateRingBody')) { throw 'DER update-ring helper is unavailable.' }
            $body = New-DERUpdateRingBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'FeatureUpdate' {
            if (-not (Test-DERAdoptionCommand 'New-DERFeatureUpdateBody')) { throw 'DER feature-update helper is unavailable.' }
            $body = New-DERFeatureUpdateBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'DriverUpdate' {
            if (-not (Test-DERAdoptionCommand 'New-DERDriverProfileBody')) { throw 'DER driver-update helper is unavailable.' }
            $body = New-DERDriverProfileBody -BuildPlan $BuildPlan -Planned $PlannedObject
        }
        'DeliveryOptimization' {
            if (-not (Test-DERAdoptionCommand 'New-DERDeliveryOptimizationBody')) { throw 'DER Delivery Optimization helper is unavailable.' }
            $body = New-DERDeliveryOptimizationBody -Planned $PlannedObject
        }
        'Analytics' {
            if (Test-DERAdoptionCommand 'New-DERAnalyticsBody') {
                $body = New-DERAnalyticsBody -Planned $PlannedObject
            } else {
                $body = [ordered]@{
                    '@odata.type' = '#microsoft.graph.windowsHealthMonitoringConfiguration'
                    displayName = [string]$PlannedObject.DisplayName
                    roleScopeTagIds = @('0')
                    allowDeviceHealthMonitoring = 'enabled'
                    configDeviceHealthMonitoringScope = 'healthMonitoring'
                }
            }
        }
        'ConditionalAccessSafety' {
            $body = [ordered]@{
                displayName = [string]$PlannedObject.DisplayName
                state = 'enabledForReportingButNotEnforced'
            }
        }
        'SettingsCatalogTopLevel' {
            $body = [ordered]@{
                name = [string]$PlannedObject.DisplayName
                platforms = 'windows10'
                technologies = 'mdm'
            }
        }
        default {
            $body = [ordered]@{}
            $body[[string]$CatalogEntry.nameProperty] = [string]$PlannedObject.DisplayName
        }
    }

    return [pscustomobject][ordered]@{
        Scope = [string]$CatalogEntry.comparisonScope
        Complete = ([string]$CatalogEntry.comparisonScope -eq 'ConfigurationBody')
        Desired = [pscustomobject]$body
    }
}

function Compare-DERAdoptionCandidate {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Actual,[Parameter(Mandatory)]$Desired)
    if (Test-DERAdoptionCommand 'Test-DERExpectedSubset') {
        return Test-DERExpectedSubset -Actual $Actual -Expected $Desired
    }

    $differences = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Desired.PSObject.Properties) {
        $actualValue = Get-DERAdoptionPropertyValue -InputObject $Actual -Name $p.Name
        if (($actualValue | ConvertTo-Json -Depth 30 -Compress) -cne ($p.Value | ConvertTo-Json -Depth 30 -Compress)) {
            $differences.Add([pscustomobject]@{Path=$p.Name;Expected=$p.Value;Actual=$actualValue})
        }
    }
    return [pscustomobject]@{Success=($differences.Count -eq 0);Differences=@($differences)}
}

function Read-DERAdoptionDecisions {
    [CmdletBinding()]
    param([string]$Path,[Parameter(Mandatory)][string]$ExpectedTenantId)
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]@{Path=$null;Decisions=@()} }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "DER adoption decision file not found: $Path" }
    $doc = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
    if ([string]$doc.schemaVersion -ne '1.0') { throw 'Unsupported DER adoption decision schema. Expected 1.0.' }
    if ([string]$doc.tenantId -ne $ExpectedTenantId) { throw "Adoption decision TenantId $($doc.tenantId) does not match authenticated tenant $ExpectedTenantId." }
    $seen = @{}
    $seenObjectIds = @{}
    foreach ($d in @($doc.decisions)) {
        if ([string]::IsNullOrWhiteSpace([string]$d.derId) -or [string]::IsNullOrWhiteSpace([string]$d.objectId)) { throw 'Each adoption decision requires derId and objectId.' }
        $parsedObjectId = [guid]::Empty
        if (-not [guid]::TryParse([string]$d.objectId,[ref]$parsedObjectId)) { throw "Adoption decision ObjectId '$($d.objectId)' for $($d.derId) is not a valid GUID." }
        if ([string]$d.decision -notin @('Adopt','Skip')) { throw "Invalid adoption decision '$($d.decision)' for $($d.derId)." }
        if ($seen.ContainsKey([string]$d.derId)) { throw "Duplicate adoption decision for DER ID $($d.derId)." }
        if ($seenObjectIds.ContainsKey([string]$d.objectId)) { throw "Adoption decision ObjectId $($d.objectId) is bound to more than one DER ID." }
        $seen[[string]$d.derId] = $true
        $seenObjectIds[[string]$d.objectId] = [string]$d.derId
        if ([string]$d.decision -eq 'Adopt' -and [string]$d.acknowledgement -ne $script:DERAdoptionAcknowledgement) {
            throw "Adoption decision for $($d.derId) is missing the exact required acknowledgement."
        }
    }
    return [pscustomobject]@{Path=(Resolve-Path -LiteralPath $Path).Path;Decisions=@($doc.decisions)}
}

function Get-DERAdoptionDecisionForCandidate {
    param([Parameter(Mandatory)]$Candidate,[Parameter(Mandatory)]$DecisionSet,[Parameter(Mandatory)][ValidateSet('Prompt','FileOnly','Disabled')][string]$Mode)
    $fileDecision = @($DecisionSet.Decisions | Where-Object {[string]$_.derId -eq [string]$Candidate.DerId} | Select-Object -First 1)
    if ($fileDecision.Count) {
        $d = $fileDecision[0]
        if ([string]$d.objectId -ne [string]$Candidate.ObjectId) {
            throw "Adoption decision ObjectId mismatch for $($Candidate.DerId). Expected candidate $($Candidate.ObjectId), file contains $($d.objectId)."
        }
        if ([string]$d.decision -eq 'Adopt' -and -not [bool]$Candidate.ComparisonComplete) {
            $allowIncomplete = ($d.PSObject.Properties.Name -contains 'allowIncompleteComparison' -and [bool]$d.allowIncompleteComparison)
            if (-not $allowIncomplete) { throw "Adoption of $($Candidate.DerId) has only a partial comparison. Set allowIncompleteComparison=true explicitly or choose Skip." }
        }
        return [pscustomobject]@{Decision=[string]$d.decision;Source='File';Notes=if($d.PSObject.Properties.Name -contains 'notes'){[string]$d.notes}else{$null}}
    }

    if ($Mode -eq 'FileOnly' -or $Mode -eq 'Disabled') { return [pscustomobject]@{Decision='Skip';Source='Default';Notes='No matching explicit adoption decision was supplied.'} }

    Write-Host ''
    Write-Host ('DER ADOPTION CANDIDATE: {0}' -f $Candidate.DerId) -ForegroundColor Yellow
    Write-Host ('  Planned : {0}' -f $Candidate.DisplayName) -ForegroundColor Gray
    Write-Host ('  ObjectId: {0}' -f $Candidate.ObjectId) -ForegroundColor Gray
    Write-Host ('  Module  : {0} / {1}' -f $Candidate.Module,$Candidate.ObjectType) -ForegroundColor Gray
    Write-Host ('  Compare : {0}; {1} difference(s)' -f $Candidate.ComparisonScope,$Candidate.DifferenceCount) -ForegroundColor Gray
    Write-Host '  Adoption changes DER local ownership state only. It does NOT modify this tenant object or its assignments.' -ForegroundColor Cyan
    if (-not [bool]$Candidate.ComparisonComplete) {
        Write-Host '  WARNING: this is a partial top-level comparison. Template/settings payload is not fully compared.' -ForegroundColor Yellow
        $phrase = 'ADOPT INCOMPLETE {0}' -f $Candidate.DerId
    } else {
        $phrase = 'ADOPT {0}' -f $Candidate.DerId
    }
    Write-Host ('  Type exactly: {0}' -f $phrase) -ForegroundColor Cyan
    Write-Host '  Or press Enter / type anything else to leave it customer-owned.' -ForegroundColor Gray
    $entered = Read-Host 'Decision'
    if ([string]$entered -ceq $phrase) { return [pscustomobject]@{Decision='Adopt';Source='Prompt';Notes=$null} }
    return [pscustomobject]@{Decision='Skip';Source='Prompt';Notes='Engineer did not enter the exact adoption phrase.'}
}

function Write-DERAdoptionArtifacts {
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)][string]$Directory)
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $jsonPath = Join-Path $Directory 'AdoptionResult.json'
    $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $rows = @($Result.Candidates | ForEach-Object {
        [pscustomobject][ordered]@{
            DerId=$_.DerId;Module=$_.Module;ObjectType=$_.ObjectType;DisplayName=$_.DisplayName;ObjectId=$_.ObjectId;
            ComparisonScope=$_.ComparisonScope;ComparisonComplete=$_.ComparisonComplete;DifferenceCount=$_.DifferenceCount;
            CandidateStatus=$_.CandidateStatus;Decision=$_.Decision;DecisionSource=$_.DecisionSource;SnapshotPath=$_.SnapshotPath;Notes=$_.Notes
        }
    })
    $csvPath = Join-Path $Directory 'AdoptionResult.csv'
    if ($rows.Count) { $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 }
    else { [System.IO.File]::WriteAllText($csvPath,'"DerId","Module","ObjectType","DisplayName","ObjectId","ComparisonScope","ComparisonComplete","DifferenceCount","CandidateStatus","Decision","DecisionSource","SnapshotPath","Notes"'+[Environment]::NewLine,[System.Text.UTF8Encoding]::new($false)) }

    $template = [pscustomobject][ordered]@{
        schemaVersion='1.0';tenantId=$Result.TenantId;decisions=@($Result.Candidates | Where-Object {$_.CandidateStatus -eq 'Candidate'} | ForEach-Object {
            [pscustomobject][ordered]@{
                derId=$_.DerId;objectId=$_.ObjectId;decision='Skip';acknowledgement=$script:DERAdoptionAcknowledgement;
                allowIncompleteComparison=(-not [bool]$_.ComparisonComplete);notes='Change decision to Adopt only after reviewing the comparison and snapshot.'
            }
        })
    }
    $template | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $Directory 'Adoption-Decisions.template.json') -Encoding UTF8

    $htmlPath = Join-Path $Directory 'Adoption-Comparison.html'
    if ((Test-DERAdoptionCommand 'New-DERHtmlDocument') -and (Test-DERAdoptionCommand 'ConvertTo-DERHtmlTable')) {
        $body = '<p><strong>Safety:</strong> adoption records DER ownership state only. No tenant object or assignment is changed by this workflow.</p>'
        $body += ConvertTo-DERHtmlTable -Rows $rows -Columns @('DerId','Module','ObjectType','DisplayName','ObjectId','ComparisonScope','ComparisonComplete','DifferenceCount','CandidateStatus','Decision','DecisionSource','SnapshotPath','Notes')
        [System.IO.File]::WriteAllText($htmlPath,(New-DERHtmlDocument -Title 'DER Adoption Comparison' -Subtitle ("Tenant {0} | Run {1}" -f $Result.TenantId,$Result.RunId) -Body $body),[System.Text.UTF8Encoding]::new($false))
    } else {
        $encoded = [System.Net.WebUtility]::HtmlEncode(($rows | ConvertTo-Json -Depth 30))
        [System.IO.File]::WriteAllText($htmlPath,"<html><body><h1>DER Adoption Comparison</h1><p>Adoption is ownership-state only; no tenant writes occur.</p><pre>$encoded</pre></body></html>",[System.Text.UTF8Encoding]::new($false))
    }

    return [pscustomobject]@{Json=$jsonPath;Csv=$csvPath;Html=$htmlPath;DecisionTemplate=(Join-Path $Directory 'Adoption-Decisions.template.json')}
}

function Invoke-DERAdoptionWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [string]$PackageRoot = (Split-Path -Parent $PSScriptRoot),
        [ValidateSet('Prompt','FileOnly','Disabled')][string]$Mode='Prompt',
        [string]$DecisionPath
    )

    $ctx = if (Test-DERAdoptionCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if (-not $ctx) { throw 'DER State engine must be initialized before the adoption workflow.' }
    if ([string]$BuildPlan.TenantId -ne [string]$ctx.TenantId) { throw 'DER adoption BuildPlan tenant does not match initialized state tenant.' }

    $adoptionRoot = Join-Path $ctx.RunRoot 'Adoption'
    $snapshotRoot = Join-Path $adoptionRoot 'Snapshots'
    New-Item -ItemType Directory -Path $snapshotRoot -Force | Out-Null

    if ($Mode -eq 'Disabled') {
        $disabled = [pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;Mode=$Mode;StartedAt=(Get-Date);CompletedAt=(Get-Date);Summary=[pscustomobject]@{Scanned=0;Candidates=0;Adopted=0;Skipped=0;Ambiguous=0;Blocked=0};Candidates=@();Artifacts=$null}
        $disabled.Artifacts = Write-DERAdoptionArtifacts -Result $disabled -Directory $adoptionRoot
        return $disabled
    }

    $catalog = Get-DERAdoptionCatalog -PackageRoot $PackageRoot
    $decisions = Read-DERAdoptionDecisions -Path $DecisionPath -ExpectedTenantId ([string]$BuildPlan.TenantId)
    $started = Get-Date
    $candidateList = New-Object System.Collections.Generic.List[object]
    $scanned = 0

    Write-DERAdoptionLog -Level STEP -Message 'Scanning planned objects for exact-name customer-object adoption candidates.' -Data @{mode=$Mode;decisionPath=$decisions.Path}

    foreach ($planned in @($BuildPlan.Objects | Where-Object {$_.Enabled})) {
        $entry = Get-DERAdoptionCatalogEntry -Catalog $catalog -PlannedObject $planned
        if (-not $entry) { continue }
        $existingState = if (Test-DERAdoptionCommand 'Get-DERStateObject') { Get-DERStateObject -DerId ([string]$planned.DerId) } else { $null }
        if ($existingState -and [string]$existingState.Status -notin @('RolledBack','Retired')) { continue }
        $scanned++
        $actionId = if (Test-DERAdoptionCommand 'New-DERActionId') { New-DERActionId -Component 'ADOPT' } else { "ADOPT-$($planned.DerId)" }
        try {
            $all = @(Invoke-DERGraphCollectionRequest -Uri ([string]$entry.collectionUri) -ApiVersion ([string]$entry.apiVersion) -Component 'Adoption' -ActionId $actionId)
            $candidateMatches = @($all | Where-Object { [string](Get-DERAdoptionPropertyValue -InputObject $_ -Name ([string]$entry.nameProperty)) -ceq [string]$planned.DisplayName })
            if (-not $candidateMatches.Count) { continue }

            if ($candidateMatches.Count -gt 1) {
                $candidateList.Add([pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;ObjectType=$planned.ObjectType;DisplayName=$planned.DisplayName;ObjectId=$null;ComparisonScope=$entry.comparisonScope;ComparisonComplete=($entry.comparisonScope -eq 'ConfigurationBody');DifferenceCount=$null;CandidateStatus='Ambiguous';Decision='Skip';DecisionSource='Safety';SnapshotPath=$null;Notes=("{0} exact-name objects were returned. DER refuses ambiguous adoption." -f $candidateMatches.Count);Differences=@()})
                Register-DERTransaction -ActionId $actionId -Phase SKIP -Module $planned.Module -DerId $planned.DerId -Message 'Adoption refused because multiple exact-name candidates were returned.' -Data @{count=$candidateMatches.Count} | Out-Null
                continue
            }

            $candidate = $candidateMatches[0]
            $objectId = [string](Get-DERAdoptionPropertyValue -InputObject $candidate -Name 'id')
            if ([string]::IsNullOrWhiteSpace($objectId)) { throw 'Exact-name adoption candidate does not contain a Microsoft ObjectId.' }

            $stateByObject = if (Test-DERAdoptionCommand 'Get-DERStateObject') { Get-DERStateObject -ObjectId $objectId } else { $null }
            if ($stateByObject -and [string]$stateByObject.DerId -ne [string]$planned.DerId) {
                $candidateList.Add([pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;ObjectType=$planned.ObjectType;DisplayName=$planned.DisplayName;ObjectId=$objectId;ComparisonScope=$entry.comparisonScope;ComparisonComplete=($entry.comparisonScope -eq 'ConfigurationBody');DifferenceCount=$null;CandidateStatus='Blocked';Decision='Skip';DecisionSource='Safety';SnapshotPath=$null;Notes=("ObjectId is already mapped to DER ID {0}; remapping is forbidden." -f $stateByObject.DerId);Differences=@()})
                continue
            }

            $itemUri = ([string]$entry.itemUriTemplate).Replace('{id}',$objectId)
            $actualRaw = Invoke-DERGraphRequest -Method GET -Uri $itemUri -ApiVersion ([string]$entry.apiVersion) -Component 'Adoption' -ActionId $actionId
            $actual = Protect-DERAdoptionData -InputObject $actualRaw
            $desiredInfo = Get-DERAdoptionDesiredProjection -BuildPlan $BuildPlan -PlannedObject $planned -CatalogEntry $entry
            $comparison = Compare-DERAdoptionCandidate -Actual $actual -Desired $desiredInfo.Desired

            $snapshotPath = Join-Path $snapshotRoot ("{0}-{1}.json" -f $planned.DerId,$objectId)
            $snapshot = [pscustomobject][ordered]@{
                SchemaVersion='1.0';TenantId=$BuildPlan.TenantId;RunId=$RunId;CapturedAt=(Get-Date).ToString('o');DerId=$planned.DerId;
                Module=$planned.Module;ObjectType=$planned.ObjectType;DisplayName=$planned.DisplayName;ObjectId=$objectId;ApiVersion=$entry.apiVersion;
                ItemUri=$itemUri;ComparisonScope=$desiredInfo.Scope;ComparisonComplete=$desiredInfo.Complete;Desired=$desiredInfo.Desired;Actual=$actual;Differences=@($comparison.Differences)
            }
            $snapshot | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
            $snapshotSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $snapshotPath).Hash.ToLowerInvariant()

            $record = [pscustomobject][ordered]@{
                DerId=$planned.DerId;Module=$planned.Module;ObjectType=$planned.ObjectType;DisplayName=$planned.DisplayName;ObjectId=$objectId;
                ComparisonScope=$desiredInfo.Scope;ComparisonComplete=[bool]$desiredInfo.Complete;DifferenceCount=@($comparison.Differences).Count;
                CandidateStatus='Candidate';Decision=$null;DecisionSource=$null;SnapshotPath=$snapshotPath;SnapshotSHA256=$snapshotSha;
                ItemUri=$itemUri;ApiVersion=$entry.apiVersion;NameProperty=$entry.nameProperty;Desired=$desiredInfo.Desired;Actual=$actual;Differences=@($comparison.Differences);Notes=$null
            }
            $candidateList.Add($record)
            if (Test-DERAdoptionCommand 'Register-DERTransaction') {
                Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module $planned.Module -DerId $planned.DerId -ObjectId $objectId -Message 'Exact-name customer object found; adoption comparison captured. No tenant write performed.' -Data @{comparisonScope=$desiredInfo.Scope;differenceCount=$record.DifferenceCount;snapshotSHA256=$snapshotSha} | Out-Null
            }
        } catch {
            $candidateList.Add([pscustomobject][ordered]@{DerId=$planned.DerId;Module=$planned.Module;ObjectType=$planned.ObjectType;DisplayName=$planned.DisplayName;ObjectId=$null;ComparisonScope=if($entry){$entry.comparisonScope}else{$null};ComparisonComplete=$false;DifferenceCount=$null;CandidateStatus='Blocked';Decision='Skip';DecisionSource='Error';SnapshotPath=$null;Notes=$_.Exception.Message;Differences=@()})
            Write-DERAdoptionLog -Level WARN -ActionId $actionId -Message ("Adoption scan blocked for {0}: {1}" -f $planned.DerId,$_.Exception.Message)
        }
    }

    # Validate every file-based Adopt decision against this run's candidate set before
    # mutating DER ownership state. One bad decision prevents partial local adoption.
    foreach ($fileDecision in @($decisions.Decisions | Where-Object {[string]$_.decision -eq 'Adopt'})) {
        $match = @($candidateList | Where-Object {[string]$_.DerId -eq [string]$fileDecision.derId -and $_.CandidateStatus -eq 'Candidate'} | Select-Object -First 1)
        if (-not $match.Count) { throw "Adoption decision requests $($fileDecision.derId), but this run did not produce exactly one valid candidate for that DER ID." }
        if ([string]$match[0].ObjectId -ne [string]$fileDecision.objectId) { throw "Adoption decision ObjectId mismatch for $($fileDecision.derId)." }
        if (-not [bool]$match[0].ComparisonComplete -and -not ($fileDecision.PSObject.Properties.Name -contains 'allowIncompleteComparison' -and [bool]$fileDecision.allowIncompleteComparison)) {
            throw "Adoption decision for $($fileDecision.derId) requires allowIncompleteComparison=true because only top-level comparison is available."
        }
    }

    foreach ($candidate in @($candidateList | Where-Object {$_.CandidateStatus -eq 'Candidate'})) {
        $actionId = if (Test-DERAdoptionCommand 'New-DERActionId') { New-DERActionId -Component 'ADOPT' } else { "ADOPT-$($candidate.DerId)" }
        $decision = Get-DERAdoptionDecisionForCandidate -Candidate $candidate -DecisionSet $decisions -Mode $Mode
        $candidate.Decision = $decision.Decision
        $candidate.DecisionSource = $decision.Source
        if ($decision.Notes) { $candidate.Notes = $decision.Notes }

        if ($decision.Decision -ne 'Adopt') {
            if (Test-DERAdoptionCommand 'Register-DERTransaction') {
                Register-DERTransaction -ActionId $actionId -Phase SKIP -Module $candidate.Module -DerId $candidate.DerId -ObjectId $candidate.ObjectId -Message 'Customer object was not adopted; DER ownership remains unchanged.' -Data @{decisionSource=$decision.Source} | Out-Null
            }
            continue
        }

        $identityExpected = [ordered]@{id=[string]$candidate.ObjectId}
        $identityExpected[[string]$candidate.NameProperty] = [string]$candidate.DisplayName
        $desiredHash = Get-DERAdoptionJsonSha256 -InputObject $candidate.Desired
        $metadata = [pscustomobject][ordered]@{
            Module=[string]$candidate.Module;ApiVersion=[string]$candidate.ApiVersion;ValidationUri=[string]$candidate.ItemUri;
            ExpectedSubset=[pscustomobject]$identityExpected;AdoptionDesiredSubset=$candidate.Desired;AdoptionDesiredHash=$desiredHash;
            AdoptionComparisonScope=[string]$candidate.ComparisonScope;AdoptionComparisonComplete=[bool]$candidate.ComparisonComplete;
            AdoptionDifferenceCount=[int]$candidate.DifferenceCount;AdoptionOriginalSnapshotPath=[string]$candidate.SnapshotPath;
            AdoptionOriginalSnapshotSHA256=[string]$candidate.SnapshotSHA256;AdoptionRunId=$RunId;AdoptionDecisionSource=[string]$decision.Source;
            AdoptionNoTenantWrite=$true;AdoptionAssignmentsChanged=$false;OriginalOwnershipClass='Customer-Owned'
        }

        if (Test-DERAdoptionCommand 'Register-DERTransaction') {
            Register-DERTransaction -ActionId $actionId -Phase RECORD_ORIGINAL -Module $candidate.Module -DerId $candidate.DerId -ObjectId $candidate.ObjectId -Message 'Recorded sanitized original customer-object snapshot before DER ownership adoption. No tenant write performed.' -Data @{snapshot=$candidate.SnapshotPath;sha256=$candidate.SnapshotSHA256} | Out-Null
        }
        Add-DERStateObject -DerId $candidate.DerId -ObjectId ([string]$candidate.ObjectId) -ObjectType ([string]$candidate.ObjectType) -DisplayName ([string]$candidate.DisplayName) -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion ([string]$BuildPlan.BaselineVersion) -DesiredHash $desiredHash -Metadata $metadata | Out-Null
        if (Test-DERAdoptionCommand 'Register-DERTransaction') {
            Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module $candidate.Module -DerId $candidate.DerId -ObjectId $candidate.ObjectId -Message 'Explicit customer-object adoption committed to DER state. Tenant object and assignments were not modified.' -Data @{decisionSource=$decision.Source;comparisonScope=$candidate.ComparisonScope} | Out-Null
        }
        Write-DERAdoptionLog -Level OK -ActionId $actionId -Message ("Adopted {0} -> {1} into DER ownership state without a tenant write." -f $candidate.DerId,$candidate.ObjectId)
    }

    $completed = Get-Date
    $result = [pscustomobject][ordered]@{
        SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;Mode=$Mode;DecisionPath=$decisions.Path;StartedAt=$started;CompletedAt=$completed;
        Summary=[pscustomobject][ordered]@{
            Scanned=$scanned;Candidates=@($candidateList | Where-Object CandidateStatus -eq 'Candidate').Count;
            Adopted=@($candidateList | Where-Object Decision -eq 'Adopt').Count;Skipped=@($candidateList | Where-Object Decision -eq 'Skip').Count;
            Ambiguous=@($candidateList | Where-Object CandidateStatus -eq 'Ambiguous').Count;Blocked=@($candidateList | Where-Object CandidateStatus -eq 'Blocked').Count
        };
        Candidates=@($candidateList);Artifacts=$null
    }
    $result.Artifacts = Write-DERAdoptionArtifacts -Result $result -Directory $adoptionRoot
    Write-DERAdoptionLog -Level OK -Message ("Adoption workflow complete: {0} candidate(s), {1} adopted, {2} skipped, {3} ambiguous/blocked." -f $result.Summary.Candidates,$result.Summary.Adopted,$result.Summary.Skipped,($result.Summary.Ambiguous+$result.Summary.Blocked)) -Data $result.Summary
    return $result
}

Export-ModuleMember -Function @(
    'Get-DERAdoptionCatalog','Get-DERAdoptionCatalogEntry','Get-DERAdoptionDesiredProjection','Compare-DERAdoptionCandidate',
    'Read-DERAdoptionDecisions','Invoke-DERAdoptionWorkflow'
)
