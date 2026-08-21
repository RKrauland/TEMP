<#
.SYNOPSIS
    DER controlled end-to-end workload pilot harness.
.DESCRIPTION
    Executes exactly one temporary DER Groups workload object in a disposable
    test tenant, validates the workload read-back/state contract, invokes the
    normal DER rollback engine with an exact-object filter, verifies rollback,
    permanently purges the exact soft-deleted pilot object, and emits evidence.

    A passing same-package no-write integration run and a passing same-package
    controlled canary run are mandatory prerequisites.
#>


# Maintenance notes
# Responsibility: Invokes one real Groups workload object and normal rollback under a tightly bounded disposable-tenant pilot contract.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERPilotCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERPilotLog { param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DERPilotCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Pilot' -ActionId $ActionId -Message $Message -Data $Data} }
function New-DERPilotActionException {
    param([Parameter(Mandatory)][string]$Message,[string]$ActionId,[string]$DerId)
    $ex=[System.InvalidOperationException]::new($Message)
    $ex.Data['DERFailureKind']='Action';$ex.Data['DERComponent']='Pilot'
    if($ActionId){$ex.Data['DERActionId']=$ActionId};if($DerId){$ex.Data['DERDerId']=$DerId}
    return $ex
}
function ConvertTo-DERPilotHtmlSafe { param($Value) if($null -eq $Value){return ''}; return [System.Net.WebUtility]::HtmlEncode([string]$Value) }
function New-DERPilotStep { param([string]$Id,[string]$Status,[string]$Message,$Data) [pscustomobject][ordered]@{Id=$Id;Status=$Status;Message=$Message;Data=$Data;Timestamp=(Get-Date).ToString('o')} }

function Get-DERPilotPolicy {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$PackageRoot)
    $path=Join-Path $PackageRoot 'Definitions\Pilot\DER-PilotPolicy.json'
    if(-not(Test-Path -LiteralPath $path)){throw "DER pilot policy is missing: $path"}
    try{$p=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -Depth 100}catch{throw "DER pilot policy is unreadable: $($_.Exception.Message)"}
    if([string]$p.schemaVersion -ne '1.0' -or [string]$p.policyVersion -ne '1.0.0'){throw 'DER pilot policy version is unsupported.'}
    return $p
}

function Test-DERPilotPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NoWriteEvidencePath,
        [Parameter(Mandatory)][string]$CanaryEvidencePath,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$PackageRoot
    )
    $findings=New-Object System.Collections.Generic.List[string]
    $policy=Get-DERPilotPolicy -PackageRoot $PackageRoot
    $manifestPath=Join-Path $PackageRoot 'Definitions\Package\DER-PackageManifest.json'
    if(-not(Test-Path -LiteralPath $manifestPath)){throw 'DER package manifest is missing.'}
    $manifestHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()

    $nw=$null;$can=$null
    if(-not(Test-Path -LiteralPath $NoWriteEvidencePath)){$findings.Add('No-write evidence file does not exist.')}else{try{$nw=Get-Content -LiteralPath $NoWriteEvidencePath -Raw|ConvertFrom-Json -Depth 100}catch{$findings.Add("No-write evidence is invalid JSON: $($_.Exception.Message)")}}
    if(-not(Test-Path -LiteralPath $CanaryEvidencePath)){$findings.Add('Canary evidence file does not exist.')}else{try{$can=Get-Content -LiteralPath $CanaryEvidencePath -Raw|ConvertFrom-Json -Depth 100}catch{$findings.Add("Canary evidence is invalid JSON: $($_.Exception.Message)")}}

    if($nw){
        if([string]$nw.evidenceType -ne 'DER-TestTenant-NoWrite'){$findings.Add('No-write evidence type is invalid.')}
        if([string]$nw.packageVersion -ne [string]$policy.generatedForPackage){$findings.Add('No-write evidence is not from this DER v1 package identity.')}
        if([int]$nw.buildNumber -ne [int]$policy.generatedForBuild){$findings.Add('No-write evidence is not from this exact DER internal build.')}
        if([string]$nw.tenantId -ne $TenantId){$findings.Add('No-write evidence tenant does not match the connected tenant.')}
        if(-not[bool]$nw.passed -or @($nw.failedChecks).Count -ne 0){$findings.Add('No-write evidence did not pass.')}
        if($null -eq $nw.graphAudit -or [long]$nw.graphAudit.TransportWriteCount -ne 0){$findings.Add('No-write evidence does not prove zero Graph transport writes.')}
        if($null -eq $nw.authentication -or $null -eq $nw.authentication.audit -or [long]$nw.authentication.audit.WriteSessionAttempts -ne 0 -or [long]$nw.authentication.audit.WriteSessionsOpened -ne 0){$findings.Add('No-write evidence does not prove zero write-authentication attempts/sessions.')}
        if($null -eq $nw.sourceSafety -or [int]$nw.sourceSafety.bypassFindingCount -ne 0){$findings.Add('No-write evidence does not prove zero Graph bypass findings.')}
        if([string]$nw.supportingHashes.packageManifestSHA256 -ne $manifestHash){$findings.Add('No-write evidence package-manifest hash does not match this package.')}
    }
    if($can){
        if([string]$can.evidenceType -ne 'DER-Canary-Pilot'){$findings.Add('Canary evidence type is invalid.')}
        if([string]$can.packageVersion -ne [string]$policy.generatedForPackage){$findings.Add('Canary evidence is not from this DER v1 package identity.')}
        if([int]$can.buildNumber -ne [int]$policy.generatedForBuild){$findings.Add('Canary evidence is not from this exact DER internal build.')}
        if([string]$can.tenantId -ne $TenantId){$findings.Add('Canary evidence tenant does not match the connected tenant.')}
        if(-not[bool]$can.passed -or @($can.failures).Count -ne 0 -or -not[bool]$can.cleanupComplete){$findings.Add('Canary evidence did not pass with complete cleanup.')}
        if($null -eq $can.graphDelta -or [long]$can.graphDelta.post -ne 1 -or [long]$can.graphDelta.patch -ne 0 -or [long]$can.graphDelta.put -ne 0 -or [long]$can.graphDelta.delete -ne 2){$findings.Add('Canary mutation delta does not match the required one-object contract.')}
        if($null -eq $can.authenticationDelta -or [long]$can.authenticationDelta.writeSessionsOpened -ne 1){$findings.Add('Canary evidence does not prove exactly one write session.')}
        if($null -eq $can.controlledObject -or [bool]$can.controlledObject.activeObjectRemaining -or [bool]$can.controlledObject.deletedObjectRemaining){$findings.Add('Canary evidence indicates an object remained after cleanup.')}
        if($null -eq $can.prerequisite -or [string]$can.prerequisite.packageManifestSHA256 -ne $manifestHash){$findings.Add('Canary evidence package-manifest hash does not match this package.')}
        if($nw -and $null -ne $can.prerequisite -and [string]$can.prerequisite.sha256 -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $NoWriteEvidencePath).Hash.ToLowerInvariant()){$findings.Add('Canary evidence was not chained to the exact no-write evidence file supplied to this pilot.')}
    }
    return [pscustomobject]@{
        Success=($findings.Count -eq 0);Findings=@($findings);Policy=$policy;PackageManifestSHA256=$manifestHash;
        NoWriteEvidence=$nw;CanaryEvidence=$can;
        NoWriteSHA256=$(if(Test-Path -LiteralPath $NoWriteEvidencePath){(Get-FileHash -Algorithm SHA256 -LiteralPath $NoWriteEvidencePath).Hash.ToLowerInvariant()}else{$null});
        CanarySHA256=$(if(Test-Path -LiteralPath $CanaryEvidencePath){(Get-FileHash -Algorithm SHA256 -LiteralPath $CanaryEvidencePath).Hash.ToLowerInvariant()}else{$null})
    }
}

function Confirm-DERPilotApproval {
    [CmdletBinding()]param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string]$DisplayName)
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host ' DER END-TO-END WORKLOAD PILOT' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host (' Tenant        : {0}' -f $Session.TenantName)
    Write-Host (' Tenant ID     : {0}' -f $Session.TenantId)
    Write-Host (' Signed in as  : {0}' -f $Session.Account)
    Write-Host (' Workload      : {0}' -f $Policy.workload.module)
    Write-Host (' Temporary obj : {0}' -f $DisplayName)
    Write-Host ' Lifecycle     : Workload create -> read-back -> state -> normal rollback -> purge'
    Write-Host ' Existing data : No existing customer object will be modified/adopted/deleted'
    Write-Host (' Required role : {0}' -f (@($Policy.operator.requiredRoles) -join ' or '))
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host ''
    Write-Host ("Type {0} to authorize this one-object pilot." -f $Policy.operator.confirmationToken) -ForegroundColor Yellow
    $entered=Read-Host 'Pilot approval'
    [pscustomobject][ordered]@{Confirmed=($entered.Trim() -ceq [string]$Policy.operator.confirmationToken);TokenRequired=[string]$Policy.operator.confirmationToken;TenantId=[string]$Session.TenantId;TenantName=[string]$Session.TenantName;Account=[string]$Session.Account;DisplayName=$DisplayName;ConfirmedAt=(Get-Date).ToString('o')}
}

function Wait-DERPilotAbsent {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$ActionId,[int]$Attempts=8,[int]$DelaySeconds=2)
    for($i=1;$i -le $Attempts;$i++){$v=Invoke-DERGraphRequest -Method GET -Uri $Uri -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $ActionId -AllowNotFound;if($null -eq $v){return $true};if($i -lt $Attempts){Start-Sleep -Seconds $DelaySeconds}}
    return $false
}
function Wait-DERPilotPresent {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$ActionId,[int]$Attempts=8,[int]$DelaySeconds=2)
    for($i=1;$i -le $Attempts;$i++){$v=Invoke-DERGraphRequest -Method GET -Uri $Uri -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $ActionId -AllowNotFound;if($null -ne $v){return $v};if($i -lt $Attempts){Start-Sleep -Seconds $DelaySeconds}}
    return $null
}

function New-DERPilotEvidence {
    param(
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$TenantId,[string]$TenantName,[Parameter(Mandatory)][string]$RuntimeRoot,[Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)]$Prerequisite,[Parameter(Mandatory)]$Approval,[Parameter(Mandatory)]$GraphBefore,[Parameter(Mandatory)]$GraphAfter,[Parameter(Mandatory)]$AuthBefore,[Parameter(Mandatory)]$AuthAfter,
        $WorkloadResult,$RollbackResult,[Parameter(Mandatory)]$Object,[Parameter(Mandatory)][object[]]$Steps,[Parameter(Mandatory)][bool]$Passed,[string[]]$Failures,[Parameter(Mandatory)][bool]$CleanupComplete,
        [bool]$StateCreated,[bool]$StateRemoved
    )
    $dir=Join-Path (Join-Path (Join-Path $RuntimeRoot 'Evidence') $TenantId) $RunId;New-Item -ItemType Directory -Path $dir -Force|Out-Null
    $jsonPath=Join-Path $dir 'DER-PilotEvidence.json';$htmlPath=Join-Path $dir 'DER-PilotEvidence.html';$csvPath=Join-Path $dir 'DER-PilotSteps.csv'
    @($Steps|Select-Object Id,Status,Message,Timestamp)|Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
    $g=[ordered]@{requestAttempts=[long]$GraphAfter.RequestAttemptCount-[long]$GraphBefore.RequestAttemptCount;transportRequests=[long]$GraphAfter.TransportRequestCount-[long]$GraphBefore.TransportRequestCount;transportReads=[long]$GraphAfter.TransportReadCount-[long]$GraphBefore.TransportReadCount;transportWrites=[long]$GraphAfter.TransportWriteCount-[long]$GraphBefore.TransportWriteCount;blockedWrites=[long]$GraphAfter.BlockedWriteCount-[long]$GraphBefore.BlockedWriteCount;post=[long]$GraphAfter.TransportByMethod.POST-[long]$GraphBefore.TransportByMethod.POST;patch=[long]$GraphAfter.TransportByMethod.PATCH-[long]$GraphBefore.TransportByMethod.PATCH;put=[long]$GraphAfter.TransportByMethod.PUT-[long]$GraphBefore.TransportByMethod.PUT;delete=[long]$GraphAfter.TransportByMethod.DELETE-[long]$GraphBefore.TransportByMethod.DELETE}
    $a=[ordered]@{writeSessionAttempts=[long]$AuthAfter.WriteSessionAttempts-[long]$AuthBefore.WriteSessionAttempts;writeSessionsOpened=[long]$AuthAfter.WriteSessionsOpened-[long]$AuthBefore.WriteSessionsOpened}
    $e=[ordered]@{
        schemaVersion='1.0';evidenceType='DER-Workload-Pilot';policyVersion=[string]$Policy.policyVersion;packageVersion=[string]$Policy.generatedForPackage;buildNumber=[int]$Policy.generatedForBuild;runId=$RunId;tenantId=$TenantId;tenantName=$TenantName;completedAt=(Get-Date).ToString('o');passed=$Passed;failures=@($Failures);cleanupComplete=$CleanupComplete;
        prerequisites=[ordered]@{packageManifestSHA256=$Prerequisite.PackageManifestSHA256;noWrite=[ordered]@{path=$Prerequisite.NoWritePath;sha256=$Prerequisite.NoWriteSHA256;runId=[string]$Prerequisite.NoWriteEvidence.runId;passed=[bool]$Prerequisite.NoWriteEvidence.passed};canary=[ordered]@{path=$Prerequisite.CanaryPath;sha256=$Prerequisite.CanarySHA256;runId=[string]$Prerequisite.CanaryEvidence.runId;passed=[bool]$Prerequisite.CanaryEvidence.passed;cleanupComplete=[bool]$Prerequisite.CanaryEvidence.cleanupComplete}};
        operatorApproval=$Approval;workload=[ordered]@{module='Groups';entryPoint='Invoke-DERGroupsModule';derId=[string]$Object.derId;displayName=[string]$Object.displayName;objectId=[string]$Object.objectId;workloadStatus=$(if($WorkloadResult){[string]$WorkloadResult.Status}else{$null});rollbackStatus=$(if($RollbackResult){if([int]$RollbackResult.Summary.RolledBack -eq 1){'RolledBack'}else{'Failed'}}else{$null})};
        stateLifecycle=[ordered]@{created=$StateCreated;removedAfterRollback=$StateRemoved};controlledObject=$Object;graphDelta=$g;authenticationDelta=$a;steps=@($Steps)
    }
    $e|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $jsonPath -Encoding utf8
    $sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $jsonPath).Hash.ToLowerInvariant()
    $rows=foreach($s in $Steps){"<tr><td>$(ConvertTo-DERPilotHtmlSafe $s.Id)</td><td>$(ConvertTo-DERPilotHtmlSafe $s.Status)</td><td>$(ConvertTo-DERPilotHtmlSafe $s.Message)</td></tr>"}
    $html=@"
<!doctype html><html><head><meta charset="utf-8"><title>DER Pilot Evidence</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:36px;color:#1f2937}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}.pass{color:#047857}.fail{color:#b91c1c}code{background:#f3f4f6;padding:2px 4px}</style></head><body>
<h1>DER End-to-End Workload Pilot Evidence</h1><p>Tenant: $(ConvertTo-DERPilotHtmlSafe $TenantName) | $(ConvertTo-DERPilotHtmlSafe $TenantId)<br>Run: $(ConvertTo-DERPilotHtmlSafe $RunId)</p>
<h2 class="$(if($Passed){'pass'}else{'fail'})">$(if($Passed){'PASS — workload, validation, rollback, and cleanup verified'}else{'FAIL — pilot contract not fully satisfied'})</h2>
<p>Workload: <b>Groups</b><br>DER ID: <code>$(ConvertTo-DERPilotHtmlSafe $Object.derId)</code><br>Object ID: <code>$(ConvertTo-DERPilotHtmlSafe $Object.objectId)</code><br>Graph writes: $($g.transportWrites) (POST=$($g.post), PATCH=$($g.patch), PUT=$($g.put), DELETE=$($g.delete))<br>Cleanup complete: $CleanupComplete</p>
<table><thead><tr><th>Step</th><th>Status</th><th>Evidence</th></tr></thead><tbody>$($rows -join [Environment]::NewLine)</tbody></table><p>JSON evidence SHA-256: <code>$sha</code></p></body></html>
"@
    $html|Set-Content -LiteralPath $htmlPath -Encoding utf8
    [pscustomobject]@{Passed=$Passed;CleanupComplete=$CleanupComplete;EvidencePath=$jsonPath;EvidenceSHA256=$sha;HtmlPath=$htmlPath;StepsCsv=$csvPath;GraphDelta=[pscustomobject]$g}
}

function Invoke-DERWorkloadPilot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)]$DiscoverySession,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][string]$NoWriteEvidencePath,
        [Parameter(Mandatory)][string]$CanaryEvidencePath
    )
    foreach($cmd in @('Invoke-DERGraphRequest','Set-DERGraphWriteGuard','Connect-DERWriteSession','Get-DERGraphRequestAuditSummary','Get-DERAuthenticationAuditSummary','Invoke-DERGroupsModule','Invoke-DERModuleRollback','Get-DERStateObject','Test-DERExpectedSubset')){if(-not(Test-DERPilotCommand $cmd)){throw "DER pilot requires $cmd."}}
    $tenantId=[string]$DiscoverySession.TenantId;$tenantName=[string]$DiscoverySession.TenantName
    $pre=Test-DERPilotPrerequisites -NoWriteEvidencePath $NoWriteEvidencePath -CanaryEvidencePath $CanaryEvidencePath -TenantId $tenantId -PackageRoot $PackageRoot
    if(-not$pre.Success){throw ('DER pilot prerequisite failed: ' + (@($pre.Findings)-join ' '))}
    $pre|Add-Member -NotePropertyName NoWritePath -NotePropertyValue (Resolve-Path -LiteralPath $NoWriteEvidencePath).Path -Force
    $pre|Add-Member -NotePropertyName CanaryPath -NotePropertyValue (Resolve-Path -LiteralPath $CanaryEvidencePath).Path -Force
    $policy=$pre.Policy

    $suffix=($RunId -replace '[^A-Za-z0-9]','');if($suffix.Length -gt 28){$suffix=$suffix.Substring($suffix.Length-28)}
    $displayName=([string]$policy.workload.displayNamePrefix)+$suffix
    $approval=Confirm-DERPilotApproval -Session $DiscoverySession -Policy $policy -DisplayName $displayName
    if(-not$approval.Confirmed){throw (New-DERPilotActionException -Message 'DER pilot approval was not granted. No pilot write was performed.')}

    $graphBefore=Get-DERGraphRequestAuditSummary;$authBefore=Get-DERAuthenticationAuditSummary
    $steps=New-Object System.Collections.Generic.List[object];$failures=New-Object System.Collections.Generic.List[string]
    $objectId=$null;$stateCreated=$false;$stateRemoved=$false;$cleanupComplete=$false;$workloadResult=$null;$rollbackResult=$null;$created=$false
    $actionId=if(Test-DERPilotCommand 'New-DERActionId'){New-DERActionId -Component 'PILOT'}else{"PILOT-$RunId"}
    try{
        $escaped=$displayName.Replace("'","''")
        $collision=Invoke-DERGraphRequest -Method GET -Uri ("groups?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $escaped) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId
        if(@($collision.value).Count -gt 0){throw (New-DERPilotActionException -Message 'A group already exists with the generated pilot display name. DER refuses to reuse or touch it.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $steps.Add((New-DERPilotStep 'PIL-001' 'Pass' 'Prerequisite evidence and unique-name precheck passed.' @{displayName=$displayName}))

        $writeSession=Connect-DERWriteSession -RunId $RunId -ExpectedTenantId $tenantId -Scopes @($policy.graph.requiredDelegatedScopes) -Environment $DiscoverySession.Environment
        if([string]$writeSession.TenantId -ne $tenantId){throw (New-DERPilotActionException -Message 'Pilot write authentication tenant mismatch.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        Set-DERGraphWriteGuard -Mode Normal -Reason 'One-object workload pilot approved. Parent invokes only DER.Groups, exact-object rollback, and exact tombstone purge.'|Out-Null
        $steps.Add((New-DERPilotStep 'PIL-002' 'Pass' 'Same-tenant write session opened and pilot write window enabled.' @{scopes=@($writeSession.Scopes)}))

        $plan=[pscustomobject][ordered]@{
            TenantId=$tenantId;TenantName=$tenantName;BaselineVersion='1.0.0';
            Answers=[pscustomobject]@{Enrollment=[pscustomobject]@{AutopilotGroupTag='DER-PILOT-NOT-USED'}};
            Objects=@([pscustomobject][ordered]@{DerId=[string]$policy.workload.derId;Module='Groups';Enabled=$true;ObjectType='SecurityGroup';DisplayName=$displayName;Metadata=[pscustomobject]@{PrincipalType='Device';Membership='Assigned'}})
        }
        $workloadResult=Invoke-DERGroupsModule -BuildPlan $plan -RunId $RunId -RuntimeRoot $RuntimeRoot
        $pilotEngineFailures=@($workloadResult.Results|Where-Object{$_.PSObject.Properties.Name -contains 'FailureKind' -and [string]$_.FailureKind -eq 'Engine'})
        if($pilotEngineFailures.Count -gt 0){
            $pilotEngineException=[System.InvalidOperationException]::new('Groups workload reported a DER engine/runtime failure during the controlled pilot.')
            $pilotEngineException.Data['DERFailureKind']='Engine';$pilotEngineException.Data['DERComponent']='Pilot';$pilotEngineException.Data['DERActionId']=$actionId;$pilotEngineException.Data['DERDerId']=[string]$policy.workload.derId
            throw $pilotEngineException
        }
        if($workloadResult.Status -ne 'Completed' -or [int]$workloadResult.Summary.Created -ne 1 -or [int]$workloadResult.Summary.Failed -ne 0 -or @($workloadResult.Results).Count -ne 1 -or [string]$workloadResult.Results[0].Status -ne 'Created'){throw (New-DERPilotActionException -Message 'Groups workload did not return the exact one-object successful pilot result.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $objectId=[string]$workloadResult.Results[0].ObjectId;if([string]::IsNullOrWhiteSpace($objectId)){throw (New-DERPilotActionException -Message 'Groups workload returned no pilot Object ID.' -ActionId $actionId -DerId ([string]$policy.workload.derId))};$created=$true
        $steps.Add((New-DERPilotStep 'PIL-003' 'Pass' 'Real DER Groups workload created exactly one DER-owned object.' @{objectId=$objectId;entryPoint='Invoke-DERGroupsModule'}))

        $state=Get-DERStateObject -DerId ([string]$policy.workload.derId)
        if($null -eq $state -or [string]$state.ObjectId -ne $objectId -or [string]$state.OwnershipClass -ne 'DER-Owned' -or [string]$state.CreatedByRunId -ne $RunId){throw (New-DERPilotActionException -Message 'Pilot state record did not bind the DER ID to the exact created Object ID/current run.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $stateCreated=$true
        $read=Invoke-DERGraphRequest -Method GET -Uri ([string]$state.Metadata.ValidationUri) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId
        $cmp=Test-DERExpectedSubset -Actual $read -Expected $state.Metadata.ExpectedSubset
        if(-not$cmp.Success -or [string]$read.id -ne $objectId -or [string]$read.displayName -ne $displayName){throw (New-DERPilotActionException -Message 'Pilot workload read-back validation failed.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $steps.Add((New-DERPilotStep 'PIL-004' 'Pass' 'Workload state and Microsoft read-back match the exact pilot object.' @{objectId=$objectId}))

        $rollbackResult=Invoke-DERModuleRollback -Module 'Groups' -RunId $RunId -RuntimeRoot $RuntimeRoot -Reason 'Controlled workload pilot rollback.' -DerId ([string]$policy.workload.derId) -ObjectId $objectId
        if([int]$rollbackResult.Summary.RolledBack -ne 1 -or [int]$rollbackResult.Summary.Failed -ne 0 -or [int]$rollbackResult.Summary.ManualRequired -ne 0){throw (New-DERPilotActionException -Message 'Exact-object rollback did not report one clean rollback.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        if(-not(Wait-DERPilotAbsent -Uri ("groups/{0}" -f $objectId) -ActionId $actionId)){throw (New-DERPilotActionException -Message 'Rollback returned but the active pilot group still resolves.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $remaining=Get-DERStateObject -DerId ([string]$policy.workload.derId);$stateRemoved=($null -eq $remaining)
        if(-not$stateRemoved){throw (New-DERPilotActionException -Message 'Rollback removed the Graph object but pilot state still contains the DER ID.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $steps.Add((New-DERPilotStep 'PIL-005' 'Pass' 'Normal DER rollback engine removed the exact active object and its current state record.' @{objectId=$objectId}))

        $deleted=Wait-DERPilotPresent -Uri ("directory/deletedItems/{0}?`$select=id,displayName" -f $objectId) -ActionId $actionId
        if($null -eq $deleted -or [string]$deleted.id -ne $objectId -or [string]$deleted.displayName -ne $displayName){throw (New-DERPilotActionException -Message 'Pilot rollback tombstone identity could not be verified; permanent cleanup refused.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        Invoke-DERGraphRequest -Method DELETE -Uri ("directory/deletedItems/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId -DerId ([string]$policy.workload.derId)|Out-Null
        if(-not(Wait-DERPilotAbsent -Uri ("directory/deletedItems/{0}" -f $objectId) -ActionId $actionId)){throw (New-DERPilotActionException -Message 'Permanent pilot cleanup returned but the deleted item still resolves.' -ActionId $actionId -DerId ([string]$policy.workload.derId))}
        $cleanupComplete=$true
        $steps.Add((New-DERPilotStep 'PIL-006' 'Pass' 'Exact soft-deleted pilot Object ID was permanently purged; tenant object inventory is back to pre-pilot state.' @{objectId=$objectId}))
    }
    catch{
        $pilotError=$_
        $failures.Add($pilotError.Exception.Message);$steps.Add((New-DERPilotStep 'PIL-FAIL' 'Fail' $pilotError.Exception.Message @{objectId=$objectId;displayName=$displayName}))
        $pilotDerId=if($policy -and $policy.workload){[string]$policy.workload.derId}else{$null}
        if(Test-DERPilotCommand 'Write-DERError'){Write-DERError -ErrorRecord $pilotError -Component 'Pilot' -ActionId $actionId -DerId $pilotDerId -Message ('Pilot main path failed: {0}' -f $pilotError.Exception.Message)}else{Write-DERPilotLog -Level ERROR -ActionId $actionId -Message ('Pilot main path failed: {0}' -f $pilotError.Exception.Message) -Data @{objectId=$objectId;displayName=$displayName}}
        if($created -and $objectId){
            try{
                # Emergency cleanup remains bound to the exact Object ID returned by this run.
                $active=Invoke-DERGraphRequest -Method GET -Uri ("groups/{0}?`$select=id,displayName" -f $objectId) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId -AllowNotFound
                if($active){if([string]$active.id -ne $objectId -or [string]$active.displayName -ne $displayName){throw (New-DERPilotActionException -Message 'Emergency cleanup active-object identity mismatch; deletion refused.' -ActionId $actionId -DerId ([string]$policy.workload.derId))};Invoke-DERGraphRequest -Method DELETE -Uri ("groups/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId -DerId ([string]$policy.workload.derId)|Out-Null;$null=Wait-DERPilotAbsent -Uri ("groups/{0}" -f $objectId) -ActionId $actionId}
                $deleted=Wait-DERPilotPresent -Uri ("directory/deletedItems/{0}?`$select=id,displayName" -f $objectId) -ActionId $actionId
                if($deleted){if([string]$deleted.id -ne $objectId -or [string]$deleted.displayName -ne $displayName){throw (New-DERPilotActionException -Message 'Emergency cleanup tombstone identity mismatch; purge refused.' -ActionId $actionId -DerId ([string]$policy.workload.derId))};Invoke-DERGraphRequest -Method DELETE -Uri ("directory/deletedItems/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Pilot' -ActionId $actionId -DerId ([string]$policy.workload.derId)|Out-Null;$cleanupComplete=Wait-DERPilotAbsent -Uri ("directory/deletedItems/{0}" -f $objectId) -ActionId $actionId}else{$cleanupComplete=$true}
                if($cleanupComplete -and (Test-DERPilotCommand 'Remove-DERStateObject')){Remove-DERStateObject -ObjectId $objectId -Reason 'Pilot emergency cleanup completed.'|Out-Null;$stateRemoved=$true}
                $steps.Add((New-DERPilotStep 'PIL-CLEANUP' $(if($cleanupComplete){'Pass'}else{'Fail'}) 'Emergency cleanup attempted for the exact pilot Object ID.' @{objectId=$objectId;cleanupComplete=$cleanupComplete}))
            }catch{$cleanupError=$_;$cleanupComplete=$false;$failures.Add("Emergency cleanup failed: $($cleanupError.Exception.Message)");$steps.Add((New-DERPilotStep 'PIL-CLEANUP' 'Fail' ("Emergency cleanup failed: {0}" -f $cleanupError.Exception.Message) @{objectId=$objectId}));if(Test-DERPilotCommand 'Write-DERError'){Write-DERError -ErrorRecord $cleanupError -Component 'Pilot' -ActionId $actionId -DerId ([string]$policy.workload.derId) -Message 'Pilot emergency cleanup failed.'}}
        }
    }
    finally{
        try{Set-DERGraphWriteGuard -Mode DenyAll -Reason 'Pilot write window closed.'|Out-Null}
        catch{throw ("DER failed to close the pilot write guard: {0}" -f $_.Exception.Message)}
    }

    $graphAfter=Get-DERGraphRequestAuditSummary;$authAfter=Get-DERAuthenticationAuditSummary
    $post=[long]$graphAfter.TransportByMethod.POST-[long]$graphBefore.TransportByMethod.POST;$patch=[long]$graphAfter.TransportByMethod.PATCH-[long]$graphBefore.TransportByMethod.PATCH;$put=[long]$graphAfter.TransportByMethod.PUT-[long]$graphBefore.TransportByMethod.PUT;$delete=[long]$graphAfter.TransportByMethod.DELETE-[long]$graphBefore.TransportByMethod.DELETE
    $contractOk=($created -and $stateCreated -and $stateRemoved -and $cleanupComplete -and $post -eq 1 -and $patch -eq 0 -and $put -eq 0 -and $delete -eq 2 -and ([long]$authAfter.WriteSessionsOpened-[long]$authBefore.WriteSessionsOpened) -eq 1)
    if(-not$contractOk){$failures.Add('Pilot mutation/auth/state lifecycle did not match the exact contract (POST=1, PATCH=0, PUT=0, DELETE=2, write session=1, state create/remove=true).')}
    $obj=[ordered]@{derId=[string]$policy.workload.derId;objectId=$objectId;displayName=$displayName;objectType='microsoft.graph.group';ownershipClass='DER-Owned';activeObjectRemaining=(-not$cleanupComplete);deletedObjectRemaining=(-not$cleanupComplete)}
    $result=New-DERPilotEvidence -RunId $RunId -TenantId $tenantId -TenantName $tenantName -RuntimeRoot $RuntimeRoot -Policy $policy -Prerequisite $pre -Approval $approval -GraphBefore $graphBefore -GraphAfter $graphAfter -AuthBefore $authBefore -AuthAfter $authAfter -WorkloadResult $workloadResult -RollbackResult $rollbackResult -Object $obj -Steps @($steps) -Passed ($contractOk -and $failures.Count -eq 0) -Failures @($failures) -CleanupComplete $cleanupComplete -StateCreated $stateCreated -StateRemoved $stateRemoved
    if($result.Passed){Write-DERPilotLog -Level OK -ActionId $actionId -Message ("Workload pilot completed. Passed={0}; CleanupComplete={1}; Evidence={2}" -f $result.Passed,$result.CleanupComplete,$result.EvidencePath) -Data $result}else{if(Test-DERPilotCommand 'Write-DERActionFailure'){Write-DERActionFailure -Component 'Pilot' -ActionId $actionId -DerId ([string]$policy.workload.derId) -Level CRITICAL -Message ("Workload pilot failed. CleanupComplete={0}; Evidence={1}" -f $result.CleanupComplete,$result.EvidencePath) -Data $result}else{Write-DERPilotLog -Level CRITICAL -ActionId $actionId -Message ("Workload pilot failed. Evidence={0}" -f $result.EvidencePath) -Data $result}}
    return $result
}

Export-ModuleMember -Function @('Get-DERPilotPolicy','Test-DERPilotPrerequisites','Confirm-DERPilotApproval','Invoke-DERWorkloadPilot')
