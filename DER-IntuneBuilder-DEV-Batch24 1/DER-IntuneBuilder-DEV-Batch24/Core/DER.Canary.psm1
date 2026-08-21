<#
.SYNOPSIS
    DER controlled tenant canary write/rollback harness.

.DESCRIPTION
    Creates exactly one isolated DER-owned Entra security group in a disposable
    test tenant, validates it by Object ID, rolls it back, validates soft-delete,
    permanently purges that exact deleted Object ID, and emits evidence.

    The canary requires a passing no-write evidence file produced by the exact same DER package.
    No existing customer object is modified, adopted, assigned, or deleted.

.NOTES
    Required parent entry point: Invoke-DERTenantCanary
#>


# Maintenance notes
# Responsibility: Runs one tightly bounded temporary security-group lifecycle after same-package no-write evidence passes.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERCanaryCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERCanaryLog {
    param([Parameter(Mandatory)][string]$Level,[Parameter(Mandatory)][string]$Message,$Data,[string]$ActionId)
    if(Test-DERCanaryCommand 'Write-DERLog') { Write-DERLog -Level $Level -Component 'Canary' -ActionId $ActionId -Message $Message -Data $Data }
}

function New-DERCanaryActionException {
    param([Parameter(Mandatory)][string]$Message,[string]$ActionId,[string]$DerId='CANARY-SECURITY-GROUP')
    $ex=[System.InvalidOperationException]::new($Message)
    $ex.Data['DERFailureKind']='Action';$ex.Data['DERComponent']='Canary'
    if($ActionId){$ex.Data['DERActionId']=$ActionId};if($DerId){$ex.Data['DERDerId']=$DerId}
    return $ex
}

function ConvertTo-DERCanaryHtmlSafe {
    param($Value)
    if($null -eq $Value){return ''}
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-DERCanaryPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $path=Join-Path $PackageRoot 'Definitions\Canary\DER-CanaryPolicy.json'
    if(-not(Test-Path -LiteralPath $path)){throw "DER canary policy is missing: $path"}
    try{$policy=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -Depth 100}catch{throw "DER canary policy is unreadable: $($_.Exception.Message)"}
    if([string]$policy.schemaVersion -ne '1.0' -or [string]$policy.policyVersion -ne '1.0.0'){throw 'DER canary policy version is unsupported.'}
    return $policy
}

function Test-DERCanaryPrerequisiteEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$PackageRoot
    )
    $findings=New-Object System.Collections.Generic.List[string]
    $manifestHash=$null
    if(-not(Test-Path -LiteralPath $Path)){$findings.Add('No-write evidence file does not exist.');return [pscustomobject]@{Success=$false;Findings=@($findings);Evidence=$null}}
    try{$evidence=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -Depth 100}catch{$findings.Add("No-write evidence is not valid JSON: $($_.Exception.Message)");return [pscustomobject]@{Success=$false;Findings=@($findings);Evidence=$null}}
    $policy=Get-DERCanaryPolicy -PackageRoot $PackageRoot
    $manifestPath=Join-Path $PackageRoot 'Definitions\Package\DER-PackageManifest.json'
    if(-not(Test-Path -LiteralPath $manifestPath)){$findings.Add('Package manifest is missing.')}else{$manifestHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash.ToLowerInvariant()}

    if([string]$evidence.schemaVersion -ne '1.0'){$findings.Add('No-write evidence schemaVersion is not 1.0.')}
    if([string]$evidence.evidenceType -ne 'DER-TestTenant-NoWrite'){$findings.Add('Evidence type is not DER-TestTenant-NoWrite.')}
    if([string]$evidence.packageVersion -ne [string]$policy.generatedForPackage){$findings.Add("Evidence packageVersion does not match this canary package ($($policy.generatedForPackage)).")}
    if([int]$evidence.buildNumber -ne [int]$policy.generatedForBuild){$findings.Add("Evidence buildNumber does not match this canary internal build ($($policy.generatedForBuild)).")}
    if([string]$evidence.tenantId -ne $TenantId){$findings.Add('Evidence tenantId does not match the connected tenant.')}
    if(-not [bool]$evidence.passed){$findings.Add('No-write evidence did not pass.')}
    if(@($evidence.failedChecks).Count -ne 0){$findings.Add('No-write evidence contains failed checks.')}
    if($null -eq $evidence.graphAudit -or [long]$evidence.graphAudit.TransportWriteCount -ne 0){$findings.Add('Evidence does not prove zero Graph transport writes.')}
    if($null -eq $evidence.authentication -or $null -eq $evidence.authentication.audit -or [long]$evidence.authentication.audit.WriteSessionAttempts -ne 0 -or [long]$evidence.authentication.audit.WriteSessionsOpened -ne 0){$findings.Add('Evidence does not prove zero write-authentication attempts/sessions.')}
    if($null -eq $evidence.sourceSafety -or [int]$evidence.sourceSafety.bypassFindingCount -ne 0){$findings.Add('Evidence does not prove zero Graph transport bypass findings.')}
    if($null -eq $evidence.transactionSafety -or [int]$evidence.transactionSafety.writeTransactionCount -ne 0){$findings.Add('Evidence contains write transaction phases.')}
    if([string]::IsNullOrWhiteSpace([string]$evidence.supportingHashes.packageManifestSHA256)){$findings.Add('Evidence is missing package manifest SHA-256.')}elseif($manifestHash -and [string]$evidence.supportingHashes.packageManifestSHA256 -ne $manifestHash){$findings.Add('Evidence package-manifest SHA-256 does not match the current package.')}

    return [pscustomobject]@{Success=($findings.Count -eq 0);Findings=@($findings);Evidence=$evidence;ManifestSHA256=$manifestHash}
}

function Confirm-DERCanaryApproval {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session,[Parameter(Mandatory)]$Policy)
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host ' DER CONTROLLED CANARY WRITE' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host (' Tenant        : {0}' -f $Session.TenantName)
    Write-Host (' Tenant ID     : {0}' -f $Session.TenantId)
    Write-Host (' Signed in as  : {0}' -f $Session.Account)
    Write-Host ' Action        : Create ONE empty DER canary security group'
    Write-Host ' Rollback      : Delete it, verify deleted item, permanently purge exact Object ID'
    Write-Host ' Existing data : No existing group/object will be modified or adopted'
    Write-Host (' Required role : {0}' -f (@($Policy.operator.requiredRoles) -join ' or '))
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host ''
    Write-Host ("Type {0} to authorize this controlled canary write." -f $Policy.operator.confirmationToken) -ForegroundColor Yellow
    $entered=Read-Host 'Canary approval'
    $confirmed=($entered.Trim() -ceq [string]$Policy.operator.confirmationToken)
    return [pscustomobject][ordered]@{Confirmed=$confirmed;TokenRequired=[string]$Policy.operator.confirmationToken;TenantId=[string]$Session.TenantId;TenantName=[string]$Session.TenantName;Account=[string]$Session.Account;ConfirmedAt=(Get-Date).ToString('o')}
}

function New-DERCanaryStep {
    param([string]$Id,[string]$Status,[string]$Message,$Data)
    return [pscustomobject][ordered]@{Id=$Id;Status=$Status;Message=$Message;Data=$Data;Timestamp=(Get-Date).ToString('o')}
}

function Wait-DERCanaryAbsent {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$ActionId,[int]$Attempts=8,[int]$DelaySeconds=2)
    for($i=1;$i -le $Attempts;$i++){
        $found=Invoke-DERGraphRequest -Method GET -Uri $Uri -ApiVersion 'v1.0' -Component 'Canary' -ActionId $ActionId -AllowNotFound
        if($null -eq $found){return $true}
        if($i -lt $Attempts){Start-Sleep -Seconds $DelaySeconds}
    }
    return $false
}

function Wait-DERCanaryPresent {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$ActionId,[int]$Attempts=8,[int]$DelaySeconds=2)
    for($i=1;$i -le $Attempts;$i++){
        $found=Invoke-DERGraphRequest -Method GET -Uri $Uri -ApiVersion 'v1.0' -Component 'Canary' -ActionId $ActionId -AllowNotFound
        if($null -ne $found){return $found}
        if($i -lt $Attempts){Start-Sleep -Seconds $DelaySeconds}
    }
    return $null
}

function New-DERCanaryEvidence {
    param(
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$TenantId,[string]$TenantName,
        [Parameter(Mandatory)][string]$RuntimeRoot,[Parameter(Mandatory)][string]$PackageRoot,[Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)]$Prerequisite,[Parameter(Mandatory)]$Approval,[Parameter(Mandatory)]$GraphBefore,[Parameter(Mandatory)]$GraphAfter,
        [Parameter(Mandatory)]$AuthBefore,[Parameter(Mandatory)]$AuthAfter,[Parameter(Mandatory)]$Object,[Parameter(Mandatory)][object[]]$Steps,
        [Parameter(Mandatory)][bool]$Passed,[string[]]$Failures,[Parameter(Mandatory)][bool]$CleanupComplete
    )
    $root=Join-Path (Join-Path (Join-Path $RuntimeRoot 'Evidence') $TenantId) $RunId
    New-Item -ItemType Directory -Path $root -Force|Out-Null
    $jsonPath=Join-Path $root 'DER-CanaryEvidence.json';$htmlPath=Join-Path $root 'DER-CanaryEvidence.html';$csvPath=Join-Path $root 'DER-CanarySteps.csv'
    @($Steps|Select-Object Id,Status,Message,Timestamp)|Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
    $delta=[ordered]@{
        requestAttempts=[long]$GraphAfter.RequestAttemptCount-[long]$GraphBefore.RequestAttemptCount
        transportRequests=[long]$GraphAfter.TransportRequestCount-[long]$GraphBefore.TransportRequestCount
        transportReads=[long]$GraphAfter.TransportReadCount-[long]$GraphBefore.TransportReadCount
        transportWrites=[long]$GraphAfter.TransportWriteCount-[long]$GraphBefore.TransportWriteCount
        blockedWrites=[long]$GraphAfter.BlockedWriteCount-[long]$GraphBefore.BlockedWriteCount
        post=[long]$GraphAfter.TransportByMethod.POST-[long]$GraphBefore.TransportByMethod.POST
        patch=[long]$GraphAfter.TransportByMethod.PATCH-[long]$GraphBefore.TransportByMethod.PATCH
        put=[long]$GraphAfter.TransportByMethod.PUT-[long]$GraphBefore.TransportByMethod.PUT
        delete=[long]$GraphAfter.TransportByMethod.DELETE-[long]$GraphBefore.TransportByMethod.DELETE
    }
    $authDelta=[ordered]@{
        writeSessionAttempts=[long]$AuthAfter.WriteSessionAttempts-[long]$AuthBefore.WriteSessionAttempts
        writeSessionsOpened=[long]$AuthAfter.WriteSessionsOpened-[long]$AuthBefore.WriteSessionsOpened
    }
    $evidence=[ordered]@{
        schemaVersion='1.0';evidenceType='DER-Canary-Pilot';policyVersion=[string]$Policy.policyVersion;packageVersion=[string]$Policy.generatedForPackage;buildNumber=[int]$Policy.generatedForBuild;
        runId=$RunId;tenantId=$TenantId;tenantName=$TenantName;completedAt=(Get-Date).ToString('o');passed=$Passed;failures=@($Failures);cleanupComplete=$CleanupComplete;
        prerequisite=[ordered]@{path=$Prerequisite.Path;sha256=$Prerequisite.SHA256;runId=[string]$Prerequisite.Evidence.runId;passed=[bool]$Prerequisite.Evidence.passed;packageManifestSHA256=[string]$Prerequisite.Evidence.supportingHashes.packageManifestSHA256};
        operatorApproval=$Approval;
        controlledObject=$Object;
        graphDelta=$delta;authenticationDelta=$authDelta;steps=@($Steps)
    }
    $evidence|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $jsonPath -Encoding utf8
    $sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $jsonPath).Hash.ToLowerInvariant()
    $rows=foreach($s in $Steps){"<tr><td>$(ConvertTo-DERCanaryHtmlSafe $s.Id)</td><td>$(ConvertTo-DERCanaryHtmlSafe $s.Status)</td><td>$(ConvertTo-DERCanaryHtmlSafe $s.Message)</td></tr>"}
    $html=@"
<!doctype html><html><head><meta charset="utf-8"><title>DER Canary Evidence</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:36px;color:#1f2937}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}.pass{color:#047857}.fail{color:#b91c1c}code{background:#f3f4f6;padding:2px 4px}</style></head><body>
<h1>DER Controlled Canary Evidence</h1><p>Tenant: $(ConvertTo-DERCanaryHtmlSafe $TenantName) | $(ConvertTo-DERCanaryHtmlSafe $TenantId)<br>Run: $(ConvertTo-DERCanaryHtmlSafe $RunId)</p>
<h2 class="$(if($Passed){'pass'}else{'fail'})">$(if($Passed){'PASS — create/read-back/rollback/purge verified'}else{'FAIL — canary contract not fully satisfied'})</h2>
<p>Object ID: <code>$(ConvertTo-DERCanaryHtmlSafe $Object.objectId)</code><br>Display name: $(ConvertTo-DERCanaryHtmlSafe $Object.displayName)<br>Graph writes in canary delta: $($delta.transportWrites) (POST=$($delta.post), PATCH=$($delta.patch), PUT=$($delta.put), DELETE=$($delta.delete))<br>Cleanup complete: $CleanupComplete</p>
<table><thead><tr><th>Step</th><th>Status</th><th>Evidence</th></tr></thead><tbody>$($rows -join [Environment]::NewLine)</tbody></table><p>JSON evidence SHA-256: <code>$sha</code></p></body></html>
"@
    $html|Set-Content -LiteralPath $htmlPath -Encoding utf8
    return [pscustomobject]@{Passed=$Passed;EvidencePath=$jsonPath;EvidenceSHA256=$sha;HtmlPath=$htmlPath;StepsCsv=$csvPath;CleanupComplete=$CleanupComplete;GraphDelta=[pscustomobject]$delta}
}

function Invoke-DERTenantCanary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)]$DiscoverySession,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$PackageRoot,
        [Parameter(Mandatory)][string]$NoWriteEvidencePath
    )
    foreach($cmd in @('Invoke-DERGraphRequest','Set-DERGraphWriteGuard','Connect-DERWriteSession','Get-DERGraphRequestAuditSummary','Get-DERAuthenticationAuditSummary')){if(-not(Test-DERCanaryCommand $cmd)){throw "DER canary requires $cmd."}}
    $policy=Get-DERCanaryPolicy -PackageRoot $PackageRoot
    $tenantId=[string]$DiscoverySession.TenantId;$tenantName=[string]$DiscoverySession.TenantName
    $pre=Test-DERCanaryPrerequisiteEvidence -Path $NoWriteEvidencePath -TenantId $tenantId -PackageRoot $PackageRoot
    if(-not $pre.Success){throw ('DER canary prerequisite failed: ' + (@($pre.Findings)-join ' '))}
    $preSha=(Get-FileHash -Algorithm SHA256 -LiteralPath $NoWriteEvidencePath).Hash.ToLowerInvariant()
    $prerequisite=[pscustomobject]@{Path=(Resolve-Path -LiteralPath $NoWriteEvidencePath).Path;SHA256=$preSha;Evidence=$pre.Evidence}
    $approval=Confirm-DERCanaryApproval -Session $DiscoverySession -Policy $policy
    if(-not $approval.Confirmed){throw (New-DERCanaryActionException -Message 'DER canary approval was not granted. No canary write was performed.')}

    $graphBefore=Get-DERGraphRequestAuditSummary;$authBefore=Get-DERAuthenticationAuditSummary
    $steps=New-Object System.Collections.Generic.List[object];$failures=New-Object System.Collections.Generic.List[string]
    $objectId=$null;$displayName=$null;$mailNickname=$null;$cleanupComplete=$false;$created=$false
    $actionId=if(Test-DERCanaryCommand 'New-DERActionId'){New-DERActionId -Component 'CANARY'}else{"CANARY-$RunId"}
    try{
        $suffix=($RunId -replace '[^A-Za-z0-9]','').ToLowerInvariant();if($suffix.Length -gt 24){$suffix=$suffix.Substring($suffix.Length-24)}
        $displayName="DER Canary - DELETE ME - $RunId";$mailNickname="der-canary-$suffix"
        $escaped=$displayName.Replace("'","''")
        $collision=Invoke-DERGraphRequest -Method GET -Uri ("groups?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $escaped) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'
        if(@($collision.value).Count -gt 0){throw (New-DERCanaryActionException -Message 'A group already exists with the generated canary display name. DER refuses to reuse or touch it.' -ActionId $actionId)}
        $steps.Add((New-DERCanaryStep 'CAN-001' 'Pass' 'Unique canary name confirmed; no existing object will be reused.' @{displayName=$displayName}))
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -Message 'Canary prerequisite/evidence/name prechecks passed.'|Out-Null}

        Set-DERGraphWriteGuard -Mode Normal -Reason 'Controlled canary approved. Only DER.Canary may perform the single-object lifecycle.'|Out-Null
        $writeScopes=@($policy.graph.requiredDelegatedScopes)
        $writeSession=Connect-DERWriteSession -RunId $RunId -ExpectedTenantId $tenantId -Scopes $writeScopes
        if([string]$writeSession.TenantId -ne $tenantId){throw (New-DERCanaryActionException -Message 'Canary write authentication tenant mismatch.' -ActionId $actionId)}
        $steps.Add((New-DERCanaryStep 'CAN-002' 'Pass' 'Write session opened in the same tenant with the canary-only delegated scope set.' @{scopes=@($writeSession.Scopes)}))

        $body=[ordered]@{displayName=$displayName;description="DER controlled canary object for run $RunId. Expected immediate rollback and permanent purge.";mailEnabled=$false;mailNickname=$mailNickname;securityEnabled=$true;groupTypes=@()}
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -Message 'Prepared isolated DER-owned canary security group create.' -Data @{displayName=$displayName}|Out-Null}
        $createdObject=Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion 'v1.0' -Body $body -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'
        $objectId=[string]$createdObject.id;if([string]::IsNullOrWhiteSpace($objectId)){throw (New-DERCanaryActionException -Message 'Graph create returned without a group Object ID.' -ActionId $actionId)};$created=$true
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase CREATED -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary group created.'|Out-Null}
        if(Test-DERCanaryCommand 'Add-DERStateObject'){
            Add-DERStateObject -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -ObjectType 'microsoft.graph.group' -DisplayName $displayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -Metadata ([ordered]@{Module='Canary';DeleteUri="groups/$objectId";ValidationUri="groups/$objectId";ApiVersion='v1.0';ExpectedCurrentSubset=[ordered]@{id=$objectId;displayName=$displayName;mailEnabled=$false;securityEnabled=$true};Canary=$true})|Out-Null
        }
        $steps.Add((New-DERCanaryStep 'CAN-003' 'Pass' 'Exactly one DER-owned canary group was created and bound to its returned Microsoft Object ID.' @{objectId=$objectId;displayName=$displayName}))

        $read=Wait-DERCanaryPresent -Uri ("groups/{0}?`$select=id,displayName,description,mailEnabled,mailNickname,securityEnabled,groupTypes" -f $objectId) -ActionId $actionId
        if($null -eq $read -or [string]$read.id -ne $objectId -or [string]$read.displayName -ne $displayName -or [bool]$read.mailEnabled -ne $false -or [bool]$read.securityEnabled -ne $true){throw (New-DERCanaryActionException -Message 'Canary create read-back did not match the exact object DER created.' -ActionId $actionId)}
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase READBACK -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary create read-back matched expected object.'|Out-Null;Register-DERTransaction -ActionId $actionId -Phase VALIDATE -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary object validation passed.'|Out-Null}
        $steps.Add((New-DERCanaryStep 'CAN-004' 'Pass' 'Create read-back matched Object ID, display name, and security-group properties.' @{objectId=$objectId}))

        Invoke-DERGraphRequest -Method DELETE -Uri ("groups/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'|Out-Null
        if(-not(Wait-DERCanaryAbsent -Uri ("groups/{0}" -f $objectId) -ActionId $actionId)){throw (New-DERCanaryActionException -Message 'Canary rollback delete returned but the active group still resolves.' -ActionId $actionId)}
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase ROLLBACK -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary active group deleted.'|Out-Null}
        $steps.Add((New-DERCanaryStep 'CAN-005' 'Pass' 'Rollback removed the canary from active groups and read-back confirmed it no longer resolves.' @{objectId=$objectId}))

        $tombstone=Wait-DERCanaryPresent -Uri ("directory/deletedItems/{0}?`$select=id,displayName,groupTypes" -f $objectId) -ActionId $actionId
        if($null -eq $tombstone -or [string]$tombstone.id -ne $objectId -or [string]$tombstone.displayName -ne $displayName){throw (New-DERCanaryActionException -Message 'DER could not verify the exact canary Object ID/name in deleted items; permanent purge refused.' -ActionId $actionId)}
        $steps.Add((New-DERCanaryStep 'CAN-006' 'Pass' 'Soft-deleted tombstone matched the exact canary Object ID and display name.' @{objectId=$objectId}))

        Invoke-DERGraphRequest -Method DELETE -Uri ("directory/deletedItems/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'|Out-Null
        if(-not(Wait-DERCanaryAbsent -Uri ("directory/deletedItems/{0}" -f $objectId) -ActionId $actionId)){throw (New-DERCanaryActionException -Message 'Permanent canary purge returned but the deleted item still resolves.' -ActionId $actionId)}
        $cleanupComplete=$true
        if(Test-DERCanaryCommand 'Remove-DERStateObject'){Remove-DERStateObject -ObjectId $objectId -Reason 'Canary lifecycle completed; exact Object ID was permanently purged.'|Out-Null}
        if(Test-DERCanaryCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase ROLLBACK_VALIDATE -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary rollback and permanent purge validated.'|Out-Null;Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'Canary' -DerId 'CANARY-SECURITY-GROUP' -ObjectId $objectId -Message 'Canary lifecycle committed as successful test evidence; no active/deleted object remains.'|Out-Null}
        $steps.Add((New-DERCanaryStep 'CAN-007' 'Pass' 'Exact deleted canary Object ID was permanently purged and no longer resolves.' @{objectId=$objectId}))
    }
    catch{
        $canaryError=$_
        $failures.Add($canaryError.Exception.Message);$steps.Add((New-DERCanaryStep 'CAN-FAIL' 'Fail' $canaryError.Exception.Message @{objectId=$objectId;displayName=$displayName}))
        if(Test-DERCanaryCommand 'Write-DERError'){Write-DERError -ErrorRecord $canaryError -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP' -Message ('Canary main path failed: {0}' -f $canaryError.Exception.Message)}else{Write-DERCanaryLog -Level ERROR -ActionId $actionId -Message ('Canary main path failed: {0}' -f $canaryError.Exception.Message) -Data @{objectId=$objectId;displayName=$displayName}}
        if($created -and $objectId){
            try{
                # Emergency cleanup is restricted to the exact Object ID returned by this run.
                $active=Invoke-DERGraphRequest -Method GET -Uri ("groups/{0}?`$select=id,displayName" -f $objectId) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -AllowNotFound
                if($active){
                    if([string]$active.id -ne $objectId -or [string]$active.displayName -ne $displayName){throw (New-DERCanaryActionException -Message 'Emergency cleanup identity check failed; refusing deletion.' -ActionId $actionId)}
                    Invoke-DERGraphRequest -Method DELETE -Uri ("groups/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'|Out-Null
                    $null=Wait-DERCanaryAbsent -Uri ("groups/{0}" -f $objectId) -ActionId $actionId
                }
                $deleted=Wait-DERCanaryPresent -Uri ("directory/deletedItems/{0}?`$select=id,displayName" -f $objectId) -ActionId $actionId
                if($deleted){
                    if([string]$deleted.id -ne $objectId -or [string]$deleted.displayName -ne $displayName){throw (New-DERCanaryActionException -Message 'Emergency purge identity check failed; refusing permanent deletion.' -ActionId $actionId)}
                    Invoke-DERGraphRequest -Method DELETE -Uri ("directory/deletedItems/{0}" -f $objectId) -ApiVersion 'v1.0' -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP'|Out-Null
                    $cleanupComplete=Wait-DERCanaryAbsent -Uri ("directory/deletedItems/{0}" -f $objectId) -ActionId $actionId
                } else {$cleanupComplete=$true}
                if($cleanupComplete -and (Test-DERCanaryCommand 'Remove-DERStateObject')){Remove-DERStateObject -ObjectId $objectId -Reason 'Canary emergency cleanup completed.'|Out-Null}
                $steps.Add((New-DERCanaryStep 'CAN-CLEANUP' $(if($cleanupComplete){'Pass'}else{'Fail'}) 'Emergency cleanup attempted for the exact canary Object ID.' @{objectId=$objectId;cleanupComplete=$cleanupComplete}))
            }catch{$cleanupError=$_;$cleanupComplete=$false;$failures.Add("Emergency cleanup failed: $($cleanupError.Exception.Message)");$steps.Add((New-DERCanaryStep 'CAN-CLEANUP' 'Fail' ("Emergency cleanup failed: {0}" -f $cleanupError.Exception.Message) @{objectId=$objectId}));if(Test-DERCanaryCommand 'Write-DERError'){Write-DERError -ErrorRecord $cleanupError -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP' -Message 'Canary emergency cleanup failed.'}}
        }
    }
    finally{
        try{Set-DERGraphWriteGuard -Mode DenyAll -Reason 'Canary write window closed.'|Out-Null}
        catch{throw ("DER failed to close the canary write guard: {0}" -f $_.Exception.Message)}
    }

    $graphAfter=Get-DERGraphRequestAuditSummary;$authAfter=Get-DERAuthenticationAuditSummary
    $postDelta=[long]$graphAfter.TransportByMethod.POST-[long]$graphBefore.TransportByMethod.POST;$patchDelta=[long]$graphAfter.TransportByMethod.PATCH-[long]$graphBefore.TransportByMethod.PATCH;$putDelta=[long]$graphAfter.TransportByMethod.PUT-[long]$graphBefore.TransportByMethod.PUT;$deleteDelta=[long]$graphAfter.TransportByMethod.DELETE-[long]$graphBefore.TransportByMethod.DELETE
    $contractOk=($created -and $cleanupComplete -and $postDelta -eq 1 -and $patchDelta -eq 0 -and $putDelta -eq 0 -and $deleteDelta -eq 2 -and ([long]$authAfter.WriteSessionsOpened-[long]$authBefore.WriteSessionsOpened) -eq 1)
    if(-not $contractOk){$failures.Add('Canary mutation/authentication delta did not match the exact one-object contract (POST=1, PATCH=0, PUT=0, DELETE=2, write session=1).')}
    $object=[ordered]@{derId='CANARY-SECURITY-GROUP';objectId=$objectId;displayName=$displayName;mailNickname=$mailNickname;objectType='microsoft.graph.group';ownershipClass='DER-Owned';activeObjectRemaining=(-not $cleanupComplete);deletedObjectRemaining=(-not $cleanupComplete)}
    $result=New-DERCanaryEvidence -RunId $RunId -TenantId $tenantId -TenantName $tenantName -RuntimeRoot $RuntimeRoot -PackageRoot $PackageRoot -Policy $policy -Prerequisite $prerequisite -Approval $approval -GraphBefore $graphBefore -GraphAfter $graphAfter -AuthBefore $authBefore -AuthAfter $authAfter -Object $object -Steps @($steps) -Passed ($contractOk -and $failures.Count -eq 0) -Failures @($failures) -CleanupComplete $cleanupComplete
    if($result.Passed){Write-DERCanaryLog -Level OK -ActionId $actionId -Message ("Controlled canary completed. Passed={0}; CleanupComplete={1}; Evidence={2}" -f $result.Passed,$result.CleanupComplete,$result.EvidencePath) -Data $result}else{if(Test-DERCanaryCommand 'Write-DERActionFailure'){Write-DERActionFailure -Component 'Canary' -ActionId $actionId -DerId 'CANARY-SECURITY-GROUP' -Level CRITICAL -Message ("Controlled canary failed. CleanupComplete={0}; Evidence={1}" -f $result.CleanupComplete,$result.EvidencePath) -Data $result}else{Write-DERCanaryLog -Level CRITICAL -ActionId $actionId -Message ("Controlled canary failed. Evidence={0}" -f $result.EvidencePath) -Data $result}}
    return $result
}

Export-ModuleMember -Function @('Get-DERCanaryPolicy','Test-DERCanaryPrerequisiteEvidence','Confirm-DERCanaryApproval','Invoke-DERTenantCanary')
