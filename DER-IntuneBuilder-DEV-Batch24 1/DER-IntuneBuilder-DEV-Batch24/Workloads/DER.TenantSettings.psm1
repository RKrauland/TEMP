<#
.SYNOPSIS
    DER Intune tenant operations workload.

.DESCRIPTION
    Implements tenant-level Intune operations that DER can currently complete
    and validate end-to-end:
      - Windows managed-device cleanup rule.
      - Company Portal default branding-profile IT/support contact fields.

    Device cleanup is DER-owned. The default Company Portal branding profile is
    a Microsoft/customer built-in object, so DER treats only the explicitly
    managed support fields as DER-Adopted and records their original state for
    safe rollback.
#>


# Maintenance notes
# Responsibility: Manages approved Intune tenant settings/branding/support values with singleton/adoption safeguards.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Workload-local failure factory.
#
# A deliberate workload safety/precondition/read-back refusal is an ACTION failure:
# DER executed the intended code path, but the requested tenant operation cannot be
# completed safely.  ENGINE is reserved for invariant failures that indicate DER's
# own logic/catalog is inconsistent.  Unexpected PowerShell exceptions are never
# routed through this helper and therefore remain ENGINE by default.
function New-DERWorkloadFailureException {
    <#
    .SYNOPSIS
        Creates a deliberate workload exception without destroying failure provenance.

    .DESCRIPTION
        Use this helper only when the workload intentionally stops because a known
        precondition, tenant condition, read-back result, ownership rule, or internal
        invariant prevents safe completion.

        FailureKind defaults to Auto:
          - No inner exception: ACTION. The workload deliberately refused/completed
            unsuccessfully even though DER itself executed normally.
          - Tagged inner exception: inherit the original ACTION/ENGINE classification.
          - Untagged inner exception: ENGINE. An unexpected PowerShell/runtime problem
            must never be disguised as a tenant/action failure merely because it was
            caught while DER was performing an action.

        DER correlation metadata from the inner exception is copied forward so the
        same Incident ID, Action ID, DER ID, Microsoft context, and originating
        component remain reconstructable when a workload adds a friendlier message.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Auto','Action','Engine')][string]$FailureKind='Auto',
        [System.Exception]$InnerException
    )

    $effectiveFailureKind=$FailureKind
    if($effectiveFailureKind -eq 'Auto'){
        if($InnerException){
            $inherited=$null
            if($InnerException.Data -and $InnerException.Data.Contains('DERFailureKind')){
                $candidate=[string]$InnerException.Data['DERFailureKind']
                if($candidate -in @('Action','Engine')){$inherited=$candidate}
            }
            $effectiveFailureKind=if($inherited){$inherited}else{'Engine'}
        }else{
            $effectiveFailureKind='Action'
        }
    }

    $exception=if($InnerException){
        [System.InvalidOperationException]::new($Message,$InnerException)
    }else{
        [System.InvalidOperationException]::new($Message)
    }
    $exception.Data['DERFailureKind']=$effectiveFailureKind

    # Preserve every DER-prefixed correlation/forensic datum supplied by the
    # originating exception.  Do not copy arbitrary third-party Exception.Data
    # values here because those can be large or contain data DER did not choose
    # to persist.  The original inner exception remains available in diagnostics.
    if($InnerException -and $InnerException.Data){
        foreach($key in $InnerException.Data.Keys){
            $name=[string]$key
            if($name -like 'DER*' -and -not $exception.Data.Contains($name)){
                $exception.Data[$name]=$InnerException.Data[$key]
            }
        }
    }

    $moduleName=[string]$ExecutionContext.SessionState.Module.Name
    if(-not [string]::IsNullOrWhiteSpace($moduleName) -and -not $exception.Data.Contains('DERComponent')){
        $exception.Data['DERComponent']=$moduleName.Replace('DER.','')
    }
    if(-not $exception.Data.Contains('DERIncidentId') -and (Get-Command New-DERIncidentId -ErrorAction SilentlyContinue)){
        $exception.Data['DERIncidentId']=New-DERIncidentId
    }
    return $exception
}


function Test-DERTenantSettingsCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERTenantSettingsLog {
    param([string]$Level,[string]$Message,$Data,[string]$ActionId)
    if (Test-DERTenantSettingsCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'TenantSettings' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function Save-DERTenantSettingsResult {
    param($Result)
    $ctx = if (Test-DERTenantSettingsCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $dir 'TenantSettings.json') -Encoding UTF8
    }
}

function Get-DERTenantSettingsStateObject {
    param([Parameter(Mandatory)][string]$DerId)
    if (Test-DERTenantSettingsCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}

function New-DERDeviceCleanupRuleBody {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned)
    $days = [int]$BuildPlan.Answers.Operations.DeviceCleanupDays
    if ($days -lt 30 -or $days -gt 270) { throw (New-DERWorkloadFailureException -Message "DER Windows device cleanup days must be between 30 and 270; received $days.") }
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.managedDeviceCleanupRule'
        displayName = $Planned.DisplayName
        description = 'Customer Windows managed-device cleanup rule. Hides stale Intune records; does not wipe/retire devices or delete Microsoft Entra device objects.'
        deviceCleanupRulePlatformType = 'windows'
        deviceInactivityBeforeRetirementInDays = $days
    }
}

function Get-DERDesiredSupportFields {
    param([Parameter(Mandatory)]$BuildPlan)
    $ops = $BuildPlan.Answers.Operations
    $desired = [ordered]@{}
    if (-not [string]::IsNullOrWhiteSpace([string]$ops.SupportName)) {
        $desired.contactITName = [string]$ops.SupportName
        $desired.onlineSupportSiteName = [string]$ops.SupportName
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ops.SupportEmail)) { $desired.contactITEmailAddress = [string]$ops.SupportEmail }
    if (-not [string]::IsNullOrWhiteSpace([string]$ops.SupportPhone)) { $desired.contactITPhoneNumber = [string]$ops.SupportPhone }
    if (-not [string]::IsNullOrWhiteSpace([string]$ops.SupportUrl)) { $desired.onlineSupportSiteUrl = [string]$ops.SupportUrl }
    return $desired
}

function Get-DERSupportOriginalFields {
    param([Parameter(Mandatory)]$BrandingProfile,[Parameter(Mandatory)]$Desired)
    $original = [ordered]@{}
    foreach ($name in @($Desired.Keys)) {
        $value = $null
        if ($BrandingProfile.PSObject.Properties.Name -contains $name) { $value = $BrandingProfile.$name }
        $original[$name] = $value
    }
    return $original
}

function Invoke-DERTenantCleanupAction {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$ActionId)

    if (-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis) {
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;Status='Skipped';Message='Managed-device cleanup rule creation requires a DER-approved Graph Preview API and Preview APIs are disabled.';ActionId=$ActionId}
    }

    $state = Get-DERTenantSettingsStateObject -DerId $Planned.DerId
    if ($state) {
        Assert-DERManagedStateObject -StateRecord $state -Component 'TenantSettings' -ActionId $ActionId -AllowedOwnershipClass @('DER-Owned') | Out-Null
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='DER-owned Windows device cleanup rule exists and matches recorded state.';ActionId=$ActionId}
    }

    $all = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/managedDeviceCleanupRules' -ApiVersion beta -Component 'TenantSettings' -ActionId $ActionId
    $overlap = @($all | Where-Object { [string]$_.deviceCleanupRulePlatformType -in @('windows','all') })
    if ($overlap.Count) {
        $sameName = @($overlap | Where-Object { [string]$_.displayName -eq [string]$Planned.DisplayName } | Select-Object -First 1)
        $existingRule = if ($sameName.Count) { $sameName[0] } else { $overlap[0] }
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$existingRule.id;Status='Skipped';Message=("An existing {0} device cleanup rule already overlaps Windows devices ('{1}'). DER will not create a competing cleanup rule; compare/adopt it explicitly." -f $existingRule.deviceCleanupRulePlatformType,$existingRule.displayName);ActionId=$ActionId}
    }

    $body = New-DERDeviceCleanupRuleBody -BuildPlan $BuildPlan -Planned $Planned
    $created = Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/managedDeviceCleanupRules' -ApiVersion beta -Body $body -Component 'TenantSettings' -DerId $Planned.DerId -ActionId $ActionId
    if (-not $created.id) { throw (New-DERWorkloadFailureException -Message 'Managed-device cleanup rule create response did not include an object ID.') }

    $uri = "deviceManagement/managedDeviceCleanupRules/$($created.id)"
    $expected = [pscustomobject]@{
        displayName=$Planned.DisplayName
        deviceCleanupRulePlatformType='windows'
        deviceInactivityBeforeRetirementInDays=[int]$BuildPlan.Answers.Operations.DeviceCleanupDays
    }
    $meta = [pscustomobject]@{Module='TenantSettings';ApiVersion='beta';ValidationUri=$uri;DeleteUri=$uri;ExpectedSubset=$expected}
    Add-DERStateObject -DerId $Planned.DerId -ObjectId $created.id -ObjectType $Planned.ObjectType -DisplayName $Planned.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null

    $read = Invoke-DERGraphRequest -Method GET -Uri $uri -ApiVersion beta -Component 'TenantSettings' -ActionId $ActionId
    if (Test-DERTenantSettingsCommand 'Test-DERExpectedSubset') {
        $compare = Test-DERExpectedSubset -Actual $read -Expected $expected
        if (-not $compare.Success) { throw (New-DERWorkloadFailureException -Message 'Windows device cleanup rule failed read-back validation.') }
    }
    Update-DERStateObject -ObjectId $created.id -MarkValidated | Out-Null
    return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$created.id;Status='Created';Message='Windows device cleanup rule created and validated.';ActionId=$ActionId}
}

function Invoke-DERTenantSupportAction {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$ActionId)

    if (-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis) {
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;Status='Skipped';Message='Company Portal branding-profile support fields currently require a DER-approved Graph Preview API and Preview APIs are disabled.';ActionId=$ActionId}
    }
    $desired=Get-DERDesiredSupportFields -BuildPlan $BuildPlan
    if(-not @($desired.Keys).Count){
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;Status='Skipped';Message='No customer IT/support contact values were supplied.';ActionId=$ActionId}
    }

    $state=Get-DERTenantSettingsStateObject -DerId $Planned.DerId
    if($state){
        Assert-DERManagedStateObject -StateRecord $state -Component 'TenantSettings' -ActionId $ActionId -AllowedOwnershipClass @('DER-Adopted') | Out-Null
    }

    $profiles=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/intuneBrandingProfiles' -ApiVersion beta -Component 'TenantSettings' -ActionId $ActionId
    $default=@($profiles | Where-Object { [bool]$_.isDefaultProfile } | Select-Object -First 1)
    if(-not $default.Count){
        return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;Status='Skipped';Message='DER could not resolve the Microsoft Intune default Company Portal branding profile; support information was not changed.';ActionId=$ActionId}
    }
    $default=$default[0]
    $uri="deviceManagement/intuneBrandingProfiles/$($default.id)"
    if($state -and [string]$state.ObjectId -ne [string]$default.id){throw (New-DERWorkloadFailureException -Message "DER RECONCILIATION_REQUIRED: recorded Company Portal branding profile '$($state.ObjectId)' is no longer the current default profile '$($default.id)'.")}
    $current=Invoke-DERGraphRequest -Method GET -Uri $uri -ApiVersion beta -Component 'TenantSettings' -ActionId $ActionId
    $original=Get-DERSupportOriginalFields -BrandingProfile $current -Desired $desired
    $compareBefore=Test-DERExpectedSubset -Actual $current -Expected $desired
    $alreadyMatches=[bool]$compareBefore.Success

    if(-not $state){
        $initialExpected=if($alreadyMatches){[pscustomobject]$desired}else{[pscustomobject]$original}
        $baseMetadata=[pscustomobject][ordered]@{Module='TenantSettings';ApiVersion='beta';ValidationUri=$uri;ExpectedSubset=$initialExpected;BuiltInTenantObjects=$true;AdoptionNoTenantWrite=$true}
        $state=Add-DERStateObject -DerId $Planned.DerId -ObjectId ([string]$default.id) -ObjectType $Planned.ObjectType -DisplayName $Planned.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $baseMetadata
    }

    if(-not $alreadyMatches){
        if(Test-DERTenantSettingsCommand 'Register-DERTransaction'){
            Register-DERTransaction -ActionId $ActionId -Phase RECORD_ORIGINAL -Module 'TenantSettings' -DerId $Planned.DerId -ObjectId $default.id -Message 'Recorded original Company Portal support fields before DER update.' -Data $original | Out-Null
        }
        $rollbackMetadata=[pscustomobject][ordered]@{
            Module='TenantSettings';ApiVersion='beta';ValidationUri=$uri;UpdateUri=$uri;UpdateMethod='PATCH'
            OriginalState=[pscustomobject]$original;OriginalExpectedSubset=[pscustomobject]$original
            ExpectedSubset=[pscustomobject]$desired;BuiltInTenantObjects=$true;AdoptionNoTenantWrite=$false
        }
        $state=Set-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $ActionId -RollbackMetadata $rollbackMetadata
        Invoke-DERGraphRequest -Method PATCH -Uri $uri -ApiVersion beta -Body $desired -Component 'TenantSettings' -DerId $Planned.DerId -ActionId $ActionId | Out-Null
    }

    $state=Get-DERStateObject -DerId $Planned.DerId
    Assert-DERManagedStateObject -StateRecord $state -Component 'TenantSettings' -ActionId $ActionId -AllowedOwnershipClass @('DER-Adopted') -MarkValidated | Out-Null
    if(-not $alreadyMatches){Clear-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $ActionId | Out-Null}
    if(Test-DERTenantSettingsCommand 'Register-DERTransaction'){
        Register-DERTransaction -ActionId $ActionId -Phase COMMIT -Module 'TenantSettings' -DerId $Planned.DerId -ObjectId $state.ObjectId -Message 'Company Portal support fields read-back validated.' -Data @{tenantWrite=(-not $alreadyMatches)} | Out-Null
    }
    $message=if($alreadyMatches){'Company Portal support information already matched the engineer-approved values; DER recorded an ownership-only adoption for drift detection.'}else{'Company Portal support information updated and read-back validated; current-run rollback preparation was cleared after commit.'}
    return [pscustomobject]@{DerId=$Planned.DerId;DisplayName=$Planned.DisplayName;ObjectId=$state.ObjectId;Status=if($alreadyMatches){'Existing'}else{'Created'};Message=$message;ActionId=$ActionId}
}

function Complete-DERTenantSettingsResult {
    param($Results,[string]$RunId)
    $summary = [pscustomobject]@{
        Created=@($Results|Where-Object Status -eq 'Created').Count
        Existing=@($Results|Where-Object Status -eq 'Existing').Count
        Skipped=@($Results|Where-Object Status -eq 'Skipped').Count
        Failed=@($Results|Where-Object Status -eq 'Failed').Count
    }
    $out = [pscustomobject]@{
        Module='TenantSettings';RunId=$RunId
        Status=if($summary.Failed){'CompletedWithFailures'}elseif($summary.Created-or$summary.Existing){'Completed'}else{'Skipped'}
        CriticalFailure=$false;Summary=$summary;Results=@($Results)
    }
    Save-DERTenantSettingsResult -Result $out
    return $out
}

function Invoke-DERTenantSettingsModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $planned = @($BuildPlan.Objects | Where-Object { $_.Enabled -and $_.Module -eq 'TenantSettings' })
    $results = New-Object System.Collections.Generic.List[object]
    if (-not $planned.Count) { return Complete-DERTenantSettingsResult -Results $results -RunId $RunId }

    foreach ($p in $planned) {
        $actionId = if (Test-DERTenantSettingsCommand 'New-DERActionId') { New-DERActionId -Component 'TENANT' } else { "TENANT-$($p.DerId)" }
        try {
            switch ([string]$p.DerId) {
                'DER-TENANT-010' { $result = Invoke-DERTenantCleanupAction -BuildPlan $BuildPlan -Planned $p -RunId $RunId -ActionId $actionId }
                'DER-TENANT-020' { $result = Invoke-DERTenantSupportAction -BuildPlan $BuildPlan -Planned $p -RunId $RunId -ActionId $actionId }
                default { $result = [pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Unknown TenantSettings action; no tenant change performed.';ActionId=$actionId} }
            }
            $results.Add($result)
        } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'TenantSettings' -ActionId $actionId -DerId $p.DerId}

            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }

    return Complete-DERTenantSettingsResult -Results $results -RunId $RunId
}

Export-ModuleMember -Function @('New-DERDeviceCleanupRuleBody','Get-DERDesiredSupportFields','Invoke-DERTenantSettingsModule')
