<#
.SYNOPSIS
    DER Windows Update workload.

.DESCRIPTION
    Creates Pilot and Production Windows Update rings using the Microsoft Graph
    v1.0 windowsUpdateForBusinessConfiguration resource and, when DER Preview
    APIs are allowed, creates matching Windows Feature Update policies.

    Production targets are intentionally empty DER Production groups. DER does
    not auto-promote devices into Production.
#>


# Maintenance notes
# Responsibility: Manages approved Windows update rings/feature update policies and validates targeting/read-back.
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


function Test-DERUpdatesCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERUpdatesLog {
    param([string]$Level,[string]$Message,$Data,[string]$ActionId)
    if (Test-DERUpdatesCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Updates' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function Save-DERUpdatesResult {
    param($Result)
    $ctx = if (Test-DERUpdatesCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $dir 'Updates.json') -Encoding UTF8
    }
}

function Get-DERUpdatesStateObject {
    param([string]$DerId)
    if (Test-DERUpdatesCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}

function Get-DERUpdatesTargetGroup {
    param([string]$DerId)
    switch ($DerId) {
        'DER-WU-010' { return Get-DERUpdatesStateObject 'DER-GRP-D-010' }
        'DER-FU-010' { return Get-DERUpdatesStateObject 'DER-GRP-D-010' }
        'DER-WU-020' { return Get-DERUpdatesStateObject 'DER-GRP-D-020' }
        'DER-FU-020' { return Get-DERUpdatesStateObject 'DER-GRP-D-020' }
        default      { return $null }
    }
}

function New-DERDeviceConfigurationAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        assignments = @(
            [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceConfigurationAssignment'
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $GroupId
                }
            }
        )
    }
}

function New-DERFeatureUpdateAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        assignments = @(
            [ordered]@{
                '@odata.type' = '#microsoft.graph.windowsFeatureUpdateProfileAssignment'
                target = [ordered]@{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId = $GroupId
                }
            }
        )
    }
}

function New-DERUpdateRingBody {
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)]$Planned
    )

    $isPilot = ([string]$Planned.DerId -eq 'DER-WU-010')
    $qualityDeferral = if ($isPilot) { [int]$BuildPlan.Answers.Updates.PilotUpdateDeferralDays } else { [int]$BuildPlan.Answers.Updates.ProductionUpdateDeferralDays }

    return [ordered]@{
        '@odata.type' = '#microsoft.graph.windowsUpdateForBusinessConfiguration'
        displayName = $Planned.DisplayName
        description = if ($isPilot) { 'Windows Update Pilot ring.' } else { 'Windows Update Production ring. Production group is intentionally empty until engineer promotion.' }
        automaticUpdateMode = 'autoInstallAtMaintenanceTime'
        microsoftUpdateServiceAllowed = $true
        driversExcluded = [bool]$BuildPlan.Answers.Updates.ManageDrivers
        qualityUpdatesDeferralPeriodInDays = $qualityDeferral
        featureUpdatesDeferralPeriodInDays = 0
        qualityUpdatesPaused = $false
        featureUpdatesPaused = $false
        businessReadyUpdatesOnly = 'businessReadyOnly'
        prereleaseFeatures = 'notAllowed'
        featureUpdatesRollbackWindowInDays = 10
        deadlineForFeatureUpdatesInDays = [int]$BuildPlan.Answers.Updates.FeatureDeadlineDays
        deadlineForQualityUpdatesInDays = [int]$BuildPlan.Answers.Updates.UpdateDeadlineDays
        deadlineGracePeriodInDays = [int]$BuildPlan.Answers.Updates.UpdateGraceDays
        postponeRebootUntilAfterDeadline = $false
        autoRestartNotificationDismissal = 'automatic'
        scheduleRestartWarningInHours = 4
        scheduleImminentRestartWarningInMinutes = 15
        userPauseAccess = 'disabled'
        userWindowsUpdateScanAccess = 'enabled'
        updateNotificationLevel = 'defaultNotifications'
        allowWindows11Upgrade = $true
    }
}

function Get-DERFeatureUpdateTargetVersion {
    param($BuildPlan)
    if ($BuildPlan.Answers.Updates.PSObject.Properties.Name -contains 'TargetFeatureUpdateVersion') {
        $candidate = [string]$BuildPlan.Answers.Updates.TargetFeatureUpdateVersion
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { return $candidate }
    }
    # Baseline fallback. The canonical value is mirrored in Definitions/Baselines/1.0.0/DER-Baseline.json and guarded by tests.
    return 'Windows 11, version 25H2'
}

function New-DERFeatureUpdateBody {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned)
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.windowsFeatureUpdateProfile'
        displayName = $Planned.DisplayName
        description = 'Windows 11 Feature Update policy. Assignment is Pilot or empty Production group only.'
        featureUpdateVersion = (Get-DERFeatureUpdateTargetVersion -BuildPlan $BuildPlan)
        installLatestWindows10OnWindows11IneligibleDevice = $false
        installFeatureUpdatesOptional = $false
        roleScopeTagIds = @('0')
    }
}

function Test-DERUpdateAssignment {
    param([string]$Uri,[string]$ApiVersion,[string]$GroupId,[string]$ActionId)
    $assignments = Invoke-DERGraphCollectionRequest -Uri $Uri -ApiVersion $ApiVersion -Component 'Updates' -ActionId $ActionId
    return [bool](@($assignments | Where-Object { [string]$_.target.groupId -eq $GroupId }).Count -gt 0)
}

function Complete-DERUpdatesResult {
    param($Results,[string]$RunId,[switch]$Critical)
    $summary = [pscustomobject]@{
        Created  = @($Results | Where-Object Status -eq 'Created').Count
        Existing = @($Results | Where-Object Status -eq 'Existing').Count
        Skipped  = @($Results | Where-Object Status -eq 'Skipped').Count
        Failed   = @($Results | Where-Object Status -eq 'Failed').Count
    }
    $out = [pscustomobject]@{
        Module = 'Updates'
        RunId = $RunId
        Status = if ($summary.Failed) { 'CompletedWithFailures' } elseif ($summary.Created -or $summary.Existing) { 'Completed' } else { 'Skipped' }
        CriticalFailure = [bool]$Critical
        Summary = $summary
        Results = @($Results)
    }
    Save-DERUpdatesResult $out
    return $out
}

function Invoke-DERUpdatesModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $planned = @($BuildPlan.Objects | Where-Object { $_.Enabled -and $_.Module -eq 'Updates' })
    $results = New-Object System.Collections.Generic.List[object]
    if (-not $planned.Count) { return Complete-DERUpdatesResult -Results $results -RunId $RunId }

    if ([bool]$BuildPlan.Answers.Updates.PreserveAutopatch) {
        foreach ($p in $planned) {
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Windows Autopatch preservation is enabled; DER will not create overlapping update policies.'})
        }
        return Complete-DERUpdatesResult -Results $results -RunId $RunId
    }

    foreach ($p in $planned) {
        $actionId = if (Test-DERUpdatesCommand 'New-DERActionId') { New-DERActionId -Component 'UPD' } else { "UPD-$($p.DerId)" }
        try {
            $targetGroup = Get-DERUpdatesTargetGroup -DerId $p.DerId
            if (-not $targetGroup) { throw (New-DERWorkloadFailureException -Message "Required DER target group is missing for $($p.DerId).") }
            Assert-DERManagedStateObject -StateRecord $targetGroup -Component 'Updates' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') | Out-Null

            $state = Get-DERUpdatesStateObject -DerId $p.DerId
            $isFeature = ([string]$p.ObjectType -eq 'FeatureUpdatePolicy')
            $apiVersion = if ($isFeature) { 'beta' } else { 'v1.0' }
            $collectionUri = if ($isFeature) { 'deviceManagement/windowsFeatureUpdateProfiles' } else { 'deviceManagement/deviceConfigurations' }

            if ($isFeature -and -not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis) {
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Windows Feature Update profile creation currently uses a DER-approved Graph Preview API and Preview APIs are disabled.';ActionId=$actionId})
                continue
            }

            if ($state) {
                Assert-DERManagedStateObject -StateRecord $state -Component 'Updates' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned update policy exists and matches recorded state.';ActionId=$actionId})
                continue
            }

            $existing = Invoke-DERGraphCollectionRequest -Uri $collectionUri -ApiVersion $apiVersion -Component 'Updates' -ActionId $actionId
            $collision = @($existing | Where-Object { [string]$_.displayName -eq [string]$p.DisplayName })
            if ($collision.Count) {
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned update policy exists; adoption is required before DER can manage it.';ActionId=$actionId})
                continue
            }

            if ($isFeature) {
                $body = New-DERFeatureUpdateBody -BuildPlan $BuildPlan -Planned $p
                $created = Invoke-DERGraphRequest -Method POST -Uri $collectionUri -ApiVersion beta -Body $body -Component 'Updates' -DerId $p.DerId -ActionId $actionId
                if (-not $created.id) { throw (New-DERWorkloadFailureException -Message 'Feature Update create response did not include an object ID.') }
                $validationUri = "deviceManagement/windowsFeatureUpdateProfiles/$($created.id)"
                $deleteUri = $validationUri
                $expected = [pscustomobject]@{displayName=$p.DisplayName;featureUpdateVersion=$body.featureUpdateVersion}
                $meta = [pscustomobject]@{Module='Updates';ApiVersion='beta';ValidationUri=$validationUri;DeleteUri=$deleteUri;ExpectedSubset=$expected;AssignmentUri="$validationUri/assignments";ExpectedAssignmentTargetId=[string]$targetGroup.ObjectId}
                if (Test-DERUpdatesCommand 'Add-DERStateObject') { Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null }
                Invoke-DERGraphRequest -Method POST -Uri "$validationUri/assign" -ApiVersion beta -Body (New-DERFeatureUpdateAssignmentBody -GroupId $targetGroup.ObjectId) -Component 'Updates' -DerId $p.DerId -ActionId $actionId | Out-Null
                $read = Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion beta -Component 'Updates' -DerId $p.DerId -ActionId $actionId
                if ([string]$read.displayName -ne [string]$p.DisplayName -or [string]$read.featureUpdateVersion -ne [string]$body.featureUpdateVersion) { throw (New-DERWorkloadFailureException -Message 'Feature Update policy failed read-back validation.') }
                if (-not (Test-DERUpdateAssignment -Uri "$validationUri/assignments" -ApiVersion beta -GroupId $targetGroup.ObjectId -ActionId $actionId)) { throw (New-DERWorkloadFailureException -Message 'Feature Update assignment failed read-back validation.') }
            } else {
                $body = New-DERUpdateRingBody -BuildPlan $BuildPlan -Planned $p
                $created = Invoke-DERGraphRequest -Method POST -Uri $collectionUri -ApiVersion v1.0 -Body $body -Component 'Updates' -DerId $p.DerId -ActionId $actionId
                if (-not $created.id) { throw (New-DERWorkloadFailureException -Message 'Update ring create response did not include an object ID.') }
                $validationUri = "deviceManagement/deviceConfigurations/$($created.id)"
                $deleteUri = $validationUri
                $expected = [pscustomobject]@{displayName=$p.DisplayName;qualityUpdatesDeferralPeriodInDays=$body.qualityUpdatesDeferralPeriodInDays;featureUpdatesDeferralPeriodInDays=0;deadlineForQualityUpdatesInDays=$body.deadlineForQualityUpdatesInDays;deadlineGracePeriodInDays=$body.deadlineGracePeriodInDays}
                $meta = [pscustomobject]@{Module='Updates';ApiVersion='v1.0';ValidationUri=$validationUri;DeleteUri=$deleteUri;ExpectedSubset=$expected;AssignmentUri="$validationUri/assignments";ExpectedAssignmentTargetId=[string]$targetGroup.ObjectId}
                if (Test-DERUpdatesCommand 'Add-DERStateObject') { Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null }
                Invoke-DERGraphRequest -Method POST -Uri "$validationUri/assign" -ApiVersion v1.0 -Body (New-DERDeviceConfigurationAssignmentBody -GroupId $targetGroup.ObjectId) -Component 'Updates' -DerId $p.DerId -ActionId $actionId | Out-Null
                $read = Invoke-DERGraphRequest -Method GET -Uri $validationUri -ApiVersion v1.0 -Component 'Updates' -DerId $p.DerId -ActionId $actionId
                $cmp = if (Test-DERUpdatesCommand 'Test-DERExpectedSubset') { Test-DERExpectedSubset -Actual $read -Expected $expected } else { [pscustomobject]@{Success=$true} }
                if (-not $cmp.Success) { throw (New-DERWorkloadFailureException -Message 'Update ring failed read-back setting validation.') }
                if (-not (Test-DERUpdateAssignment -Uri "$validationUri/assignments" -ApiVersion v1.0 -GroupId $targetGroup.ObjectId -ActionId $actionId)) { throw (New-DERWorkloadFailureException -Message 'Update ring assignment failed read-back validation.') }
            }

            if (Test-DERUpdatesCommand 'Update-DERStateObject') { Update-DERStateObject -ObjectId $created.id -MarkValidated | Out-Null }
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Update policy created, safely targeted, and validated.';ActionId=$actionId})
        } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Updates' -ActionId $actionId -DerId $p.DerId}

            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }

    $out = Complete-DERUpdatesResult -Results $results -RunId $RunId
    Write-DERUpdatesLog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message ("Updates workload complete: {0} created, {1} existing, {2} skipped, {3} failed." -f $out.Summary.Created,$out.Summary.Existing,$out.Summary.Skipped,$out.Summary.Failed) -Data $out.Summary
    return $out
}

Export-ModuleMember -Function @('New-DERUpdateRingBody','New-DERFeatureUpdateBody','Invoke-DERUpdatesModule')
