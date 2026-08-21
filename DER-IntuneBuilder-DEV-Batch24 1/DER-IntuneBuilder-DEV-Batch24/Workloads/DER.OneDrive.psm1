<#
.SYNOPSIS
    DER OneDrive for Business workload.

.DESCRIPTION
    Creates one Pilot-only Windows Settings Catalog policy for OneDrive.
    The baseline can configure silent account sign-in, Known Folder Move for
    Desktop/Documents/Pictures, Files On-Demand, and OneDrive sync-health
    reporting. No SharePoint libraries are automatically synchronized.

    Microsoft currently exposes Settings Catalog create/assign through Graph
    beta, so this workload obeys DER's Safe Preview gate.
#>


# Maintenance notes
# Responsibility: Manages approved OneDrive/KFM Settings Catalog configuration and validates Pilot targeting.
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


function Test-DEROneDriveCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DEROneDriveLog {
    param([string]$Level,[string]$Message,$Data,[string]$ActionId)
    if (Test-DEROneDriveCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'OneDrive' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function Save-DEROneDriveResult {
    param($Result)
    $ctx = if (Test-DEROneDriveCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $dir 'OneDrive.json') -Encoding UTF8
    }
}

function Get-DEROneDriveStateObject {
    param([Parameter(Mandatory)][string]$DerId)
    if (Test-DEROneDriveCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}

function New-DEROneDriveChoiceSetting {
    param(
        [Parameter(Mandatory)][string]$SettingDefinitionId,
        [Parameter(Mandatory)][string]$Value,
        [object[]]$Children = @()
    )
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = $SettingDefinitionId
            choiceSettingValue = [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value = $Value
                children = @($Children)
            }
        }
    }
}

function New-DEROneDriveChildChoice {
    param([Parameter(Mandatory)][string]$SettingDefinitionId,[Parameter(Mandatory)][string]$Value)
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
        settingDefinitionId = $SettingDefinitionId
        choiceSettingValue = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
            value = $Value
            children = @()
        }
    }
}

function New-DEROneDriveChildString {
    param([Parameter(Mandatory)][string]$SettingDefinitionId,[Parameter(Mandatory)][string]$Value)
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
        settingDefinitionId = $SettingDefinitionId
        simpleSettingValue = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
            value = $Value
        }
    }
}

function Get-DEROneDriveDefinitions {
    param([string]$ActionId)
    return @(Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationSettings' -ApiVersion beta -Component 'OneDrive' -ActionId $ActionId)
}

function ConvertTo-DEROneDriveSearchText {
    param($Object)
    $parts = @()
    foreach ($name in @('id','name','displayName','description','helpText','offsetUri','baseUri')) {
        if ($Object -and $Object.PSObject.Properties.Name -contains $name -and $null -ne $Object.$name) { $parts += [string]$Object.$name }
    }
    return (($parts -join ' ') -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()
}

function Find-DEROneDriveEnabledChoiceSetting {
    param(
        [Parameter(Mandatory)]$Definitions,
        [Parameter(Mandatory)][string[]]$Aliases
    )
    $definitionMatches = @($Definitions | Where-Object {
        $text = ConvertTo-DEROneDriveSearchText -Object $_
        $found = $false
        foreach ($alias in $Aliases) {
            $needle = (($alias -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant())
            if ($needle -and $text.Contains($needle)) { $found = $true; break }
        }
        if (-not $found) { return $false }
        if ([string]$_.'@odata.type' -notmatch 'ChoiceSettingDefinition') { return $false }
        if ($_.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.rootDefinitionId)) { return $false }
        return $true
    })
    if (-not $definitionMatches.Count) { return $null }

    foreach ($definition in $definitionMatches) {
        foreach ($option in @($definition.options)) {
            $optionText = ConvertTo-DEROneDriveSearchText -Object $option
            if ($optionText -match '(^| )enable(d)?( |$)' -or [string]$option.itemId -match '_1$') {
                $value = if ($option.itemId) { [string]$option.itemId } elseif ($option.name) { [string]$option.name } else { $null }
                if ($value) {
                    return New-DEROneDriveChoiceSetting -SettingDefinitionId ([string]$definition.id) -Value $value
                }
            }
        }
    }
    return $null
}

function New-DEROneDriveKFMSetting {
    param([Parameter(Mandatory)][string]$TenantId)

    # These identifiers are from Microsoft's current published Intune OneDrive
    # Settings Catalog Graph example. Final DER packaging will move them into
    # the versioned compatibility catalog instead of leaving them in code.
    $root = 'device_vendor_msft_policy_config_onedrivengscv2.updates~policy~onedrivengsc_kfmoptinnowizard'
    $children = @(
        (New-DEROneDriveChildChoice -SettingDefinitionId "${root}_kfmoptinnowizard_desktop_checkbox" -Value "${root}_kfmoptinnowizard_desktop_checkbox_1"),
        (New-DEROneDriveChildChoice -SettingDefinitionId "${root}_kfmoptinnowizard_documents_checkbox" -Value "${root}_kfmoptinnowizard_documents_checkbox_1"),
        (New-DEROneDriveChildChoice -SettingDefinitionId "${root}_kfmoptinnowizard_pictures_checkbox" -Value "${root}_kfmoptinnowizard_pictures_checkbox_1"),
        (New-DEROneDriveChildChoice -SettingDefinitionId "${root}_kfmoptinnowizard_dropdown" -Value "${root}_kfmoptinnowizard_dropdown_0"),
        (New-DEROneDriveChildString -SettingDefinitionId "${root}_kfmoptinnowizard_textbox" -Value $TenantId)
    )
    return New-DEROneDriveChoiceSetting -SettingDefinitionId $root -Value "${root}_1" -Children $children
}

function New-DEROneDrivePolicyBody {
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)]$Planned,[Parameter(Mandatory)]$Definitions)

    $settings = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]

    if ([bool]$BuildPlan.Answers.UserData.SilentSignIn) {
        $root = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig'
        $settings.Add((New-DEROneDriveChoiceSetting -SettingDefinitionId $root -Value "${root}_1"))
    }
    if ([bool]$BuildPlan.Answers.UserData.KnownFolderMove) {
        $settings.Add((New-DEROneDriveKFMSetting -TenantId ([string]$BuildPlan.TenantId)))
    }
    if ([bool]$BuildPlan.Answers.UserData.FilesOnDemand) {
        $root = 'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_filesondemandenabled'
        $settings.Add((New-DEROneDriveChoiceSetting -SettingDefinitionId $root -Value "${root}_1"))
    }
    if ([bool]$BuildPlan.Answers.UserData.SyncHealth) {
        $syncHealth = Find-DEROneDriveEnabledChoiceSetting -Definitions $Definitions -Aliases @('enable sync health reporting for onedrive','enable sync admin reports','enablesyncadminreports')
        if ($syncHealth) { $settings.Add($syncHealth) } else { $missing.Add('OneDrive Sync Health reporting') }
    }

    if ($missing.Count) {
        return [pscustomobject]@{ Success=$false; Missing=@($missing); Body=$null }
    }
    if (-not $settings.Count) {
        return [pscustomobject]@{ Success=$false; Missing=@('No OneDrive baseline settings were selected'); Body=$null }
    }

    $body = [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationPolicy'
        name = $Planned.DisplayName
        description = 'Customer OneDrive baseline: silent sign-in, Known Folder Move, Files On-Demand, and sync health as selected. Pilot device group only.'
        platforms = 'windows10'
        technologies = 'mdm'
        roleScopeTagIds = @('0')
        settings = @($settings)
    }
    return [pscustomobject]@{ Success=$true; Missing=@(); Body=$body }
}

function New-DEROneDriveAssignmentBody {
    param([Parameter(Mandatory)][string]$GroupId)
    return [ordered]@{
        assignments = @(
            [ordered]@{ target = [ordered]@{ '@odata.type'='#microsoft.graph.groupAssignmentTarget'; groupId=$GroupId } }
        )
    }
}

function Complete-DEROneDriveResult {
    param($Results,[string]$RunId,[switch]$Critical)
    $summary = [pscustomobject]@{
        Created=@($Results|Where-Object Status -eq 'Created').Count
        Existing=@($Results|Where-Object Status -eq 'Existing').Count
        Skipped=@($Results|Where-Object Status -eq 'Skipped').Count
        Failed=@($Results|Where-Object Status -eq 'Failed').Count
    }
    $out = [pscustomobject]@{
        Module='OneDrive';RunId=$RunId
        Status=if($summary.Failed){'CompletedWithFailures'}elseif($summary.Created-or$summary.Existing){'Completed'}else{'Skipped'}
        CriticalFailure=[bool]$Critical;Summary=$summary;Results=@($Results)
    }
    Save-DEROneDriveResult -Result $out
    return $out
}

function Invoke-DEROneDriveModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $planned = @($BuildPlan.Objects | Where-Object { $_.Enabled -and $_.Module -eq 'OneDrive' })
    $results = New-Object System.Collections.Generic.List[object]
    if (-not $planned.Count) { return Complete-DEROneDriveResult -Results $results -RunId $RunId }

    if (-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis) {
        foreach ($p in $planned) {
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='OneDrive Settings Catalog creation requires a DER-approved Graph Preview API and Preview APIs are disabled.'})
        }
        return Complete-DEROneDriveResult -Results $results -RunId $RunId
    }

    $pilot = Get-DEROneDriveStateObject -DerId 'DER-GRP-D-010'
    if (-not $pilot) {
        $results.Add([pscustomobject]@{DerId='DER-CFG-020';DisplayName='OneDrive';Status='Failed';Message='DER Pilot device group is missing.'})
        return Complete-DEROneDriveResult -Results $results -RunId $RunId -Critical
    }
    try { Assert-DERManagedStateObject -StateRecord $pilot -Component 'OneDrive' -ActionId 'OD-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'OneDrive' -ActionId 'OD-PILOT-PREFLIGHT' -DerId 'DER-GRP-D-010'}
 $results.Add([pscustomobject]@{DerId='DER-CFG-020';DisplayName='OneDrive';Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message)});return Complete-DEROneDriveResult -Results $results -RunId $RunId -Critical }

    $definitions = Get-DEROneDriveDefinitions -ActionId 'OD-DEFS'

    foreach ($p in $planned) {
        $actionId = if (Test-DEROneDriveCommand 'New-DERActionId') { New-DERActionId -Component 'OD' } else { "OD-$($p.DerId)" }
        try {
            $state = Get-DEROneDriveStateObject -DerId $p.DerId
            if ($state) {
                Assert-DERManagedStateObject -StateRecord $state -Component 'OneDrive' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='DER-owned OneDrive policy exists and matches recorded settings/assignment state.';ActionId=$actionId})
                continue
            }

            $existing = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'OneDrive' -ActionId $actionId
            $collision = @($existing | Where-Object { [string]$_.name -eq [string]$p.DisplayName })
            if ($collision.Count) {
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned OneDrive policy exists; explicit DER adoption is required.';ActionId=$actionId})
                continue
            }

            $resolved = New-DEROneDrivePolicyBody -BuildPlan $BuildPlan -Planned $p -Definitions $definitions
            if (-not $resolved.Success) {
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=("Complete OneDrive baseline could not be resolved safely: {0}" -f ($resolved.Missing -join ', '));ActionId=$actionId})
                continue
            }

            $created = Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $resolved.Body -Component 'OneDrive' -DerId $p.DerId -ActionId $actionId
            if (-not $created.id) { throw (New-DERWorkloadFailureException -Message 'OneDrive policy create response did not include an object ID.') }

            $uri = "deviceManagement/configurationPolicies/$($created.id)"
            $expected = [pscustomobject]@{ name=$p.DisplayName; platforms='windows10'; technologies='mdm' }
            $meta = [pscustomobject]@{Module='OneDrive';ApiVersion='beta';ValidationUri=$uri;DeleteUri=$uri;ExpectedSubset=$expected;SettingsUri="$uri/settings";MinimumSettingsCount=@($resolved.Settings).Count;AssignmentUri="$uri/assignments";ExpectedAssignmentTargetId=[string]$pilot.ObjectId}
            Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null

            Invoke-DERGraphRequest -Method POST -Uri "$uri/assign" -ApiVersion beta -Body (New-DEROneDriveAssignmentBody -GroupId $pilot.ObjectId) -Component 'OneDrive' -DerId $p.DerId -ActionId $actionId | Out-Null
            Assert-DERManagedStateObject -StateRecord (Get-DEROneDriveStateObject -DerId $p.DerId) -Component 'OneDrive' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='OneDrive baseline created, assigned to the DER Pilot device group, and validated.';ActionId=$actionId})
        } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'OneDrive' -ActionId $actionId -DerId $p.DerId}

            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }

    return Complete-DEROneDriveResult -Results $results -RunId $RunId
}

Export-ModuleMember -Function @('New-DEROneDrivePolicyBody','Invoke-DEROneDriveModule')
