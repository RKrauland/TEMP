<#
.SYNOPSIS
    DER Microsoft Defender Antivirus endpoint-security workload.
.DESCRIPTION
    Creates the DER Defender Antivirus baseline by resolving the current active
    Endpoint Security template and required settings at runtime. The module is
    Pilot-only and skips before writing if required Microsoft schema cannot be
    resolved safely.
#>

# Maintenance notes
# Responsibility: Builds the approved Defender Endpoint Security policy from live template definitions and validates Pilot assignment.
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


function Test-DERDefenderCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Save-DERDefenderResult {
    param($Result)
    $ctx = if (Test-DERDefenderCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $dir 'Defender.json') -Encoding UTF8
    }
}

function Get-DERDefenderStateObject {
    param([string]$DerId)
    if (Test-DERDefenderCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}

function ConvertTo-DERDefenderSearchText {
    param($Object)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('id','name','displayName','description','helpText','offsetUri','baseUri')) {
        if ($Object -and $Object.PSObject.Properties.Name -contains $name -and $null -ne $Object.$name) {
            $parts.Add([string]$Object.$name)
        }
    }
    return (($parts -join ' ') -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()
}

function Test-DERDefenderAlias {
    param([string]$Text,[string[]]$Aliases)
    foreach ($alias in @($Aliases)) {
        $needle = (($alias -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant())
        if ($needle -and $Text.Contains($needle)) { return $true }
    }
    return $false
}

function Get-DERDefenderExactPolicy {
    param([string]$Name,[string]$ActionId)
    $all = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'Defender' -ActionId $ActionId
    return @($all | Where-Object { [string]$_.name -eq $Name })
}

function Get-DERDefenderTemplate {
    param([Parameter(Mandatory)][string]$Family,[string[]]$NameAliases,[string]$ActionId)
    $templates = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicyTemplates' -ApiVersion beta -Component 'Defender' -ActionId $ActionId
    $candidates = @($templates | Where-Object {
        ([string]$_.templateFamily -eq $Family) -and
        ((-not $_.PSObject.Properties['platforms']) -or ([string]$_.platforms -match 'windows')) -and
        ((-not $_.PSObject.Properties['lifecycleState']) -or ([string]$_.lifecycleState -in @('active','unknownFutureValue')) -or [string]::IsNullOrWhiteSpace([string]$_.lifecycleState))
    })
    if ($NameAliases -and $candidates.Count) {
        $named = @($candidates | Where-Object { Test-DERDefenderAlias -Text (ConvertTo-DERDefenderSearchText $_) -Aliases $NameAliases })
        if ($named.Count) { $candidates = $named }
    }
    if (-not $candidates.Count) { return $null }
    return @($candidates | Sort-Object @{Expression={try{[version]([string]$_.displayVersion)}catch{[version]'0.0'}};Descending=$true},@{Expression={[string]$_.id};Descending=$true})[0]
}

function Get-DERDefenderCatalog {
    param([string]$TemplateId,[string]$ActionId)
    $settingTemplates = Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates" -f $TemplateId) -ApiVersion beta -Component 'Defender' -ActionId $ActionId
    $catalog = New-Object System.Collections.Generic.List[object]
    foreach ($settingTemplate in @($settingTemplates)) {
        try {
            $definitions = Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates/{1}/settingDefinitions" -f $TemplateId,$settingTemplate.id) -ApiVersion beta -Component 'Defender' -ActionId $ActionId
            foreach ($definition in @($definitions)) {
                $catalog.Add([pscustomobject]@{SettingTemplate=$settingTemplate;Definition=$definition;SearchText=(ConvertTo-DERDefenderSearchText $definition)})
            }
        } catch {
            throw (New-DERWorkloadFailureException -Message "DER cannot safely build the Defender settings catalog because template entry '$($settingTemplate.id)' could not be enumerated: $($_.Exception.Message)" -InnerException $_.Exception)
        }
    }
    return @($catalog)
}

function Find-DERDefenderDefinition {
    param($Catalog,[string[]]$Aliases,[string[]]$ExcludeAliases=@())
    $definitionMatches = @($Catalog | Where-Object {
        if (-not (Test-DERDefenderAlias -Text ([string]$_.SearchText) -Aliases $Aliases)) { return $false }
        foreach ($exclude in @($ExcludeAliases)) {
            if (Test-DERDefenderAlias -Text ([string]$_.SearchText) -Aliases @($exclude)) { return $false }
        }
        if ($_.Definition.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId)) { return $false }
        return $true
    })
    if (-not $definitionMatches.Count) { return $null }
    return @($definitionMatches | Sort-Object @{Expression={([string]$_.Definition.displayName).Length}},@{Expression={[string]$_.Definition.id}})[0]
}

function Find-DERDefenderChoice {
    param($Definition,[string[]]$Aliases)
    $definitionMatches = @($Definition.options | Where-Object { Test-DERDefenderAlias -Text (ConvertTo-DERDefenderSearchText $_) -Aliases $Aliases })
    if (-not $definitionMatches.Count) { return $null }
    return @($definitionMatches | Sort-Object @{Expression={([string]$_.displayName).Length}})[0]
}

function New-DERDefenderSetting {
    param($CatalogItem,[string[]]$ChoiceAliases,$SimpleValue)
    $definition = $CatalogItem.Definition
    $settingTemplate = $CatalogItem.SettingTemplate
    $definitionType = [string]$definition.'@odata.type'
    $instanceTemplateId = [string]$settingTemplate.settingInstanceTemplate.settingInstanceTemplateId

    if ($definitionType -match 'ChoiceSettingDefinition') {
        $option = Find-DERDefenderChoice -Definition $definition -Aliases $ChoiceAliases
        if (-not $option) { return $null }
        $value = if ($option.itemId) { [string]$option.itemId } elseif ($option.name) { [string]$option.name } else { return $null }
        $choice = [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingValue';children=@();value=$value}
        if ($option.optionValue -and $option.optionValue.settingValueTemplateReference) {
            $choice.settingValueTemplateReference = [ordered]@{settingValueTemplateId=[string]$option.optionValue.settingValueTemplateReference.settingValueTemplateId}
        }
        $instance = [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance';settingDefinitionId=[string]$definition.id;choiceSettingValue=$choice}
        if ($instanceTemplateId) { $instance.settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$instanceTemplateId} }
        return [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=$instance}
    }

    if ($definitionType -match 'SimpleSettingDefinition') {
        if ($null -eq $SimpleValue) { return $null }
        $valueTypeText = if ($definition.valueDefinition) { [string]$definition.valueDefinition.'@odata.type' } else { '' }
        $valueType = if ($valueTypeText -match 'Integer') {'Integer'} elseif ($valueTypeText -match 'Boolean') {'Boolean'} else {'String'}
        $typedValue = switch ($valueType) { 'Integer' {[int]$SimpleValue}; 'Boolean' {[bool]$SimpleValue}; default {[string]$SimpleValue} }
        $simple = [ordered]@{'@odata.type'=("#microsoft.graph.deviceManagementConfiguration{0}SettingValue" -f $valueType);value=$typedValue}
        if ($settingTemplate.settingInstanceTemplate.simpleSettingValueTemplate) {
            $simple.settingValueTemplateReference=[ordered]@{settingValueTemplateId=[string]$settingTemplate.settingInstanceTemplate.simpleSettingValueTemplate.settingValueTemplateId}
        }
        $instance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance';settingDefinitionId=[string]$definition.id;simpleSettingValue=$simple}
        if ($instanceTemplateId) { $instance.settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$instanceTemplateId} }
        return [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=$instance}
    }
    return $null
}

function New-DERDefenderAssignmentBody {
    param([string]$GroupId)
    return [ordered]@{assignments=@([ordered]@{target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}
}

function Resolve-DERDefenderSettings {
    param($Catalog,$BuildPlan)
    $specs = @(
        @{Name='Real-time protection';Aliases=@('real time protection','real time monitoring');Choices=@('enable','enabled','on')},
        @{Name='Behavior monitoring';Aliases=@('behavior monitoring','behaviour monitoring');Choices=@('enable','enabled','on')},
        @{Name='Cloud-delivered protection';Aliases=@('cloud delivered protection','cloud protection');Choices=@('enable','enabled','on')},
        @{Name='PUA protection';Aliases=@('potentially unwanted application','pua protection');Choices=@('block')},
        @{Name='Script scanning';Aliases=@('script scanning','scan scripts');Choices=@('enable','enabled','on')},
        @{Name='Archive scanning';Aliases=@('archive scanning','scan archive files');Choices=@('enable','enabled','on')},
        @{Name='Removable-drive scanning';Aliases=@('removable drive scanning','scan removable drives');Choices=@('enable','enabled','on')}
    )
    if ([bool]$BuildPlan.Answers.Security.CreateTamperProtection) {
        $specs += @{Name='Tamper Protection';Aliases=@('tamper protection');Choices=@('enable','enabled','on')}
    }
    $settings=New-Object System.Collections.Generic.List[object]
    $resolved=New-Object System.Collections.Generic.List[object]
    $missing=New-Object System.Collections.Generic.List[string]
    foreach ($spec in $specs) {
        $item=Find-DERDefenderDefinition -Catalog $Catalog -Aliases $spec.Aliases
        if (-not $item) {$missing.Add($spec.Name);continue}
        $setting=New-DERDefenderSetting -CatalogItem $item -ChoiceAliases $spec.Choices
        if (-not $setting) {$missing.Add($spec.Name);continue}
        $settings.Add($setting);$resolved.Add([pscustomobject]@{Intent=$spec.Name;DefinitionId=$item.Definition.id;DisplayName=$item.Definition.displayName})
    }
    return [pscustomobject]@{Success=($missing.Count -eq 0);Settings=@($settings);Resolved=@($resolved);Missing=@($missing)}
}

function Invoke-DERDefenderModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'Defender'}|Select-Object -First 1)
    if (-not $planned) {return Complete-DERDefenderResult $results $RunId}
    $p=$planned[0];$actionId=if(Test-DERDefenderCommand 'New-DERActionId'){New-DERActionId -Component 'DEF'}else{'DEF-001'}
    if ([string]$BuildPlan.Answers.Security.PrimaryAV -notin @('Microsoft Defender','Unknown')) {$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Third-party or mixed AV selected; DER will not create a competing Defender AV baseline.';ActionId=$actionId});return Complete-DERDefenderResult $results $RunId}
    if (-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis) {$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Defender Endpoint Security creation requires a DER-approved Graph Preview API; Preview APIs are disabled.';ActionId=$actionId});return Complete-DERDefenderResult $results $RunId}
    $pilot=Get-DERDefenderStateObject -DerId 'DER-GRP-D-010';if(-not$pilot){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';Message='DER Pilot device group is missing.';ActionId=$actionId});return Complete-DERDefenderResult $results $RunId -Critical}
    try { Assert-DERManagedStateObject -StateRecord $pilot -Component 'Defender' -ActionId 'DEF-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Defender' -ActionId $actionId -DerId $p.DerId}
 $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message);ActionId=$actionId});return Complete-DERDefenderResult $results $RunId -Critical }
    try {
        $state=Get-DERDefenderStateObject -DerId $p.DerId
        if ($state) {Assert-DERManagedStateObject -StateRecord $state -Component 'Defender' -ActionId $actionId -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned Defender policy exists and matches recorded state.';ActionId=$actionId});return Complete-DERDefenderResult $results $RunId}
        $collision=@(Get-DERDefenderExactPolicy -Name $p.DisplayName -ActionId $actionId);if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned policy exists; adoption is required before DER can manage it.';ActionId=$actionId});return Complete-DERDefenderResult $results $RunId}
        $template=Get-DERDefenderTemplate -Family 'endpointSecurityAntivirus' -NameAliases @('microsoft defender antivirus','defender antivirus') -ActionId $actionId
        if(-not$template){throw (New-DERWorkloadFailureException -Message 'Active Windows Defender Antivirus Endpoint Security template could not be resolved.')}
        $catalog=Get-DERDefenderCatalog -TemplateId $template.id -ActionId $actionId;$resolved=Resolve-DERDefenderSettings -Catalog $catalog -BuildPlan $BuildPlan
        if(-not$resolved.Success){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=("Required Defender settings could not be resolved: {0}" -f ($resolved.Missing -join ', '));ActionId=$actionId});return Complete-DERDefenderResult $results $RunId}
        $body=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationPolicy';name=$p.DisplayName;description='Microsoft Defender Antivirus baseline. Pilot only.';platforms='windows10';technologies='mdm';roleScopeTagIds=@('0');settings=@($resolved.Settings);templateReference=[ordered]@{templateId=[string]$template.id}}
        $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $body -Component Defender -DerId $p.DerId -ActionId $actionId;if(-not$created.id){throw (New-DERWorkloadFailureException -Message 'Create response did not contain an object ID.')}
        $meta=[pscustomobject]@{Module='Defender';ApiVersion='beta';ValidationUri=("deviceManagement/configurationPolicies/{0}" -f $created.id);DeleteUri=("deviceManagement/configurationPolicies/{0}" -f $created.id);ExpectedSubset=[pscustomobject]@{name=$p.DisplayName};SettingsUri=("deviceManagement/configurationPolicies/{0}/settings" -f $created.id);MinimumSettingsCount=@($resolved.Settings).Count;AssignmentUri=("deviceManagement/configurationPolicies/{0}/assignments" -f $created.id);ExpectedAssignmentTargetId=[string]$pilot.ObjectId;TemplateId=$template.id;ResolvedSettings=$resolved.Resolved}
        Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null
        Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/configurationPolicies/{0}/assign" -f $created.id) -ApiVersion beta -Body (New-DERDefenderAssignmentBody $pilot.ObjectId) -Component Defender -DerId $p.DerId -ActionId $actionId|Out-Null
        Assert-DERManagedStateObject -StateRecord (Get-DERDefenderStateObject -DerId $p.DerId) -Component 'Defender' -ActionId $actionId -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Defender baseline created, Pilot-assigned, and validated.';ActionId=$actionId})
    } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Defender' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})}
    return Complete-DERDefenderResult $results $RunId
}
function Complete-DERDefenderResult {param($Results,[string]$RunId,[switch]$Critical)$s=[pscustomobject]@{Created=@($Results|Where-Object{$_.Status-eq'Created'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject]@{Module='Defender';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=[bool]$Critical;Summary=$s;Results=@($Results)};Save-DERDefenderResult $o;return$o}
Export-ModuleMember -Function @('Invoke-DERDefenderModule')
