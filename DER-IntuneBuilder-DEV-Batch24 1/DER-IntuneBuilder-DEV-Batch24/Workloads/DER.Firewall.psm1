<#
.SYNOPSIS
    DER Windows Defender Firewall endpoint-security workload.
#>

# Maintenance notes
# Responsibility: Builds the approved Windows Firewall Endpoint Security policy from live template definitions and validates Pilot assignment.
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


function Test-DERFirewallCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Save-DERFirewallResult {
    param($Result)
    $ctx = if (Test-DERFirewallCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $dir 'Firewall.json') -Encoding UTF8
    }
}

function Get-DERFirewallStateObject {
    param([string]$DerId)
    if (Test-DERFirewallCommand 'Get-DERStateObject') { return Get-DERStateObject -DerId $DerId }
    return $null
}

function ConvertTo-DERFirewallSearchText {
    param($Object)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('id','name','displayName','description','helpText','offsetUri','baseUri')) {
        if ($Object -and $Object.PSObject.Properties.Name -contains $name -and $null -ne $Object.$name) {
            $parts.Add([string]$Object.$name)
        }
    }
    return (($parts -join ' ') -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()
}

function Test-DERFirewallAlias {
    param([string]$Text,[string[]]$Aliases)
    foreach ($alias in @($Aliases)) {
        $needle = (($alias -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant())
        if ($needle -and $Text.Contains($needle)) { return $true }
    }
    return $false
}

function Get-DERFirewallExactPolicy {
    param([string]$Name,[string]$ActionId)
    $all = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'Firewall' -ActionId $ActionId
    return @($all | Where-Object { [string]$_.name -eq $Name })
}

function Get-DERFirewallTemplate {
    param([Parameter(Mandatory)][string]$Family,[string[]]$NameAliases,[string]$ActionId)
    $templates = Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicyTemplates' -ApiVersion beta -Component 'Firewall' -ActionId $ActionId
    $candidates = @($templates | Where-Object {
        ([string]$_.templateFamily -eq $Family) -and
        ((-not $_.PSObject.Properties['platforms']) -or ([string]$_.platforms -match 'windows')) -and
        ((-not $_.PSObject.Properties['lifecycleState']) -or ([string]$_.lifecycleState -in @('active','unknownFutureValue')) -or [string]::IsNullOrWhiteSpace([string]$_.lifecycleState))
    })
    if ($NameAliases -and $candidates.Count) {
        $named = @($candidates | Where-Object { Test-DERFirewallAlias -Text (ConvertTo-DERFirewallSearchText $_) -Aliases $NameAliases })
        if ($named.Count) { $candidates = $named }
    }
    if (-not $candidates.Count) { return $null }
    return @($candidates | Sort-Object @{Expression={try{[version]([string]$_.displayVersion)}catch{[version]'0.0'}};Descending=$true},@{Expression={[string]$_.id};Descending=$true})[0]
}

function Get-DERFirewallCatalog {
    param([string]$TemplateId,[string]$ActionId)
    $settingTemplates = Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates" -f $TemplateId) -ApiVersion beta -Component 'Firewall' -ActionId $ActionId
    $catalog = New-Object System.Collections.Generic.List[object]
    foreach ($settingTemplate in @($settingTemplates)) {
        try {
            $definitions = Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates/{1}/settingDefinitions" -f $TemplateId,$settingTemplate.id) -ApiVersion beta -Component 'Firewall' -ActionId $ActionId
            foreach ($definition in @($definitions)) {
                $catalog.Add([pscustomobject]@{SettingTemplate=$settingTemplate;Definition=$definition;SearchText=(ConvertTo-DERFirewallSearchText $definition)})
            }
        } catch {
            throw (New-DERWorkloadFailureException -Message "DER cannot safely build the Firewall settings catalog because template entry '$($settingTemplate.id)' could not be enumerated: $($_.Exception.Message)" -InnerException $_.Exception)
        }
    }
    return @($catalog)
}

function Find-DERFirewallDefinition {
    param($Catalog,[string[]]$Aliases,[string[]]$ExcludeAliases=@())
    $definitionMatches = @($Catalog | Where-Object {
        if (-not (Test-DERFirewallAlias -Text ([string]$_.SearchText) -Aliases $Aliases)) { return $false }
        foreach ($exclude in @($ExcludeAliases)) {
            if (Test-DERFirewallAlias -Text ([string]$_.SearchText) -Aliases @($exclude)) { return $false }
        }
        if ($_.Definition.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId)) { return $false }
        return $true
    })
    if (-not $definitionMatches.Count) { return $null }
    return @($definitionMatches | Sort-Object @{Expression={([string]$_.Definition.displayName).Length}},@{Expression={[string]$_.Definition.id}})[0]
}

function Find-DERFirewallChoice {
    param($Definition,[string[]]$Aliases)
    $definitionMatches = @($Definition.options | Where-Object { Test-DERFirewallAlias -Text (ConvertTo-DERFirewallSearchText $_) -Aliases $Aliases })
    if (-not $definitionMatches.Count) { return $null }
    return @($definitionMatches | Sort-Object @{Expression={([string]$_.displayName).Length}})[0]
}

function New-DERFirewallSetting {
    param($CatalogItem,[string[]]$ChoiceAliases,$SimpleValue)
    $definition = $CatalogItem.Definition
    $settingTemplate = $CatalogItem.SettingTemplate
    $definitionType = [string]$definition.'@odata.type'
    $instanceTemplateId = [string]$settingTemplate.settingInstanceTemplate.settingInstanceTemplateId

    if ($definitionType -match 'ChoiceSettingDefinition') {
        $option = Find-DERFirewallChoice -Definition $definition -Aliases $ChoiceAliases
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

function New-DERFirewallAssignmentBody {
    param([string]$GroupId)
    return [ordered]@{assignments=@([ordered]@{target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}
}

function Resolve-DERFirewallSettings {param($Catalog,$BuildPlan)
    $specs=@(
        @{Name='Domain profile enabled';Aliases=@('domain profile','enable domain');Choices=@('enable','enabled','on')},
        @{Name='Private profile enabled';Aliases=@('private profile','enable private');Choices=@('enable','enabled','on')},
        @{Name='Public profile enabled';Aliases=@('public profile','enable public');Choices=@('enable','enabled','on')},
        @{Name='Inbound connections';Aliases=@('inbound connections','default inbound action');Choices=@('block')},
        @{Name='Outbound connections';Aliases=@('outbound connections','default outbound action');Choices=@('allow')},
        @{Name='Dropped packet logging';Aliases=@('log dropped packets','dropped packets');Choices=@('enable','enabled','yes')},
        @{Name='Successful connection logging';Aliases=@('log successful connections','successful connections');Choices=@('enable','enabled','yes')}
    )
    if([bool]$BuildPlan.Answers.Security.AllowLocalFirewallRuleMerge){$specs+=@{Name='Local firewall rule merge';Aliases=@('local firewall rules','local policy merge');Choices=@('enable','enabled','allow','yes')}}
    $settings=New-Object System.Collections.Generic.List[object];$missing=New-Object System.Collections.Generic.List[string]
    foreach($spec in$specs){$item=Find-DERFirewallDefinition -Catalog $Catalog -Aliases $spec.Aliases;if(-not$item){$missing.Add($spec.Name);continue};$setting=New-DERFirewallSetting -CatalogItem $item -ChoiceAliases $spec.Choices;if(-not$setting){$missing.Add($spec.Name);continue};$settings.Add($setting)}
    return[pscustomobject]@{Success=($missing.Count-eq0);Settings=@($settings);Missing=@($missing)}
}
function Invoke-DERFirewallModule{[CmdletBinding()]param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object];$planned=@($BuildPlan.Objects|Where-Object{$_.Enabled-and$_.Module-eq'Firewall'}|Select-Object -First 1);if(-not$planned){return Complete-DERFirewallResult $results $RunId};$p=$planned[0];$aid=if(Test-DERFirewallCommand 'New-DERActionId'){New-DERActionId -Component 'FW'}else{'FW-001'}
    if(-not[bool]$BuildPlan.Answers.Safety.AllowPreviewApis){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Firewall Endpoint Security creation requires DER-approved Preview APIs.';ActionId=$aid});return Complete-DERFirewallResult $results $RunId}
    $pilot=Get-DERFirewallStateObject -DerId 'DER-GRP-D-010';if(-not$pilot){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';Message='DER Pilot device group is missing.';ActionId=$aid});return Complete-DERFirewallResult $results $RunId -Critical}
    try { Assert-DERManagedStateObject -StateRecord $pilot -Component 'Firewall' -ActionId 'FW-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned') | Out-Null }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Firewall' -ActionId $aid -DerId $p.DerId}
 $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message);ActionId=$aid});return Complete-DERFirewallResult $results $RunId -Critical }
    try{$state=Get-DERFirewallStateObject -DerId $p.DerId;if($state){Assert-DERManagedStateObject -StateRecord $state -Component 'Firewall' -ActionId $aid -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned policy exists and matches recorded settings/assignment state.';ActionId=$aid});return Complete-DERFirewallResult $results $RunId};$collision=@(Get-DERFirewallExactPolicy -Name $p.DisplayName -ActionId $aid);if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned policy exists; adoption required.';ActionId=$aid});return Complete-DERFirewallResult $results $RunId};$template=Get-DERFirewallTemplate -Family 'endpointSecurityFirewall' -NameAliases @('firewall') -ActionId $aid;if(-not$template){throw (New-DERWorkloadFailureException -Message 'Active Windows Firewall Endpoint Security template could not be resolved.')};$catalog=Get-DERFirewallCatalog -TemplateId $template.id -ActionId $aid;$resolved=Resolve-DERFirewallSettings -Catalog $catalog -BuildPlan $BuildPlan;if(-not$resolved.Success){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=("Required firewall settings could not be resolved: {0}"-f($resolved.Missing-join', '));ActionId=$aid});return Complete-DERFirewallResult $results $RunId};$body=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationPolicy';name=$p.DisplayName;description='Windows Defender Firewall baseline. Pilot only.';platforms='windows10';technologies='mdm';roleScopeTagIds=@('0');settings=@($resolved.Settings);templateReference=[ordered]@{templateId=[string]$template.id}};$created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $body -Component Firewall -DerId $p.DerId -ActionId $aid;if(-not$created.id){throw (New-DERWorkloadFailureException -Message 'Create response did not contain object ID.')};$meta=[pscustomobject]@{Module='Firewall';ApiVersion='beta';ValidationUri=("deviceManagement/configurationPolicies/{0}"-f$created.id);DeleteUri=("deviceManagement/configurationPolicies/{0}"-f$created.id);ExpectedSubset=[pscustomobject]@{name=$p.DisplayName};SettingsUri=("deviceManagement/configurationPolicies/{0}/settings"-f$created.id);MinimumSettingsCount=@($resolved.Settings).Count;AssignmentUri=("deviceManagement/configurationPolicies/{0}/assignments"-f$created.id);ExpectedAssignmentTargetId=[string]$pilot.ObjectId;TemplateId=$template.id};Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null;Invoke-DERGraphRequest -Method POST -Uri("deviceManagement/configurationPolicies/{0}/assign"-f$created.id)-ApiVersion beta -Body(New-DERFirewallAssignmentBody $pilot.ObjectId)-Component Firewall -DerId $p.DerId -ActionId $aid|Out-Null;Assert-DERManagedStateObject -StateRecord (Get-DERFirewallStateObject -DerId $p.DerId) -Component 'Firewall' -ActionId $aid -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Firewall baseline created, Pilot-assigned, and validated.';ActionId=$aid})}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Firewall' -ActionId $aid -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$aid})};return Complete-DERFirewallResult $results $RunId}
function Complete-DERFirewallResult{param($Results,[string]$RunId,[switch]$Critical)$s=[pscustomobject]@{Created=@($Results|Where-Object{$_.Status-eq'Created'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject]@{Module='Firewall';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=[bool]$Critical;Summary=$s;Results=@($Results)};Save-DERFirewallResult$o;return$o}
Export-ModuleMember -Function @('Invoke-DERFirewallModule')
