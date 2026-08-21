<#
.SYNOPSIS
    DER generic Windows Settings Catalog workload.
.DESCRIPTION
    Creates Pilot-only policies for Credential Guard/VBS, device inactivity
    lock, and Windows Hello for Business using runtime setting-definition discovery.
#>

# Maintenance notes
# Responsibility: Creates approved configuration profiles and validates tracked Microsoft state rather than trusting create responses.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

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

function Test-DERConfigurationCommand{param([Parameter(Mandatory)][string]$Name)return[bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Save-DERConfigurationResult{param($Result)$ctx=if(Test-DERConfigurationCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath(Join-Path $d 'Configuration.json') -Encoding UTF8}}
function Get-DERConfigurationStateObject{param([string]$DerId)if(Test-DERConfigurationCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return$null}
function ConvertTo-DERConfigurationSearchText{param($Object)$p=@();foreach($n in@('id','name','displayName','description','helpText','offsetUri','baseUri')){if($Object-and$Object.PSObject.Properties.Name-contains$n-and$null-ne$Object.$n){$p+=[string]$Object.$n}};return(($p-join' ')-replace'[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()}
function Test-DERConfigurationAlias{param([string]$Text,[string[]]$Aliases)foreach($a in@($Aliases)){$n=(($a-replace'[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant());if($n-and$Text.Contains($n)){return$true}};return$false}
function Get-DERConfigurationDefinitions{param([string]$ActionId)$all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationSettings' -ApiVersion beta -Component Configuration -ActionId $ActionId;return@($all|Where-Object{(-not$_.PSObject.Properties['settingUsage']-or[string]$_.settingUsage-eq'configuration')-and(-not$_.PSObject.Properties['visibility']-or[string]$_.visibility-in@('settingsCatalog','unknownFutureValue'))})}
function Find-DERConfigurationDefinition{param($Definitions,[string[]]$Aliases)$m=@($Definitions|Where-Object{$text=ConvertTo-DERConfigurationSearchText$_;if(-not(Test-DERConfigurationAlias $text $Aliases)){return$false};if($_.PSObject.Properties.Name-contains'rootDefinitionId'-and-not[string]::IsNullOrWhiteSpace([string]$_.rootDefinitionId)){return$false};return$true});if(-not$m.Count){return$null};return@($m|Sort-Object@{Expression={([string]$_.displayName).Length}},@{Expression={[string]$_.id}})[0]}
function Find-DERConfigurationChoice{param($Definition,[string[]]$Aliases)$m=@($Definition.options|Where-Object{Test-DERConfigurationAlias(ConvertTo-DERConfigurationSearchText$_)$Aliases});if(-not$m.Count){return$null};return@($m|Sort-Object@{Expression={([string]$_.displayName).Length}})[0]}
function New-DERConfigurationSetting{param($Definition,[string[]]$ChoiceAliases,$SimpleValue)$type=[string]$Definition.'@odata.type';if($type-match'ChoiceSettingDefinition'){$o=Find-DERConfigurationChoice $Definition $ChoiceAliases;if(-not$o){return$null};$v=if($o.itemId){[string]$o.itemId}elseif($o.name){[string]$o.name}else{return$null};return[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance';settingDefinitionId=[string]$Definition.id;choiceSettingValue=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingValue';value=$v;children=@()}}}};if($type-match'SimpleSettingDefinition'){$vt=if([string]$Definition.valueDefinition.'@odata.type'-match'Integer'){'Integer'}elseif([string]$Definition.valueDefinition.'@odata.type'-match'Boolean'){'Boolean'}else{'String'};$val=switch($vt){'Integer'{[int]$SimpleValue};'Boolean'{[bool]$SimpleValue};default{[string]$SimpleValue}};return[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance';settingDefinitionId=[string]$Definition.id;simpleSettingValue=[ordered]@{'@odata.type'=("#microsoft.graph.deviceManagementConfiguration{0}SettingValue"-f$vt);value=$val}}}};return$null}
function Resolve-DERConfigurationPolicySettings{param([string]$DerId,$Definitions,$BuildPlan)$specs=switch($DerId){'DER-SEC-020'{@(@{N='VBS';A=@('turn on virtualization based security','virtualization based security');C=@('enable','enabled');V=$true},@{N='Credential Guard';A=@('credential guard configuration','credential guard');C=@('enabled with uefi lock','enable','enabled');V=$true})};'DER-CFG-010'{@(@{N='Inactivity timeout';A=@('maximum inactivity time device lock','max inactivity time device lock','device lock inactivity');C=$null;V=([int]$BuildPlan.Answers.Security.DeviceLockMinutes*60)})};'DER-CFG-030'{@(@{N='Windows Hello for Business';A=@('use windows hello for business','windows hello for business');C=@('enable','enabled');V=$true},@{N='Biometrics';A=@('use biometrics','biometrics');C=@('enable','enabled','allow');V=$true})};default{@()}};$settings=New-Object System.Collections.Generic.List[object];$missing=New-Object System.Collections.Generic.List[string];foreach($s in$specs){$d=Find-DERConfigurationDefinition -Definitions $Definitions -Aliases $s.A;if(-not$d){$missing.Add($s.N);continue};$setting=New-DERConfigurationSetting -Definition $d -ChoiceAliases $s.C -SimpleValue $s.V;if(-not$setting){$missing.Add($s.N);continue};$settings.Add($setting)};return[pscustomobject]@{Success=($missing.Count-eq0);Settings=@($settings);Missing=@($missing)}}
function New-DERConfigurationAssignmentBody{param([string]$GroupId)return[ordered]@{assignments=@([ordered]@{target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})}}
function Invoke-DERConfigurationModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'Configuration'})
    if(-not $planned.Count){return Complete-DERConfigurationResult $results $RunId}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){
        foreach($p in $planned){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message='Settings Catalog creation requires DER-approved Preview APIs.'})}
        return Complete-DERConfigurationResult $results $RunId
    }
    $pilot=Get-DERConfigurationStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){$results.Add([pscustomobject]@{DerId='DER-CFG';DisplayName='Configuration';Status='Failed';Message='DER Pilot device group is missing.'});return Complete-DERConfigurationResult $results $RunId -Critical}
    try{Assert-DERManagedStateObject -StateRecord $pilot -Component 'Configuration' -ActionId 'CFG-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned')|Out-Null}
    catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Configuration' -ActionId 'CFG-PILOT-PREFLIGHT' -DerId 'DER-GRP-D-010'}
$results.Add([pscustomobject]@{DerId='DER-CFG';DisplayName='Configuration';Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message)});return Complete-DERConfigurationResult $results $RunId -Critical}

    $defs=Get-DERConfigurationDefinitions -ActionId 'CFG-DEFS'
    foreach($p in $planned){
        $aid=if(Test-DERConfigurationCommand 'New-DERActionId'){New-DERActionId -Component 'CFG'}else{"CFG-$($p.DerId)"}
        try{
            $state=Get-DERConfigurationStateObject -DerId $p.DerId
            if($state){
                Assert-DERManagedStateObject -StateRecord $state -Component 'Configuration' -ActionId $aid -AllowedOwnershipClass @('DER-Owned') -MarkValidated|Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned policy exists and matches recorded settings/assignment state.';ActionId=$aid})
                continue
            }
            $existing=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'Configuration' -ActionId $aid
            $collision=@($existing|Where-Object{[string]$_.name -eq [string]$p.DisplayName})
            if($collision.Count){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned policy exists; adoption required.';ActionId=$aid});continue}
            $resolved=Resolve-DERConfigurationPolicySettings -DerId $p.DerId -Definitions $defs -BuildPlan $BuildPlan
            if(-not $resolved.Success){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=("Required Settings Catalog controls could not be resolved: {0}" -f ($resolved.Missing-join', '));ActionId=$aid});continue}
            $body=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationPolicy';name=$p.DisplayName;description='Windows configuration policy. Pilot devices only.';platforms='windows10';technologies='mdm';roleScopeTagIds=@('0');settings=@($resolved.Settings)}
            $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $body -Component 'Configuration' -DerId $p.DerId -ActionId $aid
            if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'Create response did not contain object ID.')}
            $id=[string]$created.id
            $meta=[pscustomobject]@{Module='Configuration';ApiVersion='beta';ValidationUri=("deviceManagement/configurationPolicies/{0}" -f $id);DeleteUri=("deviceManagement/configurationPolicies/{0}" -f $id);ExpectedSubset=[pscustomobject]@{name=$p.DisplayName};SettingsUri=("deviceManagement/configurationPolicies/{0}/settings" -f $id);MinimumSettingsCount=@($resolved.Settings).Count;AssignmentUri=("deviceManagement/configurationPolicies/{0}/assignments" -f $id);ExpectedAssignmentTargetId=[string]$pilot.ObjectId}
            Add-DERStateObject -DerId $p.DerId -ObjectId $id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null
            Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/configurationPolicies/{0}/assign" -f $id) -ApiVersion beta -Body (New-DERConfigurationAssignmentBody $pilot.ObjectId) -Component 'Configuration' -DerId $p.DerId -ActionId $aid|Out-Null
            Assert-DERManagedStateObject -StateRecord (Get-DERConfigurationStateObject -DerId $p.DerId) -Component 'Configuration' -ActionId $aid -AllowedOwnershipClass @('DER-Owned') -MarkValidated|Out-Null
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$id;Status='Created';Message='Settings Catalog policy created, Pilot-assigned, and read-back validated.';ActionId=$aid})
        }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'Configuration' -ActionId $aid -DerId $p.DerId}

            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$aid})
        }
    }
    return Complete-DERConfigurationResult $results $RunId
}
function Complete-DERConfigurationResult{param($Results,[string]$RunId,[switch]$Critical)$s=[pscustomobject]@{Created=@($Results|Where-Object{$_.Status-eq'Created'}).Count;Existing=@($Results|Where-Object{$_.Status-eq'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status-eq'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status-eq'Failed'}).Count};$o=[pscustomobject]@{Module='Configuration';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=[bool]$Critical;Summary=$s;Results=@($Results)};Save-DERConfigurationResult$o;return$o}
Export-ModuleMember -Function @('Invoke-DERConfigurationModule')
