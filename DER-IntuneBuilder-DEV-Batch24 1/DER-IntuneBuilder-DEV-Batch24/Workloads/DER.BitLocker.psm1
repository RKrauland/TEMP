<#
.SYNOPSIS
    DER BitLocker endpoint-security workload.

.DESCRIPTION
    Creates the DER BitLocker policy using the current Microsoft Intune
    Endpoint Security Disk Encryption template discovered at runtime. DER does
    not hard-code Microsoft template or setting GUIDs. If the current template
    cannot be resolved unambiguously for the required DER settings, the module
    skips before creating anything.

.NOTES
    Required parent entry point: Invoke-DERBitLockerModule
    Microsoft Graph configurationPolicies APIs are currently beta/preview.
#>


# Maintenance notes
# Responsibility: Resolves the active Intune disk-encryption template, builds the approved Settings Catalog payload, assigns to Pilot, and validates settings/assignment.
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


function Test-DERBitLockerCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Write-DERBitLockerLog { param([string]$Level,[string]$Message,$Data,[string]$ActionId) if(Test-DERBitLockerCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'BitLocker' -ActionId $ActionId -Message $Message -Data $Data} }
function Save-DERBitLockerResult { param($Result) $ctx=if(Test-DERBitLockerCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'BitLocker.json') -Encoding UTF8} }
function Get-DERBitLockerStateObject { param([string]$DerId) if(Test-DERBitLockerCommand 'Get-DERStateObject'){return Get-DERStateObject -DerId $DerId};return $null }

function ConvertTo-DERSearchText {
    param($Object)
    $parts=New-Object System.Collections.Generic.List[string]
    foreach($n in @('id','name','displayName','description','helpText','offsetUri','baseUri')){
        if($Object -and $Object.PSObject.Properties.Name -contains $n -and $null -ne $Object.$n){$parts.Add([string]$Object.$n)}
    }
    return (($parts -join ' ') -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant()
}
function Test-DERTextAliases {
    param([string]$Text,[string[]]$Aliases)
    foreach($a in @($Aliases)){
        $norm=(($a -replace '[^A-Za-z0-9]+',' ').Trim().ToLowerInvariant())
        if($norm -and $Text.Contains($norm)){return $true}
    }
    return $false
}
function Get-DERConfigurationPolicyExactName {
    param([string]$Name,[string]$ActionId)
    $all=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Component 'BitLocker' -ActionId $ActionId
    return @($all|Where-Object {[string]$_.name -eq $Name})
}
function Get-DEREndpointSecurityTemplate {
    param([Parameter(Mandatory)][string]$Family,[string]$ActionId)
    $templates=Invoke-DERGraphCollectionRequest -Uri 'deviceManagement/configurationPolicyTemplates' -ApiVersion beta -Component 'BitLocker' -ActionId $ActionId
    $candidates=@($templates|Where-Object {
        ([string]$_.templateFamily -eq $Family) -and
        ((-not $_.PSObject.Properties['lifecycleState']) -or ([string]$_.lifecycleState -in @('active','unknownFutureValue')) -or [string]::IsNullOrWhiteSpace([string]$_.lifecycleState)) -and
        ((-not $_.PSObject.Properties['platforms']) -or ([string]$_.platforms -match 'windows'))
    })
    if($candidates.Count -eq 0){return $null}
    return @($candidates|Sort-Object @{Expression={try{[version]([string]$_.displayVersion)}catch{[version]'0.0'}};Descending=$true},@{Expression={[string]$_.id};Descending=$true})[0]
}
function Get-DERTemplateSettingCatalog {
    param([Parameter(Mandatory)][string]$TemplateId,[string]$ActionId)
    $settingTemplates=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates" -f $TemplateId) -ApiVersion beta -Component 'BitLocker' -ActionId $ActionId
    $catalog=New-Object System.Collections.Generic.List[object]
    foreach($st in @($settingTemplates)){
        try{
            $defs=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicyTemplates/{0}/settingTemplates/{1}/settingDefinitions" -f $TemplateId,$st.id) -ApiVersion beta -Component 'BitLocker' -ActionId $ActionId
            foreach($def in @($defs)){$catalog.Add([pscustomobject]@{SettingTemplate=$st;Definition=$def;SearchText=(ConvertTo-DERSearchText $def)})}
        }catch{throw (New-DERWorkloadFailureException -Message ("DER cannot safely build the BitLocker settings catalog because template entry '{0}' could not be enumerated: {1}" -f $st.id,$_.Exception.Message) -InnerException $_.Exception)}
    }
    return @($catalog)
}
function Find-DERSettingDefinition {
    param([Parameter(Mandatory)]$Catalog,[Parameter(Mandatory)][string[]]$Aliases,[string[]]$ExcludeAliases=@(),[switch]$RootOnly)
    $definitionMatches=@($Catalog|Where-Object {
        $ok=Test-DERTextAliases -Text ([string]$_.SearchText) -Aliases $Aliases
        if(-not $ok){return $false}
        foreach($x in @($ExcludeAliases)){if(Test-DERTextAliases -Text ([string]$_.SearchText) -Aliases @($x)){return $false}}
        if($RootOnly -and $_.Definition.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId)){return $false}
        return $true
    })
    if($definitionMatches.Count -eq 0){return $null}
    # Prefer root definitions and the shortest display name to avoid broad parent/group definitions.
    return @($definitionMatches|Sort-Object @{Expression={if($_.Definition.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.Definition.rootDefinitionId)){1}else{0}}},@{Expression={([string]$_.Definition.displayName).Length}})[0]
}
function Find-DERChoiceOption {
    param([Parameter(Mandatory)]$Definition,[Parameter(Mandatory)][string[]]$Aliases)
    $options=@($Definition.options)
    $definitionMatches=@($options|Where-Object {Test-DERTextAliases -Text (ConvertTo-DERSearchText $_) -Aliases $Aliases})
    if($definitionMatches.Count -eq 0){return $null}
    return @($definitionMatches|Sort-Object @{Expression={([string]$_.displayName).Length}})[0]
}
function Get-DERSettingValueTemplateId {
    param($SettingTemplate,$Option,[switch]$Simple)
    if($Option -and $Option.PSObject.Properties.Name -contains 'optionValue' -and $Option.optionValue -and $Option.optionValue.settingValueTemplateReference){return [string]$Option.optionValue.settingValueTemplateReference.settingValueTemplateId}
    $si=$SettingTemplate.settingInstanceTemplate
    if($Simple -and $si -and $si.PSObject.Properties.Name -contains 'simpleSettingValueTemplate' -and $si.simpleSettingValueTemplate){return [string]$si.simpleSettingValueTemplate.settingValueTemplateId}
    if((-not $Simple) -and $si -and $si.PSObject.Properties.Name -contains 'choiceSettingValueTemplate' -and $si.choiceSettingValueTemplate){return [string]$si.choiceSettingValueTemplate.settingValueTemplateId}
    return $null
}
function New-DERRootSetting {
    param([Parameter(Mandatory)]$CatalogItem,[string[]]$ChoiceAliases,$SimpleValue)
    $def=$CatalogItem.Definition;$st=$CatalogItem.SettingTemplate
    if($def.PSObject.Properties.Name -contains 'rootDefinitionId' -and -not [string]::IsNullOrWhiteSpace([string]$def.rootDefinitionId)){return $null}
    $definitionType=[string]$def.'@odata.type'
    $instanceTemplateId=[string]$st.settingInstanceTemplate.settingInstanceTemplateId
    if($definitionType -match 'ChoiceSettingDefinition'){
        $opt=Find-DERChoiceOption -Definition $def -Aliases $ChoiceAliases
        if(-not $opt){return $null}
        $value=if(-not [string]::IsNullOrWhiteSpace([string]$opt.itemId)){[string]$opt.itemId}elseif(-not [string]::IsNullOrWhiteSpace([string]$opt.name)){[string]$opt.name}else{return $null}
        $valueTemplateId=Get-DERSettingValueTemplateId -SettingTemplate $st -Option $opt
        $valueRef=if($valueTemplateId){[ordered]@{settingValueTemplateId=$valueTemplateId}}else{$null}
        $choice=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingValue';children=@();value=$value}
        if($valueRef){$choice.settingValueTemplateReference=$valueRef}
        return [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance';settingDefinitionId=[string]$def.id;settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$instanceTemplateId};choiceSettingValue=$choice}}
    }
    if($definitionType -match 'SimpleSettingDefinition'){
        if($null -eq $SimpleValue){return $null}
        $valueDefType=if($def.valueDefinition){[string]$def.valueDefinition.'@odata.type'}else{''}
        $valueType=if($valueDefType -match 'Integer'){'Integer'}elseif($valueDefType -match 'Boolean'){'Boolean'}elseif($valueDefType -match 'String'){'String'}elseif($SimpleValue -is [int] -or $SimpleValue -is [long]){'Integer'}elseif($SimpleValue -is [bool]){'Boolean'}else{'String'}
        $typedValue=switch($valueType){'Integer'{[int]$SimpleValue};'Boolean'{[bool]$SimpleValue};default{[string]$SimpleValue}}
        $valueTemplateId=Get-DERSettingValueTemplateId -SettingTemplate $st -Simple
        $sv=[ordered]@{'@odata.type'=("#microsoft.graph.deviceManagementConfiguration{0}SettingValue" -f $valueType);value=$typedValue}
        if($valueTemplateId){$sv.settingValueTemplateReference=[ordered]@{settingValueTemplateId=$valueTemplateId}}
        return [ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSetting';settingInstance=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance';settingDefinitionId=[string]$def.id;settingInstanceTemplateReference=[ordered]@{settingInstanceTemplateId=$instanceTemplateId};simpleSettingValue=$sv}}
    }
    return $null
}
function Resolve-DERBitLockerSettings {
    param([Parameter(Mandatory)]$Catalog,[Parameter(Mandatory)]$BuildPlan)
    $specs=New-Object System.Collections.Generic.List[object]
    $specs.Add([pscustomobject]@{Name='Require device encryption';Required=$true;Aliases=@('require device encryption','requiredeviceencryption');Choice=@('enabled','enable','required','require','yes');Exclude=@()})
    $specs.Add([pscustomobject]@{Name='Allow standard user encryption';Required=$true;Aliases=@('allow standard user encryption','allowstandarduserencryption','allow standard users to enable encryption');Choice=@('enabled','enable','allowed','allow','yes');Exclude=@()})
    $specs.Add([pscustomobject]@{Name='Suppress warning for other disk encryption';Required=$true;Aliases=@('allow warning for other disk encryption','allowwarningforotherdiskencryption');Choice=@('disabled','disable','blocked','block','no');Exclude=@()})
    $specs.Add([pscustomobject]@{Name='Require recovery information backup to Entra';Required=$true;Aliases=@('require device to back up recovery information to microsoft entra','require device to back up recovery information to azure ad','back up recovery information to microsoft entra','backup recovery information to microsoft entra');Choice=@('yes','enabled','enable','required','require');Exclude=@('active directory domain services','ad ds')})
    $specs.Add([pscustomobject]@{Name='OS drive XTS-AES 128';Required=$true;Aliases=@('operating system drive encryption method','operating system drives encryption method','os drive encryption method','encryption method for operating system drives');Choice=@('xts aes 128','aes 128bit xts','128 bit xts');Exclude=@('fixed','removable')})
    if([bool]$BuildPlan.Answers.Security.EncryptFixedDrives){$specs.Add([pscustomobject]@{Name='Fixed drive XTS-AES 128';Required=$true;Aliases=@('fixed data drive encryption method','fixed data drives encryption method','encryption method for fixed data drives');Choice=@('xts aes 128','aes 128bit xts','128 bit xts');Exclude=@('operating system','removable')})}
    $settings=New-Object System.Collections.Generic.List[object];$resolved=New-Object System.Collections.Generic.List[object];$missing=New-Object System.Collections.Generic.List[string]
    foreach($s in $specs){
        $item=Find-DERSettingDefinition -Catalog $Catalog -Aliases $s.Aliases -ExcludeAliases $s.Exclude -RootOnly
        if(-not $item){if($s.Required){$missing.Add($s.Name)};continue}
        $setting=New-DERRootSetting -CatalogItem $item -ChoiceAliases $s.Choice
        if(-not $setting){if($s.Required){$missing.Add($s.Name)};continue}
        $settings.Add($setting);$resolved.Add([pscustomobject]@{Intent=$s.Name;DefinitionId=$item.Definition.id;DisplayName=$item.Definition.displayName})
    }
    return [pscustomobject]@{Success=($missing.Count -eq 0);Settings=@($settings);Resolved=@($resolved);Missing=@($missing)}
}
function New-DERConfigurationPolicyAssignmentBody { param([string]$GroupId) return [ordered]@{assignments=@([ordered]@{target=[ordered]@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$GroupId}})} }
function Test-DERConfigurationPolicyAssignment { param([string]$PolicyId,[string]$GroupId,[string]$ActionId) $a=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicies/{0}/assignments" -f $PolicyId) -ApiVersion beta -Component 'BitLocker' -ActionId $ActionId;return [bool](@($a|Where-Object {[string]$_.target.groupId -eq $GroupId}).Count -gt 0) }

function Invoke-DERBitLockerModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $planned=@($BuildPlan.Objects|Where-Object {$_.Enabled -and $_.Module -eq 'BitLocker'}|Select-Object -First 1)
    if(-not $planned){$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=0};Results=@()};Save-DERBitLockerResult $out;return $out}
    $p=$planned;$results=New-Object System.Collections.Generic.List[object];$actionId=if(Test-DERBitLockerCommand 'New-DERActionId'){New-DERActionId -Component 'BL'}else{'BL-001'}
    if(-not [bool]$BuildPlan.Answers.Safety.AllowPreviewApis){$msg='BitLocker Endpoint Security policy requires a DER-approved Microsoft Graph beta API; Preview APIs are disabled for this run.';$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=$msg;ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=1;Failed=0};Results=@($results)};Save-DERBitLockerResult $out;return $out}
    $pilot=Get-DERBitLockerStateObject -DerId 'DER-GRP-D-010'
    if(-not $pilot){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';Message='DER Pilot device group is missing; BitLocker cannot be safely targeted.';ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@($results)};Save-DERBitLockerResult $out;return $out}
    try{Assert-DERManagedStateObject -StateRecord $pilot -Component 'BitLocker' -ActionId 'BL-PILOT-PREFLIGHT' -AllowedOwnershipClass @('DER-Owned')|Out-Null}catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'BitLocker' -ActionId $actionId -DerId $p.DerId}
$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=('DER Pilot group failed Microsoft state validation: '+$_.Exception.Message);ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='CompletedWithFailures';CriticalFailure=$true;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=0;Failed=1};Results=@($results)};Save-DERBitLockerResult $out;return $out}
    try{
        $state=Get-DERBitLockerStateObject -DerId $p.DerId
        if($state){Assert-DERManagedStateObject -StateRecord $state -Component 'BitLocker' -DerId $p.DerId -ActionId $actionId -MarkValidated | Out-Null;$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='Tracked DER-owned BitLocker policy exists and matches recorded state.';ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='Completed';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=1;Skipped=0;Failed=0};Results=@($results)};Save-DERBitLockerResult $out;return $out}
        $collision=@(Get-DERConfigurationPolicyExactName -Name $p.DisplayName -ActionId $actionId)
        if($collision.Count -gt 0){$msg='Exact-name customer-owned BitLocker/configuration policy exists; DER will not modify it without adoption.';$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message=$msg;ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=1;Failed=0};Results=@($results)};Save-DERBitLockerResult $out;return $out}
        $template=Get-DEREndpointSecurityTemplate -Family 'endpointSecurityDiskEncryption' -ActionId $actionId
        if(-not $template){throw (New-DERWorkloadFailureException -Message 'No active Windows Endpoint Security Disk Encryption template could be resolved from Microsoft Intune.')}
        $catalog=Get-DERTemplateSettingCatalog -TemplateId ([string]$template.id) -ActionId $actionId
        $resolved=Resolve-DERBitLockerSettings -Catalog $catalog -BuildPlan $BuildPlan
        if(-not $resolved.Success){
            $msg=("Current Intune BitLocker template schema could not be safely resolved for: {0}. DER skipped the entire policy before writing anything." -f (@($resolved.Missing)-join '; '))
            if(Test-DERBitLockerCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase SKIP -Module 'BitLocker' -DerId $p.DerId -Message $msg -Data @{templateId=$template.id;missing=$resolved.Missing;resolved=$resolved.Resolved}|Out-Null}
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Skipped';Message=$msg;ActionId=$actionId});$out=[pscustomobject]@{Module='BitLocker';RunId=$RunId;Status='Skipped';CriticalFailure=$false;Summary=[pscustomobject]@{Created=0;Existing=0;Skipped=1;Failed=0};Results=@($results)};Save-DERBitLockerResult $out;return $out
        }
        $body=[ordered]@{'@odata.type'='#microsoft.graph.deviceManagementConfigurationPolicy';name=$p.DisplayName;description='Windows BitLocker endpoint-security policy. Assigned only to the Pilot device group.';platforms='windows10';technologies='mdm';roleScopeTagIds=@('0');settings=@($resolved.Settings);templateReference=[ordered]@{templateId=[string]$template.id}}
        if(Test-DERBitLockerCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'BitLocker' -DerId $p.DerId -Message 'Prepared current-schema BitLocker Endpoint Security policy create.' -Data @{templateId=$template.id;resolved=$resolved.Resolved}|Out-Null}
        $created=Invoke-DERGraphRequest -Method POST -Uri 'deviceManagement/configurationPolicies' -ApiVersion beta -Body $body -Component 'BitLocker' -DerId $p.DerId -ActionId $actionId
        if(-not $created.id){throw (New-DERWorkloadFailureException -Message 'BitLocker policy create response did not include an object ID.')}
        $expected=[pscustomobject][ordered]@{name=$p.DisplayName;platforms='windows10'}
        $meta=[pscustomobject][ordered]@{Module='BitLocker';ApiVersion='beta';ValidationUri=("deviceManagement/configurationPolicies/{0}" -f $created.id);DeleteUri=("deviceManagement/configurationPolicies/{0}" -f $created.id);ExpectedSubset=$expected;SettingsUri=("deviceManagement/configurationPolicies/{0}/settings" -f $created.id);MinimumSettingsCount=@($resolved.Settings).Count;AssignmentUri=("deviceManagement/configurationPolicies/{0}/assignments" -f $created.id);ExpectedAssignmentTargetId=[string]$pilot.ObjectId;TemplateId=$template.id;TemplateFamily=$template.templateFamily;ResolvedSettings=$resolved.Resolved}
        if(Test-DERBitLockerCommand 'Add-DERStateObject'){Add-DERStateObject -DerId $p.DerId -ObjectId ([string]$created.id) -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta|Out-Null}
        Invoke-DERGraphRequest -Method POST -Uri ("deviceManagement/configurationPolicies/{0}/assign" -f $created.id) -ApiVersion beta -Body (New-DERConfigurationPolicyAssignmentBody -GroupId ([string]$pilot.ObjectId)) -Component 'BitLocker' -DerId $p.DerId -ActionId $actionId|Out-Null
        $read=Invoke-DERGraphRequest -Method GET -Uri $meta.ValidationUri -ApiVersion beta -Component 'BitLocker' -DerId $p.DerId -ActionId $actionId
        $cmp=if(Test-DERBitLockerCommand 'Test-DERExpectedSubset'){Test-DERExpectedSubset -Actual $read -Expected $expected}else{[pscustomobject]@{Success=$true}}
        if(-not $cmp.Success){throw (New-DERWorkloadFailureException -Message 'BitLocker policy failed immediate read-back validation.')}
        $settingsRead=Invoke-DERGraphCollectionRequest -Uri ("deviceManagement/configurationPolicies/{0}/settings" -f $created.id) -ApiVersion beta -Component 'BitLocker' -ActionId $actionId
        if(@($settingsRead).Count -lt @($resolved.Settings).Count){throw (New-DERWorkloadFailureException -Message 'BitLocker policy setting count failed read-back validation.')}
        if(-not(Test-DERConfigurationPolicyAssignment -PolicyId ([string]$created.id) -GroupId ([string]$pilot.ObjectId) -ActionId $actionId)){throw (New-DERWorkloadFailureException -Message 'BitLocker Pilot assignment failed read-back validation.')}
        if(Test-DERBitLockerCommand 'Update-DERStateObject'){Update-DERStateObject -ObjectId ([string]$created.id) -MarkValidated|Out-Null}
        if(Test-DERBitLockerCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'BitLocker' -DerId $p.DerId -ObjectId $created.id -Message 'BitLocker policy created, assigned to Pilot, and validated.'|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message=("Created from current Intune Disk Encryption template, resolved {0} required settings, assigned to Pilot, and validated." -f @($resolved.Settings).Count);ActionId=$actionId})
    }catch{
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'BitLocker' -ActionId $actionId -DerId $p.DerId}

        if(Test-DERBitLockerCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $actionId -Phase FAIL -Module 'BitLocker' -DerId $p.DerId -Message $_.Exception.Message|Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
    }
    $summary=[pscustomobject]@{Created=@($results|Where-Object {$_.Status -eq 'Created'}).Count;Existing=@($results|Where-Object {$_.Status -eq 'Existing'}).Count;Skipped=@($results|Where-Object {$_.Status -eq 'Skipped'}).Count;Failed=@($results|Where-Object {$_.Status -eq 'Failed'}).Count}
    $out=[pscustomobject][ordered]@{Module='BitLocker';RunId=$RunId;Status=if($summary.Failed){'CompletedWithFailures'}elseif($summary.Created -or $summary.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$summary;Results=@($results)};Save-DERBitLockerResult $out;return $out
}

Export-ModuleMember -Function @('Invoke-DERBitLockerModule')
