<#
.SYNOPSIS
    DER Microsoft Entra Authentication Methods workload.
.DESCRIPTION
    Enables engineer-selected built-in authentication methods through Graph
    v1.0. DER Standard never disables an existing method. Changes are prepared
    as one current-run DER-Adopted composite so the central validator and central
    rollback engine own read-back and restoration behavior.
#>

# Maintenance notes
# Responsibility: Manages selected authentication-method singleton/configuration state as a composite DER-Adopted object.
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


function Test-DERAuthMethodsCommand {param([Parameter(Mandatory)][string]$Name)return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Save-DERAuthMethodsResult {param($Result)$ctx=if(Test-DERAuthMethodsCommand 'Get-DERStateContext'){Get-DERStateContext}else{$null};if($ctx){$d=Join-Path $ctx.RunRoot 'Workloads';New-Item -ItemType Directory -Path $d -Force|Out-Null;$Result|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $d 'AuthenticationMethods.json') -Encoding UTF8}}
function Get-DERAuthMethodConfiguration {param([string]$Id,[string]$ActionId)return Invoke-DERGraphRequest -Method GET -Uri ("policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{0}" -f $Id) -ApiVersion 'v1.0' -Component 'AuthenticationMethods' -ActionId $ActionId}
function New-DERAuthMethodTargets {param([string]$Id,$Current)if($Current.PSObject.Properties.Name -contains 'includeTargets' -and @($Current.includeTargets).Count){return @($Current.includeTargets)};switch($Id){'microsoftAuthenticator'{return @([ordered]@{targetType='group';id='all_users';authenticationMode='any'})};default{return @([ordered]@{targetType='group';id='all_users'})}}}
function New-DERAuthMethodPatch {param([string]$Id,$Current)$targets=New-DERAuthMethodTargets -Id $Id -Current $Current;switch($Id){'microsoftAuthenticator'{return [ordered]@{'@odata.type'='#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration';state='enabled';includeTargets=$targets}};'fido2'{return [ordered]@{'@odata.type'='#microsoft.graph.fido2AuthenticationMethodConfiguration';state='enabled';isSelfServiceRegistrationAllowed=$true;includeTargets=$targets}};'temporaryAccessPass'{return [ordered]@{'@odata.type'='#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration';state='enabled';includeTargets=$targets}};'sms'{return [ordered]@{'@odata.type'='#microsoft.graph.smsAuthenticationMethodConfiguration';state='enabled';includeTargets=$targets}};'softwareOath'{return [ordered]@{'@odata.type'='#microsoft.graph.softwareOathAuthenticationMethodConfiguration';state='enabled';includeTargets=$targets}};'voice'{return [ordered]@{'@odata.type'='#microsoft.graph.voiceAuthenticationMethodConfiguration';state='enabled';includeTargets=$targets}};default{throw (New-DERWorkloadFailureException -Message "Unsupported authentication method $Id" -FailureKind Engine)}}}
function New-DERAuthMethodRestoreBody {param([string]$Id,$Original)$body=[ordered]@{};$types=@{microsoftAuthenticator='#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration';fido2='#microsoft.graph.fido2AuthenticationMethodConfiguration';temporaryAccessPass='#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration';sms='#microsoft.graph.smsAuthenticationMethodConfiguration';softwareOath='#microsoft.graph.softwareOathAuthenticationMethodConfiguration';voice='#microsoft.graph.voiceAuthenticationMethodConfiguration'};$body['@odata.type']=$types[$Id];foreach($name in @('state','includeTargets','excludeTargets','isSelfServiceRegistrationAllowed','defaultLifetimeInMinutes','defaultLength','minimumLifetimeInMinutes','maximumLifetimeInMinutes','isUsableOnce')){if($Original.PSObject.Properties.Name -contains $name){$body[$name]=$Original.$name}};return $body}

function Complete-DERAuthMethodsResult {
    param($Results,[string]$RunId)
    $s=[pscustomobject]@{Created=0;Updated=@($Results|Where-Object{$_.Status -eq 'Updated'}).Count;Existing=@($Results|Where-Object{$_.Status -eq 'Existing'}).Count;Skipped=@($Results|Where-Object{$_.Status -eq 'Skipped'}).Count;Failed=@($Results|Where-Object{$_.Status -eq 'Failed'}).Count}
    $o=[pscustomobject]@{Module='AuthenticationMethods';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Updated -or $s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)}
    Save-DERAuthMethodsResult $o
    return $o
}

function Invoke-DERAuthenticationMethodsModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)
    $results=New-Object System.Collections.Generic.List[object]
    $planned=@($BuildPlan.Objects|Where-Object{$_.Enabled -and $_.Module -eq 'AuthenticationMethods'}|Select-Object -First 1)
    if(-not $planned.Count){return Complete-DERAuthMethodsResult $results $RunId}
    $p=$planned[0]
    $aid=if(Test-DERAuthMethodsCommand 'New-DERActionId'){New-DERActionId -Component 'AUTH'}else{'AUTH-001'}
    $wanted=New-Object System.Collections.Generic.List[string]
    if([bool]$BuildPlan.Answers.Identity.EnableAuthenticator){$wanted.Add('microsoftAuthenticator')}
    if([bool]$BuildPlan.Answers.Identity.EnableFIDO2){$wanted.Add('fido2')}
    if([bool]$BuildPlan.Answers.Identity.EnableTAP){$wanted.Add('temporaryAccessPass')}
    if([bool]$BuildPlan.Answers.Identity.EnableSMSFallback){$wanted.Add('sms')}
    if([bool]$BuildPlan.Answers.Identity.EnableSoftwareOATH){$wanted.Add('softwareOath')}
    if([bool]$BuildPlan.Answers.Identity.EnableVoice){$wanted.Add('voice')}
    if(-not $wanted.Count){return Complete-DERAuthMethodsResult $results $RunId}

    try {
        # Read every requested method before writing any of them.  One ActionId
        # and one composite adopted-state recipe cover the complete module run.
        $validations=New-Object System.Collections.Generic.List[object]
        $originalValidations=New-Object System.Collections.Generic.List[object]
        $restores=New-Object System.Collections.Generic.List[object]
        $updates=New-Object System.Collections.Generic.List[object]
        $methodPlans=New-Object System.Collections.Generic.List[object]
        foreach($id in $wanted){
            $current=Get-DERAuthMethodConfiguration -Id $id -ActionId $aid
            if(-not $current){throw (New-DERWorkloadFailureException -Message "Authentication method $id could not be read.")}
            $patch=New-DERAuthMethodPatch -Id $id -Current $current
            $uri="policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$id"
            $expected=[pscustomobject]$patch
            $restore=New-DERAuthMethodRestoreBody -Id $id -Original $current
            $validations.Add([pscustomobject]@{Uri=$uri;ApiVersion='v1.0';ExpectedSubset=$expected})
            $originalValidations.Add([pscustomobject]@{Uri=$uri;ApiVersion='v1.0';ExpectedSubset=[pscustomobject]$restore})
            $cmp=Test-DERExpectedSubset -Actual $current -Expected $expected
            if($cmp.Success){
                $methodPlans.Add([pscustomobject]@{Id=$id;Status='Existing';Message='Already enabled with the DER-selected targeting; no tenant write was required.'})
                continue
            }
            $restores.Add([pscustomobject]@{Uri=$uri;Method='PATCH';ApiVersion='v1.0';OriginalState=[pscustomobject]$restore;OriginalExpectedSubset=[pscustomobject]$restore;ExpectedCurrentSubset=$expected;MethodId=$id})
            $updates.Add([pscustomobject]@{Id=$id;Uri=$uri;Body=$patch})
            $methodPlans.Add([pscustomobject]@{Id=$id;Status='Updated';Message='Enabled and validated; DER did not disable any existing method.'})
        }

        $state=if(Test-DERAuthMethodsCommand 'Get-DERStateObject'){Get-DERStateObject -DerId $p.DerId}else{$null}
        if($state){
            if([string]$state.OwnershipClass -ne 'DER-Adopted'){throw (New-DERWorkloadFailureException -Message "Authentication Methods state '$($p.DerId)' is not DER-Adopted; automatic update refused.")}
            if([string]$state.ObjectId -notin @($wanted)){throw (New-DERWorkloadFailureException -Message "DER RECONCILIATION_REQUIRED: recorded Authentication Methods anchor '$($state.ObjectId)' is not part of the current selected method set.")}
            Assert-DERManagedStateObject -StateRecord $state -Component 'AuthenticationMethods' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') | Out-Null
        }

        $anchor=if($state){[string]$state.ObjectId}else{[string]$wanted[0]}
        $anchorUri="policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$anchor"
        $anchorExpected=@($validations | Where-Object { [string]$_.Uri -eq $anchorUri } | Select-Object -First 1)[0].ExpectedSubset
        $anchorOriginalExpected=@($originalValidations | Where-Object { [string]$_.Uri -eq $anchorUri } | Select-Object -First 1)[0].ExpectedSubset
        $desiredMetadata=[pscustomobject][ordered]@{
            Module='AuthenticationMethods';ApiVersion='v1.0';ValidationUri=$anchorUri
            ExpectedSubset=$anchorExpected;CompositeValidations=@($validations);BuiltInTenantObjects=$true
            AdoptionNoTenantWrite=($updates.Count -eq 0)
        }
        if(-not $state){
            $initialMetadata=if($updates.Count){[pscustomobject][ordered]@{Module='AuthenticationMethods';ApiVersion='v1.0';ValidationUri=$anchorUri;ExpectedSubset=$anchorOriginalExpected;CompositeValidations=@($originalValidations);BuiltInTenantObjects=$true;AdoptionNoTenantWrite=$true}}else{$desiredMetadata}
            $state=Add-DERStateObject -DerId $p.DerId -ObjectId $anchor -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Adopted' -Status Adopted -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $initialMetadata
        } elseif(-not $updates.Count){
            $state=Update-DERStateObject -ObjectId $state.ObjectId -Metadata $desiredMetadata -Status Adopted
        }

        if($updates.Count){
            foreach($restore in $restores){
                if(Test-DERAuthMethodsCommand 'Register-DERTransaction'){
                    Register-DERTransaction -ActionId $aid -Phase RECORD_ORIGINAL -Module 'AuthenticationMethods' -DerId $p.DerId -ObjectId $anchor -Message ("Recorded original authentication method configuration: {0}." -f $restore.MethodId) -Data $restore.OriginalState | Out-Null
                }
            }
            $rollbackMetadata=[pscustomobject][ordered]@{
                Module='AuthenticationMethods';ApiVersion='v1.0';ValidationUri=$anchorUri
                ExpectedSubset=$anchorExpected;CompositeValidations=@($validations);CompositeRestores=@($restores)
                BuiltInTenantObjects=$true;AdoptionNoTenantWrite=$false
            }
            $state=Set-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $aid -RollbackMetadata $rollbackMetadata
            foreach($update in $updates){
                Invoke-DERGraphRequest -Method PATCH -Uri $update.Uri -ApiVersion 'v1.0' -Body $update.Body -Component 'AuthenticationMethods' -DerId $p.DerId -ActionId $aid | Out-Null
            }
        }

        $state=Get-DERStateObject -DerId $p.DerId
        Assert-DERManagedStateObject -StateRecord $state -Component 'AuthenticationMethods' -ActionId $aid -AllowedOwnershipClass @('DER-Adopted') -MarkValidated | Out-Null
        if($updates.Count){Clear-DERAdoptedRollbackPreparation -ObjectId $state.ObjectId -RunId $RunId -ActionId $aid | Out-Null}
        if(Test-DERAuthMethodsCommand 'Register-DERTransaction'){
            Register-DERTransaction -ActionId $aid -Phase COMMIT -Module 'AuthenticationMethods' -DerId $p.DerId -ObjectId $state.ObjectId -Message 'Authentication Methods composite state read-back validated.' -Data @{SelectedMethods=@($wanted);ChangedMethods=@($updates|ForEach-Object{$_.Id})} | Out-Null
        }
        foreach($methodPlan in $methodPlans){$results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$methodPlan.Id;ObjectId=$methodPlan.Id;Status=$methodPlan.Status;Message=$methodPlan.Message;ActionId=$aid})}
    }
    catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'AuthenticationMethods' -ActionId $aid -DerId $p.DerId}

        $failure=$_.Exception.Message
        if(Test-DERAuthMethodsCommand 'Register-DERTransaction'){Register-DERTransaction -ActionId $aid -Phase FAIL -Module 'AuthenticationMethods' -DerId $p.DerId -Message $failure | Out-Null}
        $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$failure;ActionId=$aid})
    }
    return Complete-DERAuthMethodsResult $results $RunId
}

Export-ModuleMember -Function @('Invoke-DERAuthenticationMethodsModule')
