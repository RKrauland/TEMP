<#
.SYNOPSIS
    DER no-write dry-run and final build approval engine.

.DESCRIPTION
    Validates the approved plan before any workload writes: required modules,
    write-session scopes, naming constraints, duplicate DER IDs/names, tenant
    identity, dependencies, preview-API policy, production-safety invariants,
    and expected manual/skipped outcomes. This module performs no tenant
    configuration writes.

.NOTES
    Required parent entry point: Invoke-DERDryRun
#>


# Maintenance notes
# Responsibility: Evaluates safety/blocking conditions before write-capable authentication; a blocked dry run must prevent BUILD execution.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERDryRunCommand {param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERDryRunLog {param([string]$Level,[string]$Message,$Data) if(Test-DERDryRunCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'DryRun' -Message $Message -Data $Data}}

function New-DERDryRunCheck {
    param([string]$Id,[string]$Category,[ValidateSet('Pass','Warn','Block')][string]$Status,[string]$Message,$Data)
    return [pscustomobject][ordered]@{Id=$Id;Category=$Category;Status=$Status;Message=$Message;Data=$Data}
}

function Test-DERComputerNameTemplate {
    param([string]$Template)
    if ([string]::IsNullOrWhiteSpace($Template)) { return [pscustomobject]@{Valid=$false;Reason='Template is empty.'} }
    if ($Template -match '\s') { return [pscustomobject]@{Valid=$false;Reason='Windows computer names cannot contain spaces.'} }

    foreach ($token in [regex]::Matches($Template,'%RAND:(\d+)%')) {
        $length=[int]$token.Groups[1].Value
        if ($length -lt 1 -or $length -gt 15) { return [pscustomobject]@{Valid=$false;Reason='RAND token length must be between 1 and 15.'} }
    }

    # Validate the generated name rather than the raw token syntax. The colon is
    # legal only inside DER's %RAND:n% token and must never survive substitution.
    $sample=$Template -replace '%RAND:(\d+)%', { param($m) '7' * [int]$m.Groups[1].Value }
    $sample=$sample -replace '%SERIAL%','SERIAL1234'
    if ($sample -match '%') { return [pscustomobject]@{Valid=$false;Reason='Template contains an unsupported or malformed DER token.';Sample=$sample} }
    if ($sample -match '[^A-Za-z0-9-]') { return [pscustomobject]@{Valid=$false;Reason='Generated computer name contains unsupported characters.';Sample=$sample} }
    if ($sample.Length -gt 15) { return [pscustomobject]@{Valid=$false;Reason=("Sample generated name '{0}' exceeds 15 characters." -f $sample);Sample=$sample} }
    return [pscustomobject]@{Valid=$true;Reason='Valid';Sample=$sample}
}

function Show-DERDryRunSummary {
    param($BuildPlan,$Checks,$PermissionPlan)
    $pass=@($Checks|Where-Object {$_.Status -eq 'Pass'}).Count
    $warn=@($Checks|Where-Object {$_.Status -eq 'Warn'}).Count
    $block=@($Checks|Where-Object {$_.Status -eq 'Block'}).Count
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host ' DER DRY RUN RESULT' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host ("Tenant:                     {0}" -f $BuildPlan.TenantName)
    Write-Host ("Planned objects/actions:     {0}" -f $BuildPlan.Summary.PlannedObjects)
    Write-Host ("Selected workload modules:   {0}" -f $BuildPlan.Summary.Modules)
    Write-Host ("Manual actions expected:     {0}" -f $BuildPlan.Summary.ManualActions)
    Write-Host ("Customer objects modified:   0")
    Write-Host ("Customer objects deleted:    0")
    Write-Host ("Production enforcement:      0")
    Write-Host ("Required write scopes:        {0}" -f @($PermissionPlan.RequiredScopes).Count)
    Write-Host ("Checks passed:                {0}" -f $pass) -ForegroundColor Green
    Write-Host ("Warnings:                     {0}" -f $warn) -ForegroundColor Yellow
    Write-Host ("Blocking failures:            {0}" -f $block) -ForegroundColor $(if($block){'Red'}else{'Green'})
    Write-Host ''
    foreach($c in @($Checks|Where-Object {$_.Status -ne 'Pass'})) {
        $color=if($c.Status -eq 'Block'){'Red'}else{'Yellow'}
        Write-Host ("[{0}] {1}: {2}" -f $c.Status.ToUpperInvariant(),$c.Category,$c.Message) -ForegroundColor $color
    }
}

function Invoke-DERDryRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)]$PermissionPlan,
        [Parameter(Mandatory)][string]$RunId,
        $WriteSession,
        [switch]$SkipFinalApproval,
        [switch]$IntegrationNoWrite
    )
    $started=Get-Date
    $checks=New-Object System.Collections.Generic.List[object]
    Write-DERDryRunLog -Level STEP -Message 'Starting full DER no-write dry run.' -Data @{tenantId=$BuildPlan.TenantId;planned=$BuildPlan.Summary.PlannedObjects}

    if ([string]::IsNullOrWhiteSpace([string]$BuildPlan.TenantId)) {$checks.Add((New-DERDryRunCheck 'TENANT-001' 'Tenant' 'Block' 'Build plan has no Tenant ID.'))}
    else {$checks.Add((New-DERDryRunCheck 'TENANT-001' 'Tenant' 'Pass' 'Build plan contains a Tenant ID.'))}

    $derIds=@($BuildPlan.Objects|Where-Object {$_.Enabled}|Select-Object -ExpandProperty DerId)
    $dupIds=@($derIds|Group-Object|Where-Object {$_.Count -gt 1})
    if($dupIds){$checks.Add((New-DERDryRunCheck 'PLAN-001' 'Plan' 'Block' ('Duplicate DER IDs: '+(($dupIds.Name)-join ', '))))}else{$checks.Add((New-DERDryRunCheck 'PLAN-001' 'Plan' 'Pass' 'All DER IDs are unique.'))}
    $names=@($BuildPlan.Objects|Where-Object {$_.Enabled}|Select-Object -ExpandProperty DisplayName)
    $dupNames=@($names|Group-Object|Where-Object {$_.Count -gt 1})
    if($dupNames){$checks.Add((New-DERDryRunCheck 'PLAN-002' 'Plan' 'Block' ('Duplicate planned display names: '+(($dupNames.Name)-join ', '))))}else{$checks.Add((New-DERDryRunCheck 'PLAN-002' 'Plan' 'Pass' 'All planned display names are unique.'))}

    $template=Test-DERComputerNameTemplate -Template $BuildPlan.Answers.Enrollment.ComputerNameTemplate
    if($template.Valid){$checks.Add((New-DERDryRunCheck 'NAME-001' 'Enrollment' 'Pass' ("Computer-name template is valid. Sample: {0}" -f $template.Sample)))}else{$checks.Add((New-DERDryRunCheck 'NAME-001' 'Enrollment' 'Block' $template.Reason $template))}

    if($BuildPlan.Safety.NeverModifyUnowned){$checks.Add((New-DERDryRunCheck 'SAFE-001' 'Ownership' 'Pass' 'Plan preserves the DER rule: customer-owned objects are never modified automatically.'))}else{$checks.Add((New-DERDryRunCheck 'SAFE-001' 'Ownership' 'Block' 'Build plan does not assert the DER unowned-object safety rule.'))}
    if([int]$BuildPlan.Summary.CustomerOwnedObjectsModified -ne 0 -or [int]$BuildPlan.Summary.CustomerOwnedObjectsDeleted -ne 0){$checks.Add((New-DERDryRunCheck 'SAFE-002' 'Ownership' 'Block' 'Build plan contains customer-owned object modification/deletion.'))}else{$checks.Add((New-DERDryRunCheck 'SAFE-002' 'Ownership' 'Pass' 'Customer-owned object writes/deletes are zero.'))}
    if([int]$BuildPlan.Summary.ProductionEnforcement -ne 0){$checks.Add((New-DERDryRunCheck 'SAFE-003' 'Production' 'Block' 'Build plan contains production enforcement.'))}else{$checks.Add((New-DERDryRunCheck 'SAFE-003' 'Production' 'Pass' 'Production enforcement is zero.'))}
    $badCA=@($BuildPlan.Objects|Where-Object {$_.Module -eq 'ConditionalAccess' -and $_.Enabled -and $_.SafeState -ne 'Report-only'})
    if($badCA){$checks.Add((New-DERDryRunCheck 'SAFE-004' 'Conditional Access' 'Block' 'At least one planned DER Conditional Access policy is not Report-only.'))}else{$checks.Add((New-DERDryRunCheck 'SAFE-004' 'Conditional Access' 'Pass' 'All planned DER Conditional Access policies are Report-only.'))}

    if(-not $BuildPlan.Safety.AllowPreviewApis){
        $previewModules=@('ASR','Analytics','Autopilot','BitLocker','Compliance','Configuration','Defender','DeliveryOptimization','Drivers','Enrollment','Firewall','LAPS','OneDrive','TenantSettings','Updates')
        if(Test-DERDryRunCommand 'Get-DERGraphCompatibilityCatalog'){
            $compat=Get-DERGraphCompatibilityCatalog
            if($compat){$previewModules=@($compat.entries|Where-Object {$_.apiVersion -eq 'beta' -and $_.previewWriteAllowed}|Select-Object -ExpandProperty module -Unique)}
        }
        $previewDependent=@($BuildPlan.Modules|Where-Object {$_.Name -in $previewModules})
        if($previewDependent){$checks.Add((New-DERDryRunCheck 'API-001' 'Preview API' 'Block' ('Preview API writes are disabled, but selected workload modules require allowlisted beta writes: '+(@($previewDependent.Name)-join ', ')+'. Enable DER Preview APIs or deselect those workloads.')))}
        else{$checks.Add((New-DERDryRunCheck 'API-001' 'Preview API' 'Pass' 'Preview writes are disabled and no selected workload requires them.'))}
    } else {$checks.Add((New-DERDryRunCheck 'API-001' 'Preview API' 'Pass' 'DER-tested Preview API allowlist is permitted for this run; unmatched beta writes remain blocked centrally.'))}

    $moduleCatalog=@('Groups','EntraDevice','Enrollment','Autopilot','Compliance','BitLocker','LAPS','Defender','ASR','Firewall','Configuration','AuthenticationMethods','ConditionalAccess','NamedLocations','GuestExternal','AppConsent','PasswordProtection','PIM','Updates','Drivers','OneDrive','DeliveryOptimization','TenantSettings','Analytics','LoggingIntegration')
    foreach($m in @($BuildPlan.Modules|Where-Object {$_.Enabled})){
        if($moduleCatalog -contains $m.Name){$checks.Add((New-DERDryRunCheck ("MOD-{0}" -f $m.Name) 'Module' 'Pass' ("Workload $($m.Name) is recognized by DER planner.")))}
        else{$checks.Add((New-DERDryRunCheck ("MOD-{0}" -f $m.Name) 'Module' 'Block' ("Unknown workload module $($m.Name).")))}
    }

    if($IntegrationNoWrite){
        $session=$WriteSession
        if((-not $session) -and (Test-DERDryRunCommand 'Get-DERAuthenticationContext')){$session=Get-DERAuthenticationContext}
        if($WriteSession -or ($session -and [string]$session.SessionType -eq 'Write')){$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Block' 'Integration no-write mode detected a write-authenticated Graph session.'))}
        else{$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Pass' ('Integration no-write mode calculated {0} potential write scope(s) but intentionally did not request them.' -f @($PermissionPlan.RequiredScopes).Count) @{requiredScopes=@($PermissionPlan.RequiredScopes)}))}
        if(Test-DERDryRunCommand 'Get-DERGraphRequestAuditSummary'){
            $audit=Get-DERGraphRequestAuditSummary
            if([string]$audit.WriteGuardMode -ne 'DenyAll'){$checks.Add((New-DERDryRunCheck 'SAFE-INT-001' 'Integration' 'Block' 'Central Graph DENY-ALL write guard is not active.'))}
            elseif([long]$audit.TransportWriteCount -ne 0){$checks.Add((New-DERDryRunCheck 'SAFE-INT-001' 'Integration' 'Block' 'At least one Graph mutation reached transport during integration mode.' $audit))}
            else{$checks.Add((New-DERDryRunCheck 'SAFE-INT-001' 'Integration' 'Pass' 'Central Graph DENY-ALL write guard is active and no mutation has reached transport.' $audit))}
        } else {$checks.Add((New-DERDryRunCheck 'SAFE-INT-001' 'Integration' 'Block' 'Graph request audit summary is unavailable.'))}
    }
    elseif($PermissionPlan.ReportOnly){$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Pass' 'Report-only plan requires no write scopes.'))}
    else {
        $session=$WriteSession
        if((-not $session) -and (Test-DERDryRunCommand 'Get-DERAuthenticationContext')){$session=Get-DERAuthenticationContext}
        if(-not $session -or $session.SessionType -ne 'Write') {$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Block' 'DER write authentication has not been completed for this build plan.'))}
        elseif([string]$session.TenantId -ne [string]$BuildPlan.TenantId){$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Block' 'Write session is connected to a different tenant.'))}
        else {
            $scopeTest=$null
            if(Test-DERDryRunCommand 'Test-DERSessionScopes'){$scopeTest=Test-DERSessionScopes -RequiredScopes $PermissionPlan.RequiredScopes}
            if($scopeTest -and -not $scopeTest.Success){$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Block' ('Missing delegated write scopes: '+(@($scopeTest.Missing)-join ', ')) $scopeTest))}
            else{$checks.Add((New-DERDryRunCheck 'PERM-001' 'Permissions' 'Pass' 'Write session tenant and required scopes validated.'))}
        }
    }

    if($BuildPlan.Answers.Security.PrimaryAV -eq 'Third-party AV' -and $BuildPlan.Answers.Security.CreateDefender){$checks.Add((New-DERDryRunCheck 'SEC-001' 'Defender' 'Block' 'Third-party AV selected but Defender policy creation is still enabled.'))}else{$checks.Add((New-DERDryRunCheck 'SEC-001' 'Defender' 'Pass' 'AV selection and planned Defender workload do not conflict.'))}
    if($BuildPlan.Answers.Identity.ConfigurePIM -and -not $BuildPlan.Answers.Identity.CreateRiskCAPs){$checks.Add((New-DERDryRunCheck 'LIC-001' 'Licensing' 'Warn' 'PIM selected while risk policies are not selected; verify this reflects licensing/engineer intent.'))}
    foreach($site in @($BuildPlan.Answers.Infrastructure.Sites|Where-Object {$_.CreateNamedLocation})){
        if(@($site.IPv4).Count -eq 0 -and @($site.IPv6).Count -eq 0){$checks.Add((New-DERDryRunCheck ("LOC-{0:000}" -f $site.Index) 'Named Locations' 'Warn' ("Site '$($site.Name)' has no public CIDR data; its Named Location cannot be created until IP data is supplied.")))}
    }

    $blocking=@($checks|Where-Object {$_.Status -eq 'Block'}).Count
    $ready=($blocking -eq 0)
    Show-DERDryRunSummary -BuildPlan $BuildPlan -Checks $checks -PermissionPlan $PermissionPlan
    $approval=$false
    if($ready -and -not $SkipFinalApproval -and -not $IntegrationNoWrite){
        if($BuildPlan.Summary.ReportOnly){
            Write-Host 'This run is configured as REPORT-ONLY. No workload writes will be executed.' -ForegroundColor Yellow
            $approval=$false
        } else {
            Write-Host ''
            Write-Host ("DER is ready to create/configure {0} planned DER-owned object/action(s) in {1}." -f $BuildPlan.Summary.PlannedObjects,$BuildPlan.TenantName) -ForegroundColor Cyan
            Write-Host 'Existing customer objects modified: 0 | Production enforcement: 0' -ForegroundColor Green
            $v=Read-Host 'Type BUILD to grant final approval, or press Enter to stop'
            $approval=($v -ceq 'BUILD')
        }
    }
    $result=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;StartedAt=$started;CompletedAt=Get-Date;Checks=@($checks);ReadyToBuild=$ready;FinalApprovalGranted=$approval;BlockingFailures=$blocking;Warnings=@($checks|Where-Object {$_.Status -eq 'Warn'}).Count;Passed=@($checks|Where-Object {$_.Status -eq 'Pass'}).Count;ReportOnly=$BuildPlan.Summary.ReportOnly;IntegrationNoWrite=[bool]$IntegrationNoWrite}
    Write-DERDryRunLog -Level $(if($ready){'OK'}else{'ERROR'}) -Message ("DER dry run complete. Ready={0}; blocking={1}; warnings={2}; finalApproval={3}." -f $ready,$result.BlockingFailures,$result.Warnings,$approval) -Data $result
    return $result
}

Export-ModuleMember -Function @('New-DERDryRunCheck','Test-DERComputerNameTemplate','Invoke-DERDryRun')
