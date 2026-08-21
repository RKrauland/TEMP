<#
.SYNOPSIS
    DER least-privilege write-permission resolver.

.DESCRIPTION
    Maps the approved build plan to the delegated Microsoft Graph scopes that
    DER expects to need. It never requests write permissions for skipped
    modules and does not itself modify tenant configuration.

.NOTES
    Required parent entry point: Resolve-DERRequiredPermissions
#>


# Maintenance notes
# Responsibility: Calculates the minimum Graph permission set needed for the selected plan without granting permissions itself.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERPermissionsCommand {param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERPermissionsLog {param([string]$Level,[string]$Message,$Data) if(Test-DERPermissionsCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Permissions' -Message $Message -Data $Data}}

function Get-DERPermissionCatalog {
    [CmdletBinding()]
    param()
    # Scopes are kept centralized so individual workload modules never invent
    # their own authentication model. Exact API-specific scopes are validated
    # again by the workload compatibility definitions before execution.
    return [ordered]@{
        Groups=@('Group.ReadWrite.All')
        EntraDevice=@('Policy.ReadWrite.DeviceConfiguration')
        Enrollment=@('DeviceManagementServiceConfig.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All','Policy.ReadWrite.MobilityManagement')
        Autopilot=@('DeviceManagementServiceConfig.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All')
        Compliance=@('DeviceManagementConfiguration.ReadWrite.All')
        BitLocker=@('DeviceManagementConfiguration.ReadWrite.All')
        LAPS=@('DeviceManagementConfiguration.ReadWrite.All','Policy.ReadWrite.DeviceConfiguration')
        Defender=@('DeviceManagementConfiguration.ReadWrite.All')
        ASR=@('DeviceManagementConfiguration.ReadWrite.All')
        Firewall=@('DeviceManagementConfiguration.ReadWrite.All')
        Configuration=@('DeviceManagementConfiguration.ReadWrite.All')
        AuthenticationMethods=@('Policy.ReadWrite.AuthenticationMethod')
        ConditionalAccess=@('Policy.Read.All','Policy.ReadWrite.ConditionalAccess','RoleManagement.Read.Directory')
        NamedLocations=@('Policy.Read.All','Policy.ReadWrite.ConditionalAccess')
        GuestExternal=@('Policy.ReadWrite.Authorization','Policy.ReadWrite.CrossTenantAccess')
        AppConsent=@('Policy.ReadWrite.ConsentRequest')
        PIM=@('RoleManagementPolicy.ReadWrite.Directory','RoleManagement.Read.Directory')
        Updates=@('DeviceManagementConfiguration.ReadWrite.All')
        Drivers=@('DeviceManagementConfiguration.ReadWrite.All')
        OneDrive=@('DeviceManagementConfiguration.ReadWrite.All')
        DeliveryOptimization=@('DeviceManagementConfiguration.ReadWrite.All')
        TenantSettings=@()
        Analytics=@('DeviceManagementConfiguration.ReadWrite.All')
        LoggingIntegration=@()
    }
}

function Resolve-DERRequiredPermissions {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId)
    $catalog=Get-DERPermissionCatalog
    $requirements=New-Object System.Collections.Generic.List[object]
    $scopes=New-Object System.Collections.Generic.List[string]

    if ($BuildPlan.Summary.ReportOnly) {
        $result=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;RequiredScopes=@();Requirements=@();ReportOnly=$true;CalculatedAt=Get-Date}
        Write-DERPermissionsLog -Level INFO -Message 'Build plan is report-only; no DER write scopes will be requested.' -Data $result
        return $result
    }

    foreach($module in @($BuildPlan.Modules | Where-Object {$_.Enabled})) {
        $name=[string]$module.Name
        $needed=@()
        if ($catalog.Contains($name)) {$needed=@($catalog[$name])}
        if ($name -eq 'TenantSettings') {
            $tenantObjects=@($BuildPlan.Objects | Where-Object {$_.Enabled -and $_.Module -eq 'TenantSettings'})
            if (@($tenantObjects | Where-Object {$_.DerId -eq 'DER-TENANT-010'}).Count -gt 0) {$needed += 'DeviceManagementManagedDevices.ReadWrite.All'}
            if (@($tenantObjects | Where-Object {$_.DerId -eq 'DER-TENANT-020'}).Count -gt 0) {$needed += 'DeviceManagementApps.ReadWrite.All'}
            $needed=@($needed | Sort-Object -Unique)
        }
        foreach($scope in $needed){if(-not $scopes.Contains($scope)){$scopes.Add($scope)}}
        $requirements.Add([pscustomobject][ordered]@{Module=$name;Scopes=$needed;Reason=("Required by approved DER {0} workload." -f $name)})
    }
    if ($BuildPlan.Answers.Operations.ConfigureSignInBranding -and -not $scopes.Contains('OrganizationalBranding.ReadWrite.All')) {$scopes.Add('OrganizationalBranding.ReadWrite.All')}
    $unique=@($scopes|Sort-Object -Unique)
    $result=[pscustomobject][ordered]@{SchemaVersion='1.0';RunId=$RunId;TenantId=$BuildPlan.TenantId;RequiredScopes=$unique;Requirements=@($requirements);ReportOnly=$false;CalculatedAt=Get-Date}
    Write-DERPermissionsLog -Level OK -Message ("Resolved {0} unique delegated write scope(s) for {1} selected workload module(s)." -f $unique.Count,@($requirements).Count) -Data @{scopes=$unique;requirements=$requirements}
    return $result
}

Export-ModuleMember -Function @('Get-DERPermissionCatalog','Resolve-DERRequiredPermissions')
