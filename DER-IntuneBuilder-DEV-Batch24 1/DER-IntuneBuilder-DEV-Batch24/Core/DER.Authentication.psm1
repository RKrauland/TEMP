<#
.SYNOPSIS
    DER Microsoft Graph authentication engine.

.DESCRIPTION
    Owns interactive delegated authentication for DER.

    V1 authentication model:
      1. Read/discovery authentication before questionnaire
      2. Second write authentication after DER calculates required scopes

    Sessions use ContextScope Process so DER authentication is isolated to the
    current PowerShell process.

.NOTES
    Required parent entry point: Connect-DERDiscoverySession
#>


# Maintenance notes
# Responsibility: Owns discovery/write session authentication and exact tenant/session permission boundaries; it does not decide workload business logic.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DERAuthenticationContext = $null
$script:DERAuthenticationAudit = [ordered]@{DiscoverySessionAttempts=[long]0;DiscoverySessionsOpened=[long]0;WriteSessionAttempts=[long]0;WriteSessionsOpened=[long]0;Disconnects=[long]0}

function Write-DERAuthenticationLog {
    param([Parameter(Mandatory)][string]$Level,[Parameter(Mandatory)][string]$Message,$Data)
    if (Get-Command Write-DERLog -ErrorAction SilentlyContinue) {Write-DERLog -Level $Level -Component 'Authentication' -Message $Message -Data $Data}
}

function New-DERAuthenticationActionException {
    param([Parameter(Mandatory)][string]$Message,[string]$ActionId)
    $ex=[System.InvalidOperationException]::new($Message)
    $ex.Data['DERFailureKind']='Action'
    $ex.Data['DERComponent']='Authentication'
    if($ActionId){$ex.Data['DERActionId']=$ActionId}
    return $ex
}

function Get-DERDefaultDiscoveryScopes {
    [CmdletBinding()]
    param()
    return @(
        'User.Read.All','Group.Read.All','Organization.Read.All','Domain.Read.All','LicenseAssignment.Read.All','Device.Read.All',
        'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','DeviceManagementServiceConfig.Read.All',
        'Policy.Read.All','RoleManagement.Read.Directory'
    ) | Sort-Object -Unique
}

function Get-DERAuthenticationContext {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERAuthenticationContext) {return $null}
    return [pscustomobject]@{
        SessionType=$script:DERAuthenticationContext.SessionType;Account=$script:DERAuthenticationContext.Account;TenantId=$script:DERAuthenticationContext.TenantId;
        TenantName=$script:DERAuthenticationContext.TenantName;Environment=$script:DERAuthenticationContext.Environment;AuthType=$script:DERAuthenticationContext.AuthType;
        ContextScope=$script:DERAuthenticationContext.ContextScope;Scopes=@($script:DERAuthenticationContext.Scopes);ConnectedAt=$script:DERAuthenticationContext.ConnectedAt
    }
}

function Get-DERAuthenticationAuditSummary {
    [CmdletBinding()]
    param()
    return [pscustomobject][ordered]@{
        DiscoverySessionAttempts=[long]$script:DERAuthenticationAudit.DiscoverySessionAttempts
        DiscoverySessionsOpened=[long]$script:DERAuthenticationAudit.DiscoverySessionsOpened
        WriteSessionAttempts=[long]$script:DERAuthenticationAudit.WriteSessionAttempts
        WriteSessionsOpened=[long]$script:DERAuthenticationAudit.WriteSessionsOpened
        Disconnects=[long]$script:DERAuthenticationAudit.Disconnects
    }
}

function Get-DERTenantSummary {
    if (-not (Get-Command Invoke-DERGraphRequest -ErrorAction SilentlyContinue)) {throw 'DER Graph engine is not available. Initialize-DERGraphEngine must run first.'}
    $response=Invoke-DERGraphRequest -Method GET -Uri 'organization?$select=id,displayName,verifiedDomains,tenantType' -ApiVersion 'v1.0' -Component 'Authentication'
    $organization=@($response.value)|Select-Object -First 1
    if (-not $organization) {throw 'Microsoft Graph authenticated successfully, but DER could not read the organization object.'}
    $primaryDomain=$null;$verifiedDomains=@()
    foreach ($domain in @($organization.verifiedDomains)) {
        if ($domain.name) {$verifiedDomains += [string]$domain.name}
        if ($domain.isDefault -eq $true) {$primaryDomain=[string]$domain.name}
    }
    return [pscustomobject]@{TenantId=[string]$organization.id;DisplayName=[string]$organization.displayName;TenantType=[string]$organization.tenantType;PrimaryDomain=$primaryDomain;VerifiedDomains=@($verifiedDomains|Sort-Object -Unique)}
}

function Confirm-DERTenant {
    param([Parameter(Mandatory)]$TenantSummary,[Parameter(Mandatory)]$MgContext,[switch]$SkipConfirmation)
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host ' DER TENANT CONFIRMATION' -ForegroundColor Cyan
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host (' Organization  : {0}' -f $TenantSummary.DisplayName)
    Write-Host (' Primary domain: {0}' -f $TenantSummary.PrimaryDomain)
    Write-Host (' Tenant ID     : {0}' -f $TenantSummary.TenantId)
    Write-Host (' Signed in as  : {0}' -f $MgContext.Account)
    Write-Host (' Environment   : {0}' -f $MgContext.Environment)
    Write-Host '==============================================================' -ForegroundColor DarkCyan
    Write-Host ''
    if ($SkipConfirmation) {
        Write-DERAuthenticationLog -Level WARN -Message 'Tenant confirmation prompt bypassed by caller.' -Data @{tenantId=$TenantSummary.TenantId;tenantName=$TenantSummary.DisplayName;account=$MgContext.Account}
        return $true
    }
    Write-Host 'Type YES to confirm this is the tenant you intend to scan.' -ForegroundColor Yellow
    $answer=Read-Host 'Confirm tenant'
    if ($answer.Trim() -cne 'YES') {
        Write-DERAuthenticationLog -Level WARN -Message 'Engineer did not confirm the tenant.' -Data @{tenantId=$TenantSummary.TenantId;tenantName=$TenantSummary.DisplayName;entered=$answer}
        return $false
    }
    return $true
}

function Disconnect-DERSession {
    [CmdletBinding()]
    param([switch]$Quiet)
    $context=Get-MgContext
    if ($context) {
        $script:DERAuthenticationAudit.Disconnects++
        try {Disconnect-MgGraph -ErrorAction Stop|Out-Null;if (-not $Quiet) {Write-DERAuthenticationLog -Level INFO -Message 'Microsoft Graph session disconnected.'}}
        catch {if (-not $Quiet) {Write-DERAuthenticationLog -Level WARN -Message ('Unable to cleanly disconnect Microsoft Graph session: {0}' -f $_.Exception.Message)}}
    }
    $script:DERAuthenticationContext=$null
}

function Connect-DERDiscoverySession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,[string[]]$Scopes,
        [ValidateSet('Global','USGov','USGovDoD','China','BleuCloud','DelosCloud','GovSGCloud')][string]$Environment='Global',
        [string]$TenantId,[string]$ClientId,[switch]$UseDeviceAuthentication,[switch]$SkipTenantConfirmation
    )
    foreach ($command in @('Connect-MgGraph','Disconnect-MgGraph','Get-MgContext')) {if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {throw "DER authentication requires $command. Microsoft.Graph.Authentication is not loaded."}}
    if (-not $Scopes -or $Scopes.Count -eq 0) {$Scopes=Get-DERDefaultDiscoveryScopes}
    Disconnect-DERSession -Quiet
    $script:DERAuthenticationAudit.DiscoverySessionAttempts++
    Write-DERAuthenticationLog -Level STEP -Message 'Starting DER read/discovery Microsoft Graph authentication.' -Data @{runId=$RunId;environment=$Environment;scopes=$Scopes;tenantHint=$TenantId;clientIdProvided=[bool]$ClientId;deviceAuthentication=[bool]$UseDeviceAuthentication}
    $p=@{Scopes=$Scopes;ContextScope='Process';Environment=$Environment;NoWelcome=$true;ErrorAction='Stop'}
    if ($TenantId) {$p.TenantId=$TenantId};if ($ClientId) {$p.ClientId=$ClientId};if ($UseDeviceAuthentication) {$p.UseDeviceAuthentication=$true}
    try {Connect-MgGraph @p|Out-Null} catch {
        $authError=$_
        $authError.Exception.Data['DERFailureKind']='Action';$authError.Exception.Data['DERComponent']='Authentication'
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $authError -Component 'Authentication' -Message ('Microsoft Graph discovery authentication failed: {0}' -f $authError.Exception.Message)}else{Write-DERAuthenticationLog -Level ERROR -Message ('Microsoft Graph discovery authentication failed: {0}' -f $authError.Exception.Message)}
        throw $authError
    }
    $mgContext=Get-MgContext
    if (-not $mgContext -or -not $mgContext.TenantId) {throw (New-DERAuthenticationActionException -Message 'Connect-MgGraph returned without a usable DER Graph context.')}
    if (Get-Command Set-DERGraphEnvironment -ErrorAction SilentlyContinue) {Set-DERGraphEnvironment -Environment $Environment|Out-Null}
    $tenantSummary=Get-DERTenantSummary
    if ($tenantSummary.TenantId -ne [string]$mgContext.TenantId) {Disconnect-DERSession -Quiet;throw (New-DERAuthenticationActionException -Message ('DER tenant verification mismatch. Graph context {0} vs organization {1}.' -f $mgContext.TenantId,$tenantSummary.TenantId))}
    if (-not (Confirm-DERTenant -TenantSummary $tenantSummary -MgContext $mgContext -SkipConfirmation:$SkipTenantConfirmation)) {Disconnect-DERSession -Quiet;throw (New-DERAuthenticationActionException -Message 'Tenant confirmation was not granted. DER made no tenant changes.')}
    $script:DERAuthenticationContext=[pscustomobject][ordered]@{
        SessionType='Discovery';RunId=$RunId;Account=[string]$mgContext.Account;TenantId=[string]$mgContext.TenantId;TenantName=[string]$tenantSummary.DisplayName;
        Environment=[string]$Environment;AuthType=[string]$mgContext.AuthType;ContextScope=[string]$mgContext.ContextScope;Scopes=@($mgContext.Scopes|Sort-Object -Unique);ConnectedAt=Get-Date
    }
    $script:DERAuthenticationAudit.DiscoverySessionsOpened++
    Write-DERAuthenticationLog -Level OK -Message ('Discovery session connected to {0}.' -f $tenantSummary.DisplayName) -Data @{tenantId=$script:DERAuthenticationContext.TenantId;tenantName=$script:DERAuthenticationContext.TenantName;account=$script:DERAuthenticationContext.Account;environment=$script:DERAuthenticationContext.Environment;scopeCount=$script:DERAuthenticationContext.Scopes.Count}
    return Get-DERAuthenticationContext
}

function Connect-DERWriteSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$ExpectedTenantId,[Parameter(Mandatory)][string[]]$Scopes,
        [ValidateSet('Global','USGov','USGovDoD','China','BleuCloud','DelosCloud','GovSGCloud')][string]$Environment='Global',
        [string]$ClientId,[switch]$UseDeviceAuthentication
    )
    if (-not $Scopes -or $Scopes.Count -eq 0) {throw 'DER write authentication requires explicitly calculated write scopes.'}
    $script:DERAuthenticationAudit.WriteSessionAttempts++
    Disconnect-DERSession -Quiet
    Write-DERAuthenticationLog -Level STEP -Message 'Starting DER write Microsoft Graph authentication for the approved build plan.' -Data @{runId=$RunId;expectedTenantId=$ExpectedTenantId;environment=$Environment;scopes=$Scopes}
    $p=@{TenantId=$ExpectedTenantId;Scopes=($Scopes|Sort-Object -Unique);ContextScope='Process';Environment=$Environment;NoWelcome=$true;ErrorAction='Stop'}
    if ($ClientId) {$p.ClientId=$ClientId};if ($UseDeviceAuthentication) {$p.UseDeviceAuthentication=$true}
    try {Connect-MgGraph @p|Out-Null} catch {
        $authError=$_
        $authError.Exception.Data['DERFailureKind']='Action';$authError.Exception.Data['DERComponent']='Authentication'
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $authError -Component 'Authentication' -Message ('Microsoft Graph write authentication failed: {0}' -f $authError.Exception.Message)}else{Write-DERAuthenticationLog -Level ERROR -Message ('Microsoft Graph write authentication failed: {0}' -f $authError.Exception.Message)}
        throw $authError
    }
    $mgContext=Get-MgContext
    if (-not $mgContext -or -not $mgContext.TenantId) {throw (New-DERAuthenticationActionException -Message 'DER write authentication completed without a usable Graph context.')}
    if ([string]$mgContext.TenantId -ne $ExpectedTenantId) {Disconnect-DERSession -Quiet;throw (New-DERAuthenticationActionException -Message ('DER write authentication connected to wrong tenant. Expected {0}, got {1}.' -f $ExpectedTenantId,$mgContext.TenantId))}
    if (Get-Command Set-DERGraphEnvironment -ErrorAction SilentlyContinue) {Set-DERGraphEnvironment -Environment $Environment|Out-Null}
    $tenantSummary=Get-DERTenantSummary
    if ($tenantSummary.TenantId -ne $ExpectedTenantId) {Disconnect-DERSession -Quiet;throw (New-DERAuthenticationActionException -Message 'DER write session tenant verification failed.')}
    $script:DERAuthenticationContext=[pscustomobject][ordered]@{
        SessionType='Write';RunId=$RunId;Account=[string]$mgContext.Account;TenantId=[string]$mgContext.TenantId;TenantName=[string]$tenantSummary.DisplayName;
        Environment=[string]$Environment;AuthType=[string]$mgContext.AuthType;ContextScope=[string]$mgContext.ContextScope;Scopes=@($mgContext.Scopes|Sort-Object -Unique);ConnectedAt=Get-Date
    }
    $script:DERAuthenticationAudit.WriteSessionsOpened++
    Write-DERAuthenticationLog -Level OK -Message ('Write session connected to {0}.' -f $tenantSummary.DisplayName) -Data @{tenantId=$script:DERAuthenticationContext.TenantId;account=$script:DERAuthenticationContext.Account;scopeCount=$script:DERAuthenticationContext.Scopes.Count}
    return Get-DERAuthenticationContext
}

function Test-DERSessionScopes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$RequiredScopes)
    $context=Get-MgContext
    if (-not $context) {return [pscustomobject]@{Success=$false;Missing=@($RequiredScopes);Granted=@()}}
    $granted=@($context.Scopes);$missing=@()
    foreach ($required in ($RequiredScopes|Sort-Object -Unique)) {if ($granted -notcontains $required) {$missing += $required}}
    return [pscustomobject]@{Success=($missing.Count -eq 0);Missing=$missing;Granted=$granted}
}

Export-ModuleMember -Function @('Get-DERDefaultDiscoveryScopes','Get-DERAuthenticationContext','Get-DERAuthenticationAuditSummary','Connect-DERDiscoverySession','Connect-DERWriteSession','Disconnect-DERSession','Test-DERSessionScopes')
