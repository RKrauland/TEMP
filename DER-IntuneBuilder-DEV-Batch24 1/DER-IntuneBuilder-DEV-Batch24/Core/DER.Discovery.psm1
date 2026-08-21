<#
.SYNOPSIS
    DER tenant discovery engine.

.DESCRIPTION
    Performs the read-only tenant scan that drives the DER questionnaire and
    build plan. Every resource is queried independently so a missing license,
    unsupported API, or denied permission is recorded instead of hiding the
    rest of the tenant.

.NOTES
    Required parent entry point: Invoke-DERTenantDiscovery
#>


# Maintenance notes
# Responsibility: Performs read-only tenant discovery. Critical family failures must stop planning rather than masquerade as empty tenant state.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERDiscoveryCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERDiscoveryLog {
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$ActionId,
        $Data
    )
    if (Test-DERDiscoveryCommand -Name 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Discovery' -ActionId $ActionId -Message $Message -Data $Data
    } elseif ($Level -in @('STEP','OK','WARN','ERROR','CRITICAL')) {
        Write-Host "[$Level] [Discovery] $Message"
    }
}

function New-DERDiscoveryActionId {
    param([Parameter(Mandatory)][string]$Name)
    if (Test-DERDiscoveryCommand -Name 'New-DERActionId') {
        return New-DERActionId -Component 'DISC'
    }
    return ('DER-DISC-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0,8).ToUpperInvariant()))
}

function Get-DERDiscoveryCatalog {
    [CmdletBinding()]
    param()

    # Keep this catalog declarative. It is intentionally broader than the
    # minimum required build so the questionnaire can react to existing state.
    return @(
        [pscustomobject]@{Key='Tenant';Category='Tenant';Mode='Collection';Api='v1.0';Uri='organization?$select=id,displayName,verifiedDomains,tenantType,createdDateTime';Critical=$true;Snapshot=$true},
        [pscustomobject]@{Key='Domains';Category='Tenant';Mode='Collection';Api='v1.0';Uri='domains?$select=id,isDefault,isInitial,isVerified,authenticationType,supportedServices';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='Licenses';Category='Tenant';Mode='Collection';Api='v1.0';Uri='subscribedSkus';Critical=$true;Snapshot=$true},
        [pscustomobject]@{Key='Users';Category='Identity';Mode='Collection';Api='v1.0';Uri='users?$select=id,userType,accountEnabled,createdDateTime';Critical=$false;Snapshot=$false},
        [pscustomobject]@{Key='Groups';Category='Identity';Mode='Collection';Api='v1.0';Uri='groups?$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled,membershipRule,membershipRuleProcessingState,createdDateTime';Critical=$true;Snapshot=$true},
        [pscustomobject]@{Key='Devices';Category='Devices';Mode='Collection';Api='v1.0';Uri='devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,profileType,accountEnabled,isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime';Critical=$false;Snapshot=$false},
        [pscustomobject]@{Key='ManagedDevices';Category='Intune';Mode='Collection';Api='v1.0';Uri='deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,operatingSystem,osVersion,managedDeviceOwnerType,managementAgent,complianceState,lastSyncDateTime,enrolledDateTime,model,manufacturer,serialNumber,userPrincipalName';Critical=$false;Snapshot=$false},

        [pscustomobject]@{Key='ConditionalAccessPolicies';Category='IdentitySecurity';Mode='Collection';Api='v1.0';Uri='identity/conditionalAccess/policies';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='NamedLocations';Category='IdentitySecurity';Mode='Collection';Api='v1.0';Uri='identity/conditionalAccess/namedLocations';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='SecurityDefaults';Category='IdentitySecurity';Mode='Singleton';Api='v1.0';Uri='policies/identitySecurityDefaultsEnforcementPolicy';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='AuthenticationMethodsPolicy';Category='IdentitySecurity';Mode='Singleton';Api='v1.0';Uri='policies/authenticationMethodsPolicy';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DeviceRegistrationPolicy';Category='IdentitySecurity';Mode='Singleton';Api='v1.0';Uri='policies/deviceRegistrationPolicy';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='AuthorizationPolicy';Category='IdentitySecurity';Mode='Singleton';Api='v1.0';Uri='policies/authorizationPolicy';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='PermissionGrantPolicies';Category='IdentitySecurity';Mode='Collection';Api='v1.0';Uri='policies/permissionGrantPolicies';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='AdminConsentRequestPolicy';Category='IdentitySecurity';Mode='Singleton';Api='v1.0';Uri='policies/adminConsentRequestPolicy';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DirectoryRoleDefinitions';Category='IdentitySecurity';Mode='Collection';Api='v1.0';Uri='roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DirectoryRoleAssignments';Category='IdentitySecurity';Mode='Collection';Api='v1.0';Uri='roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId,appScopeId,createdDateTime';Critical=$false;Snapshot=$true},

        # MDM scope currently requires the preview API. DER only reads it here.
        [pscustomobject]@{Key='MobileDeviceManagementPolicies';Category='Enrollment';Mode='Collection';Api='beta';Uri='policies/mobileDeviceManagementPolicies?$expand=includedGroups';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DeviceEnrollmentConfigurations';Category='Enrollment';Mode='Collection';Api='beta';Uri='deviceManagement/deviceEnrollmentConfigurations';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='AutopilotProfiles';Category='Enrollment';Mode='Collection';Api='beta';Uri='deviceManagement/windowsAutopilotDeploymentProfiles';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='AutopilotDevices';Category='Enrollment';Mode='Collection';Api='beta';Uri='deviceManagement/windowsAutopilotDeviceIdentities?$select=id,azureActiveDirectoryDeviceId,serialNumber,groupTag,manufacturer,model,enrollmentState,lastContactedDateTime';Critical=$false;Snapshot=$true},

        [pscustomobject]@{Key='CompliancePolicies';Category='Intune';Mode='Collection';Api='beta';Uri='deviceManagement/deviceCompliancePolicies';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DeviceConfigurations';Category='Intune';Mode='Collection';Api='beta';Uri='deviceManagement/deviceConfigurations';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='ConfigurationPolicies';Category='Intune';Mode='Collection';Api='beta';Uri='deviceManagement/configurationPolicies';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='GroupPolicyConfigurations';Category='Intune';Mode='Collection';Api='beta';Uri='deviceManagement/groupPolicyConfigurations';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='EndpointSecurityIntents';Category='Intune';Mode='Collection';Api='beta';Uri='deviceManagement/intents';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='FeatureUpdateProfiles';Category='Updates';Mode='Collection';Api='beta';Uri='deviceManagement/windowsFeatureUpdateProfiles';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='DriverUpdateProfiles';Category='Updates';Mode='Collection';Api='beta';Uri='deviceManagement/windowsDriverUpdateProfiles';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='ManagedDeviceCleanupRules';Category='Tenant';Mode='Collection';Api='beta';Uri='deviceManagement/managedDeviceCleanupRules';Critical=$false;Snapshot=$true},
        [pscustomobject]@{Key='IntuneBrandingProfiles';Category='Tenant';Mode='Collection';Api='beta';Uri='deviceManagement/intuneBrandingProfiles';Critical=$false;Snapshot=$true}
    )
}

function Get-DERExceptionStatusCode {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    try {
        if ($ErrorRecord.Exception.Data -and $ErrorRecord.Exception.Data.Contains('DERStatusCode')) {
            return [int]$ErrorRecord.Exception.Data['DERStatusCode']
        }
    } catch {
        # Status extraction is best-effort metadata only; the original discovery
        # exception still controls the fail-closed discovery result.
        $null=$_.Exception.Message
    }
    return $null
}

function Get-DERDiscoveryFailureState {
    param([Nullable[int]]$StatusCode)
    if ($null -eq $StatusCode) { return 'Error' }
    switch ([int]$StatusCode) {
        401 { return 'AuthenticationFailed' }
        403 { return 'PermissionDenied' }
        404 { return 'Unavailable' }
        default { return 'Error' }
    }
}

function Invoke-DERDiscoveryItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Definition,
        [Parameter(Mandatory)][string]$RunId
    )

    $actionId = New-DERDiscoveryActionId -Name $Definition.Key
    $started = Get-Date
    Write-DERDiscoveryLog -Level DEBUG -ActionId $actionId -Message ("Scanning {0}." -f $Definition.Key) -Data $Definition

    try {
        if ($Definition.Mode -eq 'Collection') {
            $data = @(Invoke-DERGraphCollectionRequest -Uri $Definition.Uri -ApiVersion $Definition.Api -ActionId $actionId -Component ('Discovery.{0}' -f $Definition.Key))
        } else {
            $data = Invoke-DERGraphRequest -Method GET -Uri $Definition.Uri -ApiVersion $Definition.Api -ActionId $actionId -Component ('Discovery.{0}' -f $Definition.Key)
        }

        $duration = [int]((Get-Date) - $started).TotalMilliseconds
        $count = if ($Definition.Mode -eq 'Collection') { @($data).Count } elseif ($null -eq $data) { 0 } else { 1 }
        Write-DERDiscoveryLog -Level OK -ActionId $actionId -Message ("{0} scan complete ({1} item(s))." -f $Definition.Key,$count) -Data @{durationMs=$duration;api=$Definition.Api;count=$count}

        return [pscustomobject][ordered]@{
            Key = $Definition.Key
            Category = $Definition.Category
            ApiVersion = $Definition.Api
            Uri = $Definition.Uri
            Mode = $Definition.Mode
            Critical = [bool]$Definition.Critical
            Snapshot = [bool]$Definition.Snapshot
            Status = 'Success'
            StatusCode = 200
            Count = $count
            DurationMs = $duration
            Error = $null
            Data = $data
        }
    } catch {
        $duration = [int]((Get-Date) - $started).TotalMilliseconds
        $statusCode = Get-DERExceptionStatusCode -ErrorRecord $_
        $state = Get-DERDiscoveryFailureState -StatusCode $statusCode
        $level = if ($Definition.Critical) { 'ERROR' } else { 'WARN' }
        Write-DERDiscoveryLog -Level $level -ActionId $actionId -Message ("{0} scan did not complete: {1}" -f $Definition.Key,$_.Exception.Message) -Data @{statusCode=$statusCode;state=$state;durationMs=$duration;api=$Definition.Api;uri=$Definition.Uri}

        if ($Definition.Critical) {
            # Critical discovery failures are still returned to the caller so the
            # analysis/report can explain them. The parent decides whether a
            # later stage can continue.
        }

        return [pscustomobject][ordered]@{
            Key = $Definition.Key
            Category = $Definition.Category
            ApiVersion = $Definition.Api
            Uri = $Definition.Uri
            Mode = $Definition.Mode
            Critical = [bool]$Definition.Critical
            Snapshot = [bool]$Definition.Snapshot
            Status = $state
            StatusCode = $statusCode
            Count = 0
            DurationMs = $duration
            Error = $_.Exception.Message
            Data = $null
        }
    }
}

function Get-DERDiscoveryData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)][string]$Key
    )
    if ($Discovery.Collections -is [System.Collections.IDictionary] -and $Discovery.Collections.Contains($Key)) {
        return $Discovery.Collections[$Key]
    }
    if ($Discovery.Singletons -is [System.Collections.IDictionary] -and $Discovery.Singletons.Contains($Key)) {
        return $Discovery.Singletons[$Key]
    }
    return $null
}

function Get-DERLicenseCapabilities {
    [CmdletBinding()]
    param($SubscribedSkus)

    $skuParts = @()
    $planNames = @()
    foreach ($sku in @($SubscribedSkus)) {
        if ($sku.skuPartNumber) { $skuParts += [string]$sku.skuPartNumber }
        foreach ($plan in @($sku.servicePlans)) {
            if ($plan.servicePlanName) { $planNames += [string]$plan.servicePlanName }
        }
    }
    $skuParts = @($skuParts | Sort-Object -Unique)
    $planNames = @($planNames | Sort-Object -Unique)
    $haystack = (($skuParts + $planNames) -join '|').ToUpperInvariant()

    return [pscustomobject][ordered]@{
        Intune = [bool]($haystack -match 'INTUNE')
        EntraP1 = [bool]($haystack -match 'AAD_PREMIUM(\||$)|AAD_PREMIUM_P1|ENTRA.*P1')
        EntraP2 = [bool]($haystack -match 'AAD_PREMIUM_P2|ENTRA.*P2')
        DefenderForEndpoint = [bool]($haystack -match 'MDE|DEFENDER_ENDPOINT|ATP_ENTERPRISE|MICROSOFT_DEFENDER_FOR_ENDPOINT')
        IntuneSuite = [bool]($haystack -match 'INTUNE_SUITE|INTUNESUITE')
        EndpointPrivilegeManagement = [bool]($haystack -match 'ENDPOINT_PRIVILEGE|EPM')
        RemoteHelp = [bool]($haystack -match 'REMOTE_HELP|REMOTEHELP')
        RawSkuPartNumbers = $skuParts
        RawServicePlanNames = $planNames
    }
}

function Get-DERWindowsGeneration {
    [CmdletBinding()]
    param([string]$OperatingSystem,[string]$OperatingSystemVersion)
    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) { return 'Unknown' }
    if ($OperatingSystem -notmatch '(?i)windows') { return 'Other' }
    if ([string]::IsNullOrWhiteSpace($OperatingSystemVersion)) { return 'WindowsUnknown' }

    $match = [regex]::Match($OperatingSystemVersion,'^(\d+)\.(\d+)\.(\d+)')
    if (-not $match.Success) { return 'WindowsUnknown' }
    $build = 0
    [void][int]::TryParse($match.Groups[3].Value,[ref]$build)
    if ($build -ge 22000) { return 'Windows11' }
    if ($build -ge 10240) { return 'Windows10' }
    return 'WindowsLegacy'
}

function Get-DERDiscoverySummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Discovery)

    $users = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'Users')
    $groups = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'Groups')
    $devices = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'Devices')
    $managed = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'ManagedDevices')
    $ca = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'ConditionalAccessPolicies')
    $compliance = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'CompliancePolicies')
    $config = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'ConfigurationPolicies')
    $classicConfig = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'DeviceConfigurations')
    $autopilot = @(Get-DERDiscoveryData -Discovery $Discovery -Key 'AutopilotDevices')

    $windows10 = 0; $windows11 = 0; $windowsUnknown = 0
    foreach ($device in $devices) {
        switch (Get-DERWindowsGeneration -OperatingSystem ([string]$device.operatingSystem) -OperatingSystemVersion ([string]$device.operatingSystemVersion)) {
            'Windows10' {$windows10++}
            'Windows11' {$windows11++}
            'WindowsUnknown' {$windowsUnknown++}
        }
    }

    return [pscustomobject][ordered]@{
        Users = $users.Count
        Guests = @($users | Where-Object {$_.userType -eq 'Guest'}).Count
        Groups = $groups.Count
        DynamicGroups = @($groups | Where-Object {@($_.groupTypes) -contains 'DynamicMembership'}).Count
        EntraDevices = $devices.Count
        ManagedDevices = $managed.Count
        Windows10Devices = $windows10
        Windows11Devices = $windows11
        WindowsUnknownDevices = $windowsUnknown
        AutopilotDevices = $autopilot.Count
        ConditionalAccessPolicies = $ca.Count
        CompliancePolicies = $compliance.Count
        ConfigurationPolicies = ($config.Count + $classicConfig.Count)
    }
}

function Invoke-DERTenantDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][string]$RunId,
        [string[]]$OnlyKeys
    )

    if (-not (Test-DERDiscoveryCommand -Name 'Invoke-DERGraphRequest')) {
        throw 'DER Discovery requires DER.Graph.psm1 to be initialized first.'
    }

    $started = Get-Date
    $tenantId = [string]$Session.TenantId
    if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'DER Discovery received a session without a TenantId.' }

    Write-DERDiscoveryLog -Level STEP -Message ("Starting read-only tenant discovery for {0}." -f $tenantId) -Data @{runId=$RunId;account=$Session.Account;tenantName=$Session.TenantName}

    $catalog = @(Get-DERDiscoveryCatalog)
    if ($OnlyKeys -and $OnlyKeys.Count -gt 0) {
        $catalog = @($catalog | Where-Object {$OnlyKeys -contains $_.Key})
    }

    $resourceResults = [ordered]@{}
    $collections = [ordered]@{}
    $singletons = [ordered]@{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $criticalFailures = New-Object System.Collections.Generic.List[object]

    foreach ($definition in $catalog) {
        $result = Invoke-DERDiscoveryItem -Definition $definition -RunId $RunId
        $resourceResults[$definition.Key] = [pscustomobject][ordered]@{
            Key=$result.Key;Category=$result.Category;ApiVersion=$result.ApiVersion;Uri=$result.Uri;Mode=$result.Mode;
            Critical=$result.Critical;Snapshot=$result.Snapshot;Status=$result.Status;StatusCode=$result.StatusCode;
            Count=$result.Count;DurationMs=$result.DurationMs;Error=$result.Error
        }

        if ($result.Status -eq 'Success') {
            if ($definition.Mode -eq 'Collection') { $collections[$definition.Key] = @($result.Data) }
            else { $singletons[$definition.Key] = $result.Data }
        } else {
            if ($definition.Mode -eq 'Collection') { $collections[$definition.Key] = @() }
            else { $singletons[$definition.Key] = $null }
            $warnings.Add(("{0}: {1}" -f $definition.Key,$result.Status))
            if([bool]$definition.Critical){$criticalFailures.Add($result)}
        }
    }

    if($criticalFailures.Count -gt 0){
        $detail=@($criticalFailures|ForEach-Object{"$($_.Key)=$($_.Status) HTTP=$($_.StatusCode): $($_.Error)"}) -join '; '
        throw "DER discovery failed closed because one or more critical discovery families could not be established. Planning will not continue with an empty substitute. $detail"
    }
    $tenant = $null
    if ($collections.Contains('Tenant')) { $tenant = @($collections['Tenant']) | Select-Object -First 1 }
    if (-not $tenant) { throw 'DER critical Tenant discovery returned no organization object. Planning is blocked.' }

    if ([string]$tenant.id -and [string]$tenant.id -ne $tenantId) {
        throw ("DER Discovery tenant mismatch. Session {0}, discovery {1}." -f $tenantId,$tenant.id)
    }

    $licenses = if ($collections.Contains('Licenses')) { @($collections['Licenses']) } else { @() }
    $capabilities = Get-DERLicenseCapabilities -SubscribedSkus $licenses

    $discovery = [pscustomobject][ordered]@{
        SchemaVersion = '1.0'
        RunId = $RunId
        TenantId = $tenantId
        TenantName = if ($tenant.displayName) {[string]$tenant.displayName} else {[string]$Session.TenantName}
        Account = [string]$Session.Account
        Environment = [string]$Session.Environment
        StartedAt = $started
        CompletedAt = Get-Date
        DurationMs = 0
        Tenant = $tenant
        Capabilities = $capabilities
        Summary = $null
        ResourceStatus = $resourceResults
        Collections = $collections
        Singletons = $singletons
        Warnings = @($warnings)
        DiscoveryCatalog = @($catalog | ForEach-Object {
            [pscustomobject]@{Key=$_.Key;Category=$_.Category;Mode=$_.Mode;ApiVersion=$_.Api;Uri=$_.Uri;Critical=$_.Critical;Snapshot=$_.Snapshot}
        })
    }
    $discovery.DurationMs = [int]($discovery.CompletedAt - $started).TotalMilliseconds
    $discovery.Summary = Get-DERDiscoverySummary -Discovery $discovery

    $successful = @($resourceResults.Values | Where-Object {$_.Status -eq 'Success'}).Count
    $failed = $resourceResults.Count - $successful
    Write-DERDiscoveryLog -Level OK -Message ("Tenant discovery complete: {0} resource families succeeded, {1} unavailable/denied/failed." -f $successful,$failed) -Data @{summary=$discovery.Summary;capabilities=$capabilities;warnings=$warnings;durationMs=$discovery.DurationMs}

    return $discovery
}

Export-ModuleMember -Function @(
    'Get-DERDiscoveryCatalog','Get-DERDiscoveryData','Get-DERLicenseCapabilities','Get-DERWindowsGeneration','Get-DERDiscoverySummary','Invoke-DERTenantDiscovery'
)
