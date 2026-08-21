<#
.SYNOPSIS
    DER tenant analysis engine.

.DESCRIPTION
    Interprets discovery and snapshot data before the questionnaire begins.
    Produces environment classification, capability flags, hygiene findings,
    detected conflicts/overlaps, and questionnaire branch hints. This module is
    read-only and never modifies Microsoft 365.

.NOTES
    Required parent entry point: Invoke-DERTenantAnalysis
#>


# Maintenance notes
# Responsibility: Transforms discovery evidence into findings without mutating the tenant.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERAnalysisCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERAnalysisLog {
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        $Data
    )
    if (Test-DERAnalysisCommand -Name 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Analysis' -Message $Message -Data $Data
    }
}

function Get-DERAnalysisData {
    param([Parameter(Mandatory)]$Discovery,[Parameter(Mandatory)][string]$Key)
    if (Test-DERAnalysisCommand -Name 'Get-DERDiscoveryData') {
        return Get-DERDiscoveryData -Discovery $Discovery -Key $Key
    }
    if ($Discovery.Collections -is [System.Collections.IDictionary] -and $Discovery.Collections.Contains($Key)) { return $Discovery.Collections[$Key] }
    if ($Discovery.Singletons -is [System.Collections.IDictionary] -and $Discovery.Singletons.Contains($Key)) { return $Discovery.Singletons[$Key] }
    return $null
}

function New-DERFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Recommendation,
        [string]$SourceKey,
        [string]$ObjectId,
        [string]$ObjectName,
        [string]$FindingType='Observation'
    )
    return [pscustomobject][ordered]@{
        FindingId = ('DER-FIND-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0,10).ToUpperInvariant()))
        Severity = $Severity
        Category = $Category
        FindingType = $FindingType
        Title = $Title
        Detail = $Detail
        Recommendation = $Recommendation
        SourceKey = $SourceKey
        ObjectId = $ObjectId
        ObjectName = $ObjectName
    }
}

function Test-DERVagueName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $trim = $Name.Trim()
    if ($trim.Length -lt 3) { return $true }
    return [bool]($trim -match '(?i)^(test|testing|new policy|policy ?\d*|profile ?\d*|copy of|copy |temp|temporary|untitled|default policy|new profile|configuration policy)$')
}

function Get-DERObjectName {
    param($Object)
    foreach ($propertyName in @('displayName','name','description')) {
        if ($Object -and $Object.PSObject.Properties.Name -contains $propertyName -and $Object.$propertyName) { return [string]$Object.$propertyName }
    }
    return $null
}


function Get-DERAutopatchIndicators {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Discovery)

    # Windows Autopatch creates/uses Entra groups and Intune update policies.
    # DER treats display-name matches only as preservation indicators, never as
    # proof of ownership or permission to modify an object.
    $sources = @(
        [pscustomobject]@{Key='Groups';Items=@(Get-DERAnalysisData -Discovery $Discovery -Key 'Groups')},
        [pscustomobject]@{Key='DeviceConfigurations';Items=@(Get-DERAnalysisData -Discovery $Discovery -Key 'DeviceConfigurations')},
        [pscustomobject]@{Key='ConfigurationPolicies';Items=@(Get-DERAnalysisData -Discovery $Discovery -Key 'ConfigurationPolicies')},
        [pscustomobject]@{Key='FeatureUpdateProfiles';Items=@(Get-DERAnalysisData -Discovery $Discovery -Key 'FeatureUpdateProfiles')},
        [pscustomobject]@{Key='DriverUpdateProfiles';Items=@(Get-DERAnalysisData -Discovery $Discovery -Key 'DriverUpdateProfiles')}
    )

    $indicators = New-Object System.Collections.Generic.List[object]
    foreach ($source in $sources) {
        foreach ($item in @($source.Items)) {
            $name = Get-DERObjectName -Object $item
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($name -match '(?i)\bwindows\s+autopatch\b|\bautopatch\b') {
                $indicators.Add([pscustomobject][ordered]@{
                    SourceKey = $source.Key
                    ObjectId = if ($item.PSObject.Properties.Name -contains 'id') {[string]$item.id} else {$null}
                    ObjectName = [string]$name
                })
            }
        }
    }

    return @($indicators | Sort-Object SourceKey,ObjectName -Unique)
}

function Get-DEREnvironmentClassification {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Discovery)

    $summary = $Discovery.Summary
    $policyCount = [int]$summary.ConditionalAccessPolicies + [int]$summary.CompliancePolicies + [int]$summary.ConfigurationPolicies
    $managed = [int]$summary.ManagedDevices
    $users = [int]$summary.Users

    if ($managed -eq 0 -and $policyCount -eq 0 -and $users -le 5) { return 'NewOrMostlyEmpty' }
    if ($managed -le 5 -and $policyCount -le 2) { return 'LightlyConfigured' }
    return 'ExistingProductionLikely'
}

function Get-DERMDMScopeAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Discovery)
    $policies = @(Get-DERAnalysisData -Discovery $Discovery -Key 'MobileDeviceManagementPolicies')
    if ($policies.Count -eq 0) { return [pscustomobject]@{Detected=$false;AppliesTo=$null;PolicyId=$null;IncludedGroups=@();Valid=$null} }
    $policy = @($policies | Where-Object {$_.displayName -match '(?i)intune'} | Select-Object -First 1)
    if (-not $policy) { $policy = @($policies | Select-Object -First 1) }
    if (-not $policy) { return [pscustomobject]@{Detected=$false;AppliesTo=$null;PolicyId=$null;IncludedGroups=@();Valid=$null} }
    $included = @()
    foreach ($g in @($policy.includedGroups)) { if ($g.id) { $included += [string]$g.id } }
    return [pscustomobject][ordered]@{
        Detected=$true;AppliesTo=[string]$policy.appliesTo;PolicyId=[string]$policy.id;DisplayName=[string]$policy.displayName;
        IncludedGroups=@($included);Valid=if ($policy.PSObject.Properties.Name -contains 'isValid') {[bool]$policy.isValid} else {$null};
        IsMdmEnrollmentDuringRegistrationDisabled=if ($policy.PSObject.Properties.Name -contains 'isMdmEnrollmentDuringRegistrationDisabled') {$policy.isMdmEnrollmentDuringRegistrationDisabled} else {$null}
    }
}

function Get-DERAssignmentCountMap {
    param([Parameter(Mandatory)]$Snapshot)
    $map = @{}
    foreach ($record in @($Snapshot.AssignmentResults)) {
        if ($record.Status -eq 'Success' -and $record.ObjectId) {
            $map[[string]$record.ObjectId] = [int]$record.Count
        }
    }
    return $map
}

function Add-DERPolicyHygieneFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Findings
    )

    $families = @('ConditionalAccessPolicies','CompliancePolicies','DeviceConfigurations','ConfigurationPolicies','GroupPolicyConfigurations','EndpointSecurityIntents','AutopilotProfiles','FeatureUpdateProfiles','DriverUpdateProfiles')
    $assignmentMap = Get-DERAssignmentCountMap -Snapshot $Snapshot

    foreach ($family in $families) {
        $objects = @(Get-DERAnalysisData -Discovery $Discovery -Key $family)
        if ($objects.Count -eq 0) { continue }

        $named = foreach ($object in $objects) {
            [pscustomobject]@{Object=$object;Name=(Get-DERObjectName -Object $object);Id=[string]$object.id}
        }

        foreach ($entry in $named) {
            if (Test-DERVagueName -Name $entry.Name) {
                $Findings.Add((New-DERFinding -Severity 'Low' -Category 'Tenant Hygiene' -FindingType 'Naming' -Title 'Vague or placeholder object name detected' -Detail ("{0} contains an object named '{1}' that may be difficult to understand later." -f $family,$entry.Name) -Recommendation 'Review and document the object. DER will not rename customer-owned objects.' -SourceKey $family -ObjectId $entry.Id -ObjectName $entry.Name))
            }
            if ($entry.Id -and $assignmentMap.ContainsKey($entry.Id) -and $assignmentMap[$entry.Id] -eq 0) {
                $Findings.Add((New-DERFinding -Severity 'Low' -Category 'Tenant Hygiene' -FindingType 'Unassigned' -Title 'Unassigned policy/profile detected' -Detail ("'{0}' currently has no captured assignments." -f $entry.Name) -Recommendation 'Confirm whether the object is intentionally staged, unused, or a placeholder. DER will not delete it.' -SourceKey $family -ObjectId $entry.Id -ObjectName $entry.Name))
            }
        }

        $duplicates = @($named | Where-Object {-not [string]::IsNullOrWhiteSpace($_.Name)} | Group-Object { $_.Name.Trim().ToLowerInvariant() } | Where-Object {$_.Count -gt 1})
        foreach ($duplicate in $duplicates) {
            $names = @($duplicate.Group | ForEach-Object {$_.Name}) -join ', '
            $Findings.Add((New-DERFinding -Severity 'Medium' -Category 'Tenant Hygiene' -FindingType 'DuplicateName' -Title 'Duplicate-looking policy names detected' -Detail ("{0} contains {1} objects with the same display name: {2}" -f $family,$duplicate.Count,$names) -Recommendation 'Compare actual settings and assignments. Same names do not prove identical configuration.' -SourceKey $family))
        }
    }
}

function Add-DERScanGapFindings {
    param([Parameter(Mandatory)]$Discovery,[Parameter(Mandatory)][System.Collections.Generic.List[object]]$Findings)
    foreach ($key in $Discovery.ResourceStatus.Keys) {
        $status = $Discovery.ResourceStatus[$key]
        if ($status.Status -eq 'Success') { continue }
        $severity = if ($status.Critical) {'High'} elseif ($status.Status -eq 'PermissionDenied') {'Low'} else {'Informational'}
        $Findings.Add((New-DERFinding -Severity $severity -Category 'Discovery' -FindingType 'ScanGap' -Title ("Discovery incomplete: {0}" -f $key) -Detail ("DER could not read {0}. State: {1}. {2}" -f $key,$status.Status,$status.Error) -Recommendation 'The questionnaire/build will avoid assuming this feature is absent. Missing read permission or licensing may need review.' -SourceKey $key))
    }
}

function Invoke-DERTenantAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$RunId
    )

    $started = Get-Date
    Write-DERAnalysisLog -Level STEP -Message 'Analyzing tenant discovery and PRE-BUILD snapshot.' -Data @{runId=$RunId;tenantId=$Discovery.TenantId}
    $findings = New-Object System.Collections.Generic.List[object]

    $classification = Get-DEREnvironmentClassification -Discovery $Discovery
    $capabilities = $Discovery.Capabilities
    $summary = $Discovery.Summary

    Add-DERScanGapFindings -Discovery $Discovery -Findings $findings
    Add-DERPolicyHygieneFindings -Discovery $Discovery -Snapshot $Snapshot -Findings $findings

    if ([int]$summary.Windows10Devices -gt 0) {
        $findings.Add((New-DERFinding -Severity 'Medium' -Category 'Windows' -FindingType 'LegacyOS' -Title 'Windows 10 devices detected' -Detail ("DER detected {0} Entra device object(s) that appear to be Windows 10." -f $summary.Windows10Devices) -Recommendation 'DER v1 is Windows 11 focused. Existing Windows 10 should be reported and reviewed before enforcing new enrollment restrictions.' -SourceKey 'Devices'))
    }

    $securityDefaults = Get-DERAnalysisData -Discovery $Discovery -Key 'SecurityDefaults'
    $securityDefaultsEnabled = $null
    if ($securityDefaults -and $securityDefaults.PSObject.Properties.Name -contains 'isEnabled') {
        $securityDefaultsEnabled = [bool]$securityDefaults.isEnabled
        if ($securityDefaultsEnabled) {
            $findings.Add((New-DERFinding -Severity 'Informational' -Category 'Identity Security' -FindingType 'SecurityDefaults' -Title 'Security Defaults is enabled' -Detail 'DER will preserve Security Defaults while DER Conditional Access policies remain Report-only.' -Recommendation 'Transition only after emergency access is complete and Report-only Conditional Access impact is reviewed.' -SourceKey 'SecurityDefaults'))
        }
    }

    $caPolicies = @(Get-DERAnalysisData -Discovery $Discovery -Key 'ConditionalAccessPolicies')
    $caEnabled = @($caPolicies | Where-Object {$_.state -eq 'enabled'}).Count
    $caReportOnly = @($caPolicies | Where-Object {$_.state -eq 'enabledForReportingButNotEnforced'}).Count
    if ($caEnabled -gt 0) {
        $findings.Add((New-DERFinding -Severity 'Medium' -Category 'Conditional Access' -FindingType 'ExistingEnforcement' -Title 'Existing enforced Conditional Access policies detected' -Detail ("{0} existing Conditional Access policy/policies are enabled." -f $caEnabled) -Recommendation 'DER will inventory and compare them but will not modify them unless explicitly adopted.' -SourceKey 'ConditionalAccessPolicies'))
    }

    $mdm = Get-DERMDMScopeAnalysis -Discovery $Discovery
    if ($mdm.Detected -and $mdm.AppliesTo -eq 'none') {
        $findings.Add((New-DERFinding -Severity 'Medium' -Category 'Enrollment' -FindingType 'MDMScope' -Title 'Automatic MDM enrollment scope is None' -Detail 'Microsoft Intune automatic enrollment is not currently scoped to users through this policy.' -Recommendation 'DER can propose Selected scope using the DER Intune Enrollment group, subject to explicit engineer approval.' -SourceKey 'MobileDeviceManagementPolicies' -ObjectId $mdm.PolicyId -ObjectName $mdm.DisplayName))
    }

    $autopilotProfiles = @(Get-DERAnalysisData -Discovery $Discovery -Key 'AutopilotProfiles')
    $autopilotDevices = @(Get-DERAnalysisData -Discovery $Discovery -Key 'AutopilotDevices')
    $autopatchIndicators = @(Get-DERAutopatchIndicators -Discovery $Discovery)
    if ($autopatchIndicators.Count -gt 0) {
        $sampleNames = @($autopatchIndicators | Select-Object -First 5 | ForEach-Object { $_.ObjectName }) -join ', '
        $findings.Add((New-DERFinding -Severity 'Informational' -Category 'Windows Updates' -FindingType 'AutopatchIndicator' -Title 'Windows Autopatch indicators detected' -Detail ("DER found {0} group/update-policy name(s) containing an Autopatch indicator. Examples: {1}" -f $autopatchIndicators.Count,$sampleNames) -Recommendation 'Treat this as a preservation signal, not ownership proof. DER will default to preserving existing Autopatch-managed update configuration and ask the engineer before creating overlapping update policies.' -SourceKey 'Updates'))
    }
    if ($autopilotProfiles.Count -gt 0) {
        $findings.Add((New-DERFinding -Severity 'Informational' -Category 'Autopilot' -FindingType 'ExistingConfiguration' -Title 'Existing Autopilot profiles detected' -Detail ("DER found {0} Autopilot deployment profile(s)." -f $autopilotProfiles.Count) -Recommendation 'Compare existing profiles with the DER proposal; do not assume naming equals configuration.' -SourceKey 'AutopilotProfiles'))
    }

    $roleDefinitions = @(Get-DERAnalysisData -Discovery $Discovery -Key 'DirectoryRoleDefinitions')
    $roleAssignments = @(Get-DERAnalysisData -Discovery $Discovery -Key 'DirectoryRoleAssignments')
    $gaDefinition = @($roleDefinitions | Where-Object {$_.displayName -eq 'Global Administrator'} | Select-Object -First 1)
    $gaCount = 0
    if ($gaDefinition) { $gaCount = @($roleAssignments | Where-Object {$_.roleDefinitionId -eq $gaDefinition.id}).Count }
    if ($gaCount -ge 5) {
        $findings.Add((New-DERFinding -Severity 'Medium' -Category 'Privileged Access' -FindingType 'AdminCount' -Title 'High number of permanent Global Administrator assignments detected' -Detail ("DER found {0} active role assignment(s) for Global Administrator in the readable assignment set." -f $gaCount) -Recommendation 'Review least privilege and PIM eligibility. DER will not remove or change existing administrators.' -SourceKey 'DirectoryRoleAssignments'))
    }

    $branchHints = [pscustomobject][ordered]@{
        ExistingTenant = ($classification -ne 'NewOrMostlyEmpty')
        NewOrMostlyEmpty = ($classification -eq 'NewOrMostlyEmpty')
        HasIntune = [bool]$capabilities.Intune
        HasEntraP1 = [bool]$capabilities.EntraP1
        HasEntraP2 = [bool]$capabilities.EntraP2
        HasDefenderForEndpoint = [bool]$capabilities.DefenderForEndpoint
        HasIntuneSuite = [bool]$capabilities.IntuneSuite
        HasRemoteHelp = [bool]$capabilities.RemoteHelp
        HasEndpointPrivilegeManagement = [bool]$capabilities.EndpointPrivilegeManagement
        HasWindows10 = ([int]$summary.Windows10Devices -gt 0)
        HasWindows11 = ([int]$summary.Windows11Devices -gt 0)
        HasAutopilotDevices = ($autopilotDevices.Count -gt 0)
        HasAutopilotProfiles = ($autopilotProfiles.Count -gt 0)
        HasAutopatch = ($autopatchIndicators.Count -gt 0)
        AutopatchIndicators = @($autopatchIndicators)
        HasExistingConditionalAccess = ($caPolicies.Count -gt 0)
        SecurityDefaultsEnabled = $securityDefaultsEnabled
        MDMScope = $mdm.AppliesTo
        HasGuests = ([int]$summary.Guests -gt 0)
        AskAboutPIM = [bool]$capabilities.EntraP2
        AskAboutRiskPolicies = [bool]$capabilities.EntraP2
        AskAboutDefender = [bool]$capabilities.DefenderForEndpoint
        AskAboutExistingTenantConflicts = ($classification -ne 'NewOrMostlyEmpty')
    }

    $severityCounts = [ordered]@{}
    foreach ($severity in @('Critical','High','Medium','Low','Informational')) {
        $severityCounts[$severity] = @($findings | Where-Object {$_.Severity -eq $severity}).Count
    }

    $completed = Get-Date
    $analysis = [pscustomobject][ordered]@{
        SchemaVersion='1.0';RunId=$RunId;TenantId=$Discovery.TenantId;TenantName=$Discovery.TenantName;
        StartedAt=$started;CompletedAt=$completed;DurationMs=[int]($completed-$started).TotalMilliseconds;
        EnvironmentClassification=$classification;Summary=$summary;Capabilities=$capabilities;MDMScope=$mdm;
        ConditionalAccess=[pscustomobject]@{Total=$caPolicies.Count;Enabled=$caEnabled;ReportOnly=$caReportOnly;Disabled=@($caPolicies|Where-Object {$_.state -eq 'disabled'}).Count};
        Autopilot=[pscustomobject]@{Profiles=$autopilotProfiles.Count;Devices=$autopilotDevices.Count};
        Autopatch=[pscustomobject]@{IndicatorsDetected=($autopatchIndicators.Count -gt 0);IndicatorCount=$autopatchIndicators.Count;Indicators=@($autopatchIndicators)};
        PrivilegedAccess=[pscustomobject]@{GlobalAdministratorAssignments=$gaCount};
        BranchHints=$branchHints;SeverityCounts=[pscustomobject]$severityCounts;Findings=@($findings);
        SnapshotRoot=$Snapshot.RootPath
    }

    $level = if ($severityCounts.Critical -gt 0 -or $severityCounts.High -gt 0) {'WARN'} else {'OK'}
    Write-DERAnalysisLog -Level $level -Message ("Tenant analysis complete: {0} finding(s), classification {1}." -f $findings.Count,$classification) -Data @{severityCounts=$severityCounts;branchHints=$branchHints;summary=$summary}
    return $analysis
}

Export-ModuleMember -Function @(
    'New-DERFinding','Test-DERVagueName','Get-DERAutopatchIndicators','Get-DEREnvironmentClassification','Get-DERMDMScopeAnalysis','Invoke-DERTenantAnalysis'
)
