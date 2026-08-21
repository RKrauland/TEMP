<#
.SYNOPSIS
    DER build-plan compiler.

.DESCRIPTION
    Converts discovery, analysis, and engineer answers into a deterministic,
    non-writing build plan. The plan is the single source of truth for later
    permission resolution, dry-run validation, workload execution, reporting,
    and the tenant build recipe.

.NOTES
    Required parent entry point: New-DERBuildPlan
#>


# Maintenance notes
# Responsibility: Converts baseline plus questionnaire into deterministic DER object/action intent. Planner DER IDs are part of the immutable baseline contract.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERPlannerCommand {param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue)}
function Write-DERPlannerLog {param([string]$Level,[string]$Message,$Data) if (Test-DERPlannerCommand 'Write-DERLog'){Write-DERLog -Level $Level -Component 'Planner' -Message $Message -Data $Data}}

function New-DERPlannedObject {
    param([string]$DerId,[string]$Module,[string]$ObjectType,[string]$DisplayName,[string]$Action='Create',[string]$SafeState='Pilot/Empty',[bool]$Enabled=$true,$Metadata)
    return [pscustomobject][ordered]@{DerId=$DerId;Module=$Module;ObjectType=$ObjectType;DisplayName=$DisplayName;Action=$Action;Enabled=$Enabled;SafeState=$SafeState;Metadata=$Metadata}
}

function New-DERManualAction {
    param([string]$Id,[string]$Category,[string]$Title,[string]$Reason,[string]$Priority='Normal',$Metadata)
    return [pscustomobject][ordered]@{Id=$Id;Category=$Category;Title=$Title;Reason=$Reason;Priority=$Priority;Metadata=$Metadata}
}

function Add-DERGroupObjects {
    param($Answers,[System.Collections.Generic.List[object]]$Objects)
    $a=$Answers.Organization.Acronym
    if (-not $Answers.Infrastructure.CreateCoreGroups) {return}
    $groups=@(
        @('DER-GRP-D-010','ABC - SG - Device - 010 - Pilot','Device'),
        @('DER-GRP-U-010','ABC - SG - User - 010 - Pilot','User'),
        @('DER-GRP-D-020','ABC - SG - Device - 020 - Production','Device'),
        @('DER-GRP-U-020','ABC - SG - User - 020 - Production','User'),
        @('DER-GRP-U-030','ABC - SG - User - 030 - Emergency Access','User'),
        @('DER-GRP-U-040','ABC - SG - User - 040 - Intune Administrators','User'),
        @('DER-GRP-U-050','ABC - SG - User - 050 - Intune Help Desk','User'),
        @('DER-GRP-U-060','ABC - SG - User - 060 - Intune Read Only','User'),
        @('DER-GRP-U-070','ABC - SG - User - 070 - Local Device Administrators','User'),
        @('DER-GRP-U-080','ABC - SG - User - 080 - Intune Enrollment','User'),
        @('DER-GRP-U-090','ABC - SG - User - 090 - SSPR Pilot','User')
    )
    foreach($g in $groups){$Objects.Add((New-DERPlannedObject -DerId $g[0] -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ($g[1] -replace '^ABC',$a) -Metadata @{Membership='Assigned';PrincipalType=$g[2]}))}
    if ($Answers.Infrastructure.CreateGeoCAP) {$Objects.Add((New-DERPlannedObject -DerId 'DER-GRP-U-100' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - User - 100 - International Travel") -Metadata @{Membership='Assigned';PrincipalType='User'}))}
    if ($Answers.Identity.ConfigureGuests) {$Objects.Add((New-DERPlannedObject -DerId 'DER-GRP-U-110' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - User - 110 - Guest Inviters") -Metadata @{Membership='Assigned';PrincipalType='User'}))}
    if ($Answers.Enrollment.SharedDevices) {$Objects.Add((New-DERPlannedObject -DerId 'DER-GRP-D-140' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - Device - 140 - Shared Devices") -Metadata @{Membership='Assigned';PrincipalType='Device'}))}
    if ($Answers.Enrollment.SelfDeploying) {$Objects.Add((New-DERPlannedObject -DerId 'DER-GRP-D-150' -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - Device - 150 - Autopilot Self Deploying") -Metadata @{Membership='Assigned';PrincipalType='Device';Purpose='AutopilotSelfDeploying'}))}
    if ($Answers.Infrastructure.CreateExclusionGroups) {
        foreach($g in @(
            @('DER-GRP-D-100','Exclude Compliance'),@('DER-GRP-D-110','Exclude Configuration'),@('DER-GRP-D-120','Exclude Endpoint Security'),@('DER-GRP-D-130','Exclude Windows Update')
        )) {$Objects.Add((New-DERPlannedObject -DerId $g[0] -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - Device - $($g[0].Substring($g[0].Length-3)) - $($g[1])") -Metadata @{Membership='Assigned';PrincipalType='Device';Purpose='Exclusion'}))}
    }
    if ($Answers.Infrastructure.CreateDynamicInventoryGroups) {
        $dyn=@(
            @('DER-GRP-DY-D-010','Windows 11'),@('DER-GRP-DY-D-020','Windows 10'),@('DER-GRP-DY-D-030','macOS'),@('DER-GRP-DY-D-040','Autopilot Windows'),@('DER-GRP-DY-D-050','iOS iPadOS'),@('DER-GRP-DY-D-060','Android')
        )
        foreach($g in $dyn){$Objects.Add((New-DERPlannedObject -DerId $g[0] -Module 'Groups' -ObjectType 'DynamicSecurityGroup' -DisplayName ("$a - SG - Dynamic - Device - $($g[0].Substring($g[0].Length-3)) - $($g[1])") -Metadata @{Membership='Dynamic';PrincipalType='Device'}))}
    }
    if ($Answers.Infrastructure.CreateDepartmentGroups) {
        $i=200
        foreach($d in @($Answers.Infrastructure.Departments)){$Objects.Add((New-DERPlannedObject -DerId ("DER-GRP-U-{0}" -f $i) -Module 'Groups' -ObjectType 'SecurityGroup' -DisplayName ("$a - SG - User - $i - Department - $d") -Metadata @{Membership='Assigned';PrincipalType='User';Department=$d}));$i+=10}
    }
}

function Add-DERWorkloadObjects {
    param($Answers,$Analysis,[System.Collections.Generic.List[object]]$Objects,[System.Collections.Generic.List[object]]$Manual)
    $a=$Answers.Organization.Acronym
    if ($Answers.Enrollment.UseEnrollmentGroup) {$Objects.Add((New-DERPlannedObject -DerId 'DER-ENTRA-010' -Module 'EntraDevice' -ObjectType 'DeviceRegistrationPolicy' -DisplayName 'Microsoft Entra device registration policy' -Action 'Configure' -SafeState 'Explicit approval required'))}
    $Objects.Add((New-DERPlannedObject -DerId 'DER-ENR-010' -Module 'Enrollment' -ObjectType 'EnrollmentRestriction' -DisplayName ("$a - ENR - 010 - Windows Corporate Enrollment") -SafeState 'Enrollment Users group only'))
    $Objects.Add((New-DERPlannedObject -DerId 'DER-ENR-020' -Module 'Enrollment' -ObjectType 'EnrollmentLimit' -DisplayName ("$a - ENR - 020 - Device Enrollment Limit") -SafeState 'Enrollment Users group only'))
    if ($Answers.Enrollment.UseAutopilot) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-AP-010' -Module 'Autopilot' -ObjectType 'AutopilotProfile' -DisplayName ("$a - AP - 010 - User Driven") -SafeState 'Assigned only to DER Autopilot group'))
        $Objects.Add((New-DERPlannedObject -DerId 'DER-ESP-010' -Module 'Autopilot' -ObjectType 'EnrollmentStatusPage' -DisplayName ("$a - ESP - 010 - Windows Autopilot") -SafeState 'Assigned only to DER Autopilot group'))
        # Pre-provisioning is enabled on DER-AP-010 via preprovisioningAllowed; it is not a separate Autopilot profile.
        if ($Answers.Enrollment.SelfDeploying){$Objects.Add((New-DERPlannedObject -DerId 'DER-AP-030' -Module 'Autopilot' -ObjectType 'AutopilotProfile' -DisplayName ("$a - AP - 030 - Self Deploying") -SafeState 'Assigned only to empty DER self-deploying group'))}
        if ($Answers.Enrollment.AutopilotRegistrationSource -in @('Need manual hash collection','Unknown')) {$Manual.Add((New-DERManualAction -Id 'MAN-AP-001' -Category 'Autopilot' -Title 'Register Autopilot hardware' -Reason 'DER cannot obtain hardware hashes from devices it cannot access.' -Priority 'High'))}
    }
    if ($Answers.Security.CreateCompliance){$Objects.Add((New-DERPlannedObject -DerId 'DER-COMP-010' -Module 'Compliance' -ObjectType 'CompliancePolicy' -DisplayName ("$a - COMP - 010 - Windows 11 Standard") -SafeState 'Pilot only'))}
    if ($Answers.Security.CreateBitLocker){$Objects.Add((New-DERPlannedObject -DerId 'DER-BL-010' -Module 'BitLocker' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - BL - 010 - Windows BitLocker") -SafeState 'Pilot only'))}
    if ($Answers.Security.CreateLAPS){$Objects.Add((New-DERPlannedObject -DerId 'DER-LAPS-010' -Module 'LAPS' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - LAPS - 010 - Windows Local Administrator") -SafeState 'Pilot only / tenant switch approval'))}
    if ($Answers.Security.CreateDefender){$Objects.Add((New-DERPlannedObject -DerId 'DER-SEC-010' -Module 'Defender' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - SEC - 010 - Microsoft Defender Antivirus") -SafeState 'Pilot only'))}
    if ($Answers.Security.CreateASR){$Objects.Add((New-DERPlannedObject -DerId 'DER-ASR-010' -Module 'ASR' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - ASR - 010 - Attack Surface Reduction") -SafeState 'Audit-first/Pilot'))}
    if ($Answers.Security.CreateNetworkProtection){$Objects.Add((New-DERPlannedObject -DerId 'DER-ASR-020' -Module 'ASR' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - ASR - 020 - Network Protection") -SafeState 'Audit'))}
    if ($Answers.Security.CreateCFA){$Objects.Add((New-DERPlannedObject -DerId 'DER-ASR-030' -Module 'ASR' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - ASR - 030 - Controlled Folder Access") -SafeState 'Audit'))}
    if ($Answers.Security.CreateFirewall){$Objects.Add((New-DERPlannedObject -DerId 'DER-FW-010' -Module 'Firewall' -ObjectType 'EndpointSecurityPolicy' -DisplayName ("$a - FW - 010 - Windows Defender Firewall") -SafeState 'Pilot only'))}
    if ($Answers.Security.CreateVBS){$Objects.Add((New-DERPlannedObject -DerId 'DER-SEC-020' -Module 'Configuration' -ObjectType 'SettingsCatalogPolicy' -DisplayName ("$a - SEC - 020 - Credential Guard and VBS") -SafeState 'Pilot only'))}
    $Objects.Add((New-DERPlannedObject -DerId 'DER-CFG-010' -Module 'Configuration' -ObjectType 'SettingsCatalogPolicy' -DisplayName ("$a - CFG - 010 - Windows Device Lock") -SafeState 'Pilot only'))
    if ($Answers.Enrollment.EnableWHfB){$Objects.Add((New-DERPlannedObject -DerId 'DER-CFG-030' -Module 'Configuration' -ObjectType 'SettingsCatalogPolicy' -DisplayName ("$a - CFG - 030 - Windows Hello for Business") -SafeState 'Pilot only'))}

    $Objects.Add((New-DERPlannedObject -DerId 'DER-AUTH-010' -Module 'AuthenticationMethods' -ObjectType 'AuthenticationMethodsPolicy' -DisplayName 'Microsoft Entra Authentication Methods Policy' -Action 'Configure' -SafeState 'Pilot/scoped where supported'))
    if ($Answers.Identity.EnableSSPRPilot){$Manual.Add((New-DERManualAction -Id 'MAN-SSPR-001' -Category 'Identity' -Title 'Enable SSPR for DER SSPR Pilot group' -Reason 'DER v1 treats ordinary-user SSPR scope enablement as a manual portal action unless a supported API is validated.' -Priority 'High' -Metadata @{Group=("$a - SG - User - 090 - SSPR Pilot")}))}

    if ($Answers.Identity.CreateConditionalAccess) {
        foreach($c in @(
            @('DER-CAP-010','Block Legacy Authentication'),@('DER-CAP-020','Require MFA - All Users'),@('DER-CAP-030','Require Phishing Resistant MFA - Administrators'),@('DER-CAP-040','Protect Security Information Registration'),@('DER-CAP-050','Protect Device Registration'),@('DER-CAP-060','Require Compliant Windows Device'),@('DER-CAP-070','Require Compliant Device - Administrators'),@('DER-CAP-080','Require MFA - Guests'),@('DER-CAP-110','Restrict Authentication Flows')
        )) {$Objects.Add((New-DERPlannedObject -DerId $c[0] -Module 'ConditionalAccess' -ObjectType 'ConditionalAccessPolicy' -DisplayName ("$a - CAP - $($c[0].Substring($c[0].Length-3)) - $($c[1])") -SafeState 'Report-only'))}
        if ($Answers.Identity.CreateRiskCAPs) {
            $Objects.Add((New-DERPlannedObject -DerId 'DER-CAP-090' -Module 'ConditionalAccess' -ObjectType 'ConditionalAccessPolicy' -DisplayName ("$a - CAP - 090 - Protect Risky Sign Ins") -SafeState 'Report-only'))
            $Objects.Add((New-DERPlannedObject -DerId 'DER-CAP-100' -Module 'ConditionalAccess' -ObjectType 'ConditionalAccessPolicy' -DisplayName ("$a - CAP - 100 - Protect High Risk Users") -SafeState 'Report-only'))
        }
        if ($Answers.Infrastructure.CreateGeoCAP){$Objects.Add((New-DERPlannedObject -DerId 'DER-CAP-120' -Module 'ConditionalAccess' -ObjectType 'ConditionalAccessPolicy' -DisplayName ("$a - CAP - 120 - Restrict Unapproved Countries") -SafeState 'Report-only'))}
        $Manual.Add((New-DERManualAction -Id 'MAN-EA-001' -Category 'Emergency Access' -Title 'Create and secure two Emergency Access accounts' -Reason 'DER creates the exclusion framework but does not half-create emergency identities or physical FIDO keys.' -Priority 'Critical'))
    }
    if ($Answers.Infrastructure.CreateGeoCAP){$Objects.Add((New-DERPlannedObject -DerId 'DER-LOC-COUNTRY-010' -Module 'NamedLocations' -ObjectType 'NamedLocation' -DisplayName ("$a - LOC - 910 - Approved Countries") -SafeState 'Not trusted; geographic CA reference only' -Metadata @{Type='Country';Countries=@($Answers.Infrastructure.NormalCountries);IncludeUnknownCountriesAndRegions=$false}))}
    foreach($site in @($Answers.Infrastructure.Sites | Where-Object {$_.CreateNamedLocation})) {$Objects.Add((New-DERPlannedObject -DerId ("DER-LOC-SITE-{0:000}" -f $site.Index) -Module 'NamedLocations' -ObjectType 'NamedLocation' -DisplayName ("$a - LOC - {0:000} - {1}" -f ($site.Index*10),$site.Name) -SafeState 'Not trusted unless explicitly approved' -Metadata $site))}
    if ($Answers.Infrastructure.CorporateVPN -and $Answers.Infrastructure.CorporateVPN.CreateNamedLocation){$Objects.Add((New-DERPlannedObject -DerId 'DER-LOC-VPN-010' -Module 'NamedLocations' -ObjectType 'NamedLocation' -DisplayName ("$a - LOC - 900 - $($Answers.Infrastructure.CorporateVPN.Name)") -SafeState 'Not trusted unless explicitly approved' -Metadata $Answers.Infrastructure.CorporateVPN))}
    if ($Answers.Identity.ConfigureGuests){$Objects.Add((New-DERPlannedObject -DerId 'DER-GUEST-010' -Module 'GuestExternal' -ObjectType 'ExternalCollaborationSettings' -DisplayName 'Microsoft Entra External Collaboration Settings' -Action 'Configure' -SafeState 'Explicit approval'))}
    if ($Answers.Identity.ConfigureGuests){$Manual.Add((New-DERManualAction -Id 'MAN-GUEST-001' -Category 'Guest Access' -Title 'Assign Guest Inviter role to approved guest inviters' -Reason 'The DER Guest Inviters security group is an administrative reference group; DER does not assume it is role-assignable. Deliberately grant the Microsoft Entra Guest Inviter role to the intended approved users, or create an approved role-assignable group separately.' -Priority 'Normal' -Metadata @{Group=("$a - SG - User - 110 - Guest Inviters")}))}
    if ($Answers.Identity.ConfigureCrossTenant){$Objects.Add((New-DERPlannedObject -DerId 'DER-XTENANT-010' -Module 'GuestExternal' -ObjectType 'CrossTenantAccessPolicy' -DisplayName 'Microsoft Entra Cross-Tenant Access' -Action 'Configure' -SafeState 'Explicit partner-by-partner approval'))}
    if ($Answers.Identity.ConfigureCrossTenant){$Manual.Add((New-DERManualAction -Id 'MAN-XTENANT-001' -Category 'External Collaboration' -Title 'Approve partner-by-partner cross-tenant trust settings' -Reason 'DER will not infer inbound MFA, compliant-device, hybrid-join, or collaboration trust for partner tenants without explicit engineer choices.' -Priority 'High' -Metadata @{Partners=@($Answers.Identity.PartnerTenants)}))}
    if ($Answers.Identity.EnableAdminConsentWorkflow){$Objects.Add((New-DERPlannedObject -DerId 'DER-CONSENT-010' -Module 'AppConsent' -ObjectType 'AdminConsentRequestPolicy' -DisplayName 'Microsoft Entra Admin Consent Workflow' -Action 'Configure' -SafeState 'Reviewers required'))}
    if ($Answers.Identity.EnableCustomPasswordProtection){$Manual.Add((New-DERManualAction -Id 'MAN-PASS-001' -Category 'Identity' -Title 'Configure custom Microsoft Entra Password Protection terms' -Reason 'DER did not validate a supported Microsoft Graph write API for the custom banned-password list; per DER safety rules this remains manual.' -Priority 'Normal' -Metadata @{SuggestedTerms=@($Answers.Organization.Name,$Answers.Organization.Acronym)}))}
    if ($Answers.Identity.ConfigurePIM){$Objects.Add((New-DERPlannedObject -DerId 'DER-PIM-010' -Module 'PIM' -ObjectType 'PrivilegedRolePolicy' -DisplayName 'Microsoft Entra PIM Baseline' -Action 'Configure' -SafeState 'Eligible/JIT; selected roles only'))}
    if ($Answers.Identity.ConfigurePIM -and $Answers.Identity.PIMRequireApproval){$Manual.Add((New-DERManualAction -Id 'MAN-PIM-APPROVER-001' -Category 'PIM' -Title 'Select PIM activation approvers' -Reason 'PIM approval was requested, but DER requires explicit approver identities or groups before enabling an approval rule.' -Priority 'High'))}

    if ($Answers.Updates.CreateUpdateRings -and -not $Answers.Updates.PreserveAutopatch) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-WU-010' -Module 'Updates' -ObjectType 'UpdateRing' -DisplayName ("$a - WU - 010 - Windows Update - Pilot") -SafeState 'Pilot group'))
        $Objects.Add((New-DERPlannedObject -DerId 'DER-WU-020' -Module 'Updates' -ObjectType 'UpdateRing' -DisplayName ("$a - WU - 020 - Windows Update - Production") -SafeState 'Empty Production group'))
    }
    if ($Answers.Updates.CreateFeatureUpdatePolicies -and -not $Answers.Updates.PreserveAutopatch) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-FU-010' -Module 'Updates' -ObjectType 'FeatureUpdatePolicy' -DisplayName ("$a - FU - 010 - Windows 11 - Pilot") -SafeState 'Pilot group'))
        $Objects.Add((New-DERPlannedObject -DerId 'DER-FU-020' -Module 'Updates' -ObjectType 'FeatureUpdatePolicy' -DisplayName ("$a - FU - 020 - Windows 11 - Production") -SafeState 'Empty Production group'))
    }
    if ($Answers.Updates.ManageDrivers -and -not $Answers.Updates.PreserveAutopatch) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-WU-030' -Module 'Drivers' -ObjectType 'DriverUpdatePolicy' -DisplayName ("$a - WU - 030 - Driver Updates - Pilot") -SafeState 'Pilot group'))
        $Objects.Add((New-DERPlannedObject -DerId 'DER-WU-040' -Module 'Drivers' -ObjectType 'DriverUpdatePolicy' -DisplayName ("$a - WU - 040 - Driver Updates - Production") -SafeState 'Empty Production group'))
    }
    if ($Answers.UserData.UseOneDrive){$Objects.Add((New-DERPlannedObject -DerId 'DER-CFG-020' -Module 'OneDrive' -ObjectType 'SettingsCatalogPolicy' -DisplayName ("$a - CFG - 020 - OneDrive") -SafeState 'Pilot device group'))}
    if ($Answers.UserData.ConfigureDeliveryOptimization){$Objects.Add((New-DERPlannedObject -DerId 'DER-DO-010' -Module 'DeliveryOptimization' -ObjectType 'DeliveryOptimizationConfiguration' -DisplayName ("$a - CFG - 040 - Delivery Optimization") -SafeState 'Pilot device group'))}

    if ($Answers.Operations.EnableDeviceCleanup) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-TENANT-010' -Module 'TenantSettings' -ObjectType 'ManagedDeviceCleanupRule' -DisplayName ("$a - CLEANUP - 010 - Windows Inactive Devices") -Action 'Create' -SafeState 'Windows records only; no wipe/retire/Entra delete'))
    }
    $hasSupportInfo = (-not [string]::IsNullOrWhiteSpace([string]$Answers.Operations.SupportName)) -or (-not [string]::IsNullOrWhiteSpace([string]$Answers.Operations.SupportEmail)) -or (-not [string]::IsNullOrWhiteSpace([string]$Answers.Operations.SupportPhone)) -or (-not [string]::IsNullOrWhiteSpace([string]$Answers.Operations.SupportUrl))
    if ($hasSupportInfo) {
        $Objects.Add((New-DERPlannedObject -DerId 'DER-TENANT-020' -Module 'TenantSettings' -ObjectType 'IntuneBrandingProfileSupportFields' -DisplayName 'Microsoft Intune Company Portal Support Information' -Action 'Configure' -SafeState 'Only engineer-supplied support fields; preserve all other branding'))
    }
    if ($Answers.Operations.EnableEndpointAnalytics){$Objects.Add((New-DERPlannedObject -DerId 'DER-ANALYTICS-010' -Module 'Analytics' -ObjectType 'EndpointAnalyticsSettings' -DisplayName ("$a - CFG - 050 - Endpoint Analytics") -Action 'Configure' -SafeState 'Pilot device group only'))}
    if ($Answers.Operations.ConfigureLoggingIntegration){
        $Objects.Add((New-DERPlannedObject -DerId 'DER-LOGINT-010' -Module 'LoggingIntegration' -ObjectType 'DiagnosticSettings' -DisplayName 'Intune / Entra Diagnostic Export' -Action 'Configure' -SafeState 'Manual until Azure Monitor resource authentication is implemented'))
        $Manual.Add((New-DERManualAction -Id 'MAN-LOG-001' -Category 'Logging' -Title 'Configure Intune Diagnostics Settings to the existing Azure Monitor destination' -Reason 'Intune Diagnostics Settings depend on Azure subscription/resource context and Azure Monitor authorization that DER does not yet validate end-to-end.' -Priority 'Normal' -Metadata @{Destination=[string]$Answers.Operations.SIEM;PortalPath='Intune admin center > Reports > Diagnostics settings';Logs=@('AuditLogs','OperationalLogs','DeviceComplianceOrg','IntuneDevices')}))
    }
}

function New-DERBuildPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Discovery,[Parameter(Mandatory)]$Analysis,[Parameter(Mandatory)]$Answers,[Parameter(Mandatory)][string]$RunId)
    $started=Get-Date
    Write-DERPlannerLog -Level STEP -Message 'Compiling deterministic DER build plan.' -Data @{tenantId=$Discovery.TenantId;profile=$Answers.Profile}
    $objects=New-Object System.Collections.Generic.List[object]
    $manual=New-Object System.Collections.Generic.List[object]
    Add-DERGroupObjects -Answers $Answers -Objects $objects
    Add-DERWorkloadObjects -Answers $Answers -Analysis $Analysis -Objects $objects -Manual $manual

    if ($Answers.Enrollment.CreateStagingAccount) {$manual.Add((New-DERManualAction -Id 'MAN-STAGE-001' -Category 'Enrollment' -Title ("Create/validate staging account {0}" -f $Answers.Enrollment.StagingAccountName) -Reason 'DER will only create this identity automatically if the account lifecycle and security can be completed safely end-to-end.' -Priority 'Normal' -Metadata @{StagingAccountName=[string]$Answers.Enrollment.StagingAccountName}))}
    if ($Answers.Enrollment.UseDEM) {$manual.Add((New-DERManualAction -Id 'MAN-DEM-001' -Category 'Enrollment' -Title 'Review Device Enrollment Manager account selection' -Reason 'DEM is optional and should be deliberately assigned to the correct account.' -Priority 'Normal'))}
    if ($Answers.Operations.ConfigureSignInBranding) {$manual.Add((New-DERManualAction -Id 'MAN-BRAND-001' -Category 'Branding' -Title 'Provide customer sign-in branding assets' -Reason 'DER will not invent customer logos, legal text, or branding assets.' -Priority 'Low'))}
    if ($Answers.Operations.ConfigureTerms) {$manual.Add((New-DERManualAction -Id 'MAN-TERMS-001' -Category 'Legal' -Title 'Provide approved Terms and Conditions text' -Reason 'DER never invents legal language.' -Priority 'Normal'))}

    $moduleNames=@($objects | Where-Object {$_.Enabled} | Select-Object -ExpandProperty Module -Unique | Sort-Object)
    $modules=@()
    foreach($name in $moduleNames){$modules += [pscustomobject][ordered]@{Name=$name;Enabled=$true;ObjectCount=@($objects|Where-Object {$_.Module -eq $name -and $_.Enabled}).Count;Risk=if($name -eq 'ConditionalAccess'){'High'}elseif($name -in @('Enrollment','TenantSettings','EntraDevice','PIM')){'Medium'}else{'Low'};SafeInitialState=(@($objects|Where-Object {$_.Module -eq $name}|Select-Object -ExpandProperty SafeState -Unique)-join '; ')}}

    $customerWrites=if ($Answers.Safety.ChangeControl -eq 'Report-only / no tenant writes') {0} else {@($objects|Where-Object {$_.Enabled}).Count}
    $plan=[pscustomobject][ordered]@{
        SchemaVersion='1.0';RunId=$RunId;TenantId=$Discovery.TenantId;TenantName=$Discovery.TenantName;BaselineVersion='1.0.0';CreatedAt=Get-Date;EnvironmentClassification=$Analysis.EnvironmentClassification;
        Profile=$Answers.Profile;Organization=$Answers.Organization;Safety=$Answers.Safety;Answers=$Answers;
        Modules=$modules;Objects=@($objects);ManualActions=@($manual);ExistingFindings=@($Analysis.Findings);
        Summary=[pscustomobject]@{PlannedObjects=@($objects|Where-Object {$_.Enabled}).Count;Modules=$modules.Count;ManualActions=$manual.Count;CustomerOwnedObjectsModified=0;CustomerOwnedObjectsDeleted=0;ProductionEnforcement=0;PotentialWrites=$customerWrites;ReportOnly=($Answers.Safety.ChangeControl -eq 'Report-only / no tenant writes')}
    }
    if (Test-DERPlannerCommand 'Save-DERBuildRecipeState') {Save-DERBuildRecipeState -BuildRecipe $plan | Out-Null}
    Write-DERPlannerLog -Level OK -Message ("Build plan compiled: {0} planned object/action(s), {1} workload modules, {2} manual action(s)." -f $plan.Summary.PlannedObjects,$plan.Summary.Modules,$plan.Summary.ManualActions) -Data $plan.Summary
    return $plan
}

Export-ModuleMember -Function @('New-DERPlannedObject','New-DERManualAction','New-DERBuildPlan')
