<#
.SYNOPSIS
    DER discovery-driven engineer questionnaire.

.DESCRIPTION
    Presents only the decisions DER cannot safely infer from tenant discovery,
    applies DER Standard defaults, supports a Custom mode, and persists the
    resulting answer set for resume/audit purposes. This module performs no
    tenant writes.

.NOTES
    Required parent entry point: Invoke-DERQuestionnaire
#>


# Maintenance notes
# Responsibility: Resolves operator/site choices into deterministic answers. NonInteractive mode must never fall back to hidden prompts.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DERQuestionnaireNonInteractive = $false

function Test-DERQuestionnaireCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Write-DERQuestionnaireLog {
    param([Parameter(Mandatory)][string]$Level,[Parameter(Mandatory)][string]$Message,$Data)
    if (Test-DERQuestionnaireCommand -Name 'Write-DERLog') { Write-DERLog -Level $Level -Component 'Questionnaire' -Message $Message -Data $Data }
}

function ConvertTo-DERSafeAcronym {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $clean=($Name -replace '[^A-Za-z0-9 ]',' ').Trim()
    $words=@($clean -split '\s+' | Where-Object {$_})
    if ($words.Count -gt 1) {
        $value=($words | ForEach-Object {$_.Substring(0,1)}) -join ''
    } else {
        $value=($clean -replace '\s','')
        if ($value.Length -gt 8) {$value=$value.Substring(0,8)}
    }
    if ([string]::IsNullOrWhiteSpace($value)) {$value='ORG'}
    return $value.ToUpperInvariant()
}

function ConvertTo-DERComputerPrefix {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Acronym)
    $value=($Acronym -replace '[^A-Za-z0-9]','').ToUpperInvariant()
    if ($value.Length -gt 7) {$value=$value.Substring(0,7)}
    if ([string]::IsNullOrWhiteSpace($value)) {$value='ORG'}
    return $value
}

function Read-DERText {
    param([Parameter(Mandatory)][string]$Prompt,[string]$Default,[switch]$Required,$PresetValue)
    if ($null -ne $PresetValue) {
        $value=[string]$PresetValue
        if($Required -and [string]::IsNullOrWhiteSpace($value)){throw "NonInteractive/preset value for '$Prompt' is required and cannot be blank."}
        return $value
    }
    if($script:DERQuestionnaireNonInteractive){
        if($Required){throw "NonInteractive questionnaire is missing required preset value for '$Prompt'."}
        return [string]$Default
    }
    while ($true) {
        $suffix=if ($Default) {" [$Default]"} else {''}
        $v=Read-Host ($Prompt+$suffix)
        if ([string]::IsNullOrWhiteSpace($v)) {$v=$Default}
        if (-not $Required -or -not [string]::IsNullOrWhiteSpace($v)) {return [string]$v}
        Write-Host 'A value is required.' -ForegroundColor Yellow
    }
}

function Read-DERYesNo {
    param([Parameter(Mandatory)][string]$Prompt,[bool]$Default=$true,$PresetValue)
    if ($null -ne $PresetValue) {
        if($PresetValue -is [bool]){return [bool]$PresetValue}
        $text=[string]$PresetValue
        switch -Regex ($text.Trim()) {
            '^(true|1|y|yes)$' {return $true}
            '^(false|0|n|no)$' {return $false}
            default {throw "Invalid preset value '$PresetValue' for yes/no question '$Prompt'."}
        }
    }
    if($script:DERQuestionnaireNonInteractive){return $Default}
    $hint=if ($Default) {'Y/n'} else {'y/N'}
    while ($true) {
        $v=Read-Host ("$Prompt [$hint]")
        if ([string]::IsNullOrWhiteSpace($v)) {return $Default}
        switch -Regex ($v.Trim()) {
            '^(y|yes)$' {return $true}
            '^(n|no)$' {return $false}
            default {Write-Host 'Enter Y or N.' -ForegroundColor Yellow}
        }
    }
}

function Read-DERChoice {
    param([Parameter(Mandatory)][string]$Prompt,[Parameter(Mandatory)][string[]]$Options,[int]$DefaultIndex=0,$PresetValue)
    if ($null -ne $PresetValue) {
        $index=0
        if([int]::TryParse([string]$PresetValue,[ref]$index) -and [string]$PresetValue -match '^\d+$'){
            if($index -ge 0 -and $index -lt $Options.Count){return $Options[$index]}
            throw "Invalid preset choice index '$PresetValue' for '$Prompt'. Valid zero-based range is 0-$($Options.Count-1)."
        }
        if ($Options -contains [string]$PresetValue) {return [string]$PresetValue}
        throw "Invalid preset choice '$PresetValue' for '$Prompt'. Valid values: $($Options -join ', ')."
    }
    if($script:DERQuestionnaireNonInteractive){return $Options[$DefaultIndex]}
    Write-Host ''
    Write-Host $Prompt -ForegroundColor Cyan
    for ($i=0;$i -lt $Options.Count;$i++) {$mark=if ($i -eq $DefaultIndex) {' (Recommended/default)'} else {''};Write-Host ("  {0}. {1}{2}" -f ($i+1),$Options[$i],$mark)}
    while ($true) {
        $v=Read-Host ("Select 1-$($Options.Count) [$($DefaultIndex+1)]")
        if ([string]::IsNullOrWhiteSpace($v)) {return $Options[$DefaultIndex]}
        $n=0
        if ([int]::TryParse($v,[ref]$n) -and $n -ge 1 -and $n -le $Options.Count) {return $Options[$n-1]}
        if ($Options -contains $v) {return $v}
        Write-Host 'Invalid selection.' -ForegroundColor Yellow
    }
}

function Read-DERInteger {
    param([Parameter(Mandatory)][string]$Prompt,[int]$Default,[int]$Minimum=0,[int]$Maximum=100000,$PresetValue)
    if ($null -ne $PresetValue) {
        $n=0
        if(-not[int]::TryParse([string]$PresetValue,[ref]$n)){throw "Invalid integer preset '$PresetValue' for '$Prompt'."}
        if($n -lt $Minimum -or $n -gt $Maximum){throw "Preset value $n for '$Prompt' is outside the allowed range $Minimum-$Maximum."}
        return $n
    }
    if($script:DERQuestionnaireNonInteractive){return $Default}
    while ($true) {
        $v=Read-Host ("$Prompt [$Default]")
        if ([string]::IsNullOrWhiteSpace($v)) {return $Default}
        $n=0
        if ([int]::TryParse($v,[ref]$n) -and $n -ge $Minimum -and $n -le $Maximum) {return $n}
        Write-Host ("Enter a number from {0} to {1}." -f $Minimum,$Maximum) -ForegroundColor Yellow
    }
}

function ConvertFrom-DERCommaList {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {return @()}
    return @($Value -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_} | Sort-Object -Unique)
}

function Get-DERPresetValue {
    param($Preset,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Preset) {return $null}
    if ($Preset -is [System.Collections.IDictionary] -and $Preset.Contains($Name)) {return $Preset[$Name]}
    $p=$Preset.PSObject.Properties[$Name]
    if ($p) {return $p.Value}
    return $null
}

function New-DERSiteQuestionnaireEntry {
    param([int]$Index,$Preset)
    Write-Host ''
    Write-Host ("Site {0}" -f $Index) -ForegroundColor Cyan
    $name=Read-DERText -Prompt 'Site/location name' -Default ("Site {0}" -f $Index) -Required -PresetValue (Get-DERPresetValue $Preset 'Name')
    $region=Read-DERText -Prompt 'City / state / country or region' -PresetValue (Get-DERPresetValue $Preset 'Region')
    $timezone=Read-DERText -Prompt 'Timezone (optional)' -PresetValue (Get-DERPresetValue $Preset 'TimeZone')
    $ipv4=ConvertFrom-DERCommaList (Read-DERText -Prompt 'Static public IPv4 CIDR(s), comma separated (optional)' -PresetValue (Get-DERPresetValue $Preset 'IPv4Raw'))
    $ipv6=ConvertFrom-DERCommaList (Read-DERText -Prompt 'Static public IPv6 CIDR(s), comma separated (optional)' -PresetValue (Get-DERPresetValue $Preset 'IPv6Raw'))
    $createNamed=Read-DERYesNo -Prompt 'Create a Microsoft Entra Named Location for this site?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateNamedLocation')
    $trusted=$false
    if ($createNamed) {$trusted=Read-DERYesNo -Prompt 'Mark this Named Location as Trusted?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'Trusted')}
    return [pscustomobject][ordered]@{Index=$Index;Name=$name;Region=$region;TimeZone=$timezone;IPv4=$ipv4;IPv6=$ipv6;CreateNamedLocation=$createNamed;Trusted=$trusted}
}

function New-DERStandardDefaults {
    param($Discovery,$Analysis,[string]$Acronym)
    $p2=[bool]$Analysis.BranchHints.HasEntraP2
    $mde=[bool]$Analysis.BranchHints.HasDefenderForEndpoint
    return [ordered]@{
        CreateCoreGroups=$true;CreateDynamicInventoryGroups=$true;CreateExclusionGroups=$true;UseBuiltInAllTargets=$true;
        AllowPreviewApis=$true;PilotFirst=$true;TenantSwitchMode='AskBeforeEachChange';
        UseAutopilot=$true;AutopilotMethod='Traditional Windows Autopilot';DeploymentScenario='User-driven Microsoft Entra Join';EndUserAccountType='Standard User';
        GlobalAdminsLocalAdmins=$false;UseEnrollmentGroup=$true;MDMScope='Selected';CorporateWindowsOnly=$true;MaxEnrollmentsPerUser=5;
        ExistingDeviceAutopilotAction='Report eligible devices first';AutopilotGroupTag=("{0} - WIN" -f $Acronym);ComputerNameTemplate=("{0}-%RAND:7%" -f (ConvertTo-DERComputerPrefix $Acronym));
        HidePrivacyOobe=$true;HideConsumerOobe=$true;CreateESP=$true;ESPTimeoutMinutes=60;ESPAllowReset=$true;ESPAllowContinueOnFailure=$false;
        PreProvisioning=$false;SharedDevices=$false;SelfDeploying=$false;EnableWHfB=$true;EnableBiometrics=$true;CreateStagingAccount=$false;UseDEM=$false;
        CreateCompliance=$true;RequireBitLocker=$true;RequireSecureBoot=$true;RequireTPM=$true;RequireCodeIntegrity=$true;RequireFirewallCompliance=$true;
        DefenderRiskCompliance=$mde;MaximumMachineRisk='Medium';NonComplianceGraceDays=1;AutomaticRetireWipe=$false;MarkNoPolicyNoncompliant=$true;
        CreateBitLocker=$true;BitLockerCipher='XTS-AES 128';EncryptFixedDrives=$true;RemovableStorage='Allow';
        CreateLAPS=$true;LAPSPasswordLength=20;LAPSRotationDays=30;LAPSPostAuthRotation=$true;
        CreateDefender=$true;PUA='Block';CreateTamperProtection=$true;CreateASR=$true;CreateNetworkProtection=$true;NetworkProtectionMode='Audit';CreateCFA=$true;CFAMode='Audit';
        CreateFirewall=$true;AllowLocalFirewallRuleMerge=$true;CreateVBS=$true;DeviceLockMinutes=15;BlockConsumerFeatures=$true;SMBMode='Audit/report only';
        EnableAuthenticator=$true;EnableFIDO2=$true;EnableTAP=$true;EnableSMSFallback=$true;EnableVoice=$false;EnableSoftwareOATH=$true;EnableSSPRPilot=$true;
        CreateConditionalAccess=$true;CreateRiskCAPs=$p2;CreateGeoCAP=$true;RestrictGuestVisibility=$true;EnableAdminConsentWorkflow=$true;EnableCustomPasswordProtection=$true;ConfigurePIM=$p2;
        PreserveSecurityDefaults=$true;CreateUpdateRings=$true;CreateFeatureUpdatePolicies=$true;TargetFeatureUpdateVersion='Windows 11, version 25H2';PilotUpdateDeferralDays=0;ProductionUpdateDeferralDays=7;UpdateDeadlineDays=7;UpdateGraceDays=2;FeatureDeadlineDays=14;FeatureGraceDays=2;
        ManageDrivers=$true;DriverPilotDelayDays=3;DriverProductionDelayDays=14;RespectSafeguards=$true;UseOneDrive=$false;ConfigureDeliveryOptimization=$false;
        EnableEnrollmentNotifications=$true;EnableDeviceCleanup=$true;DeviceCleanupDays=90;EnableEndpointAnalytics=$true;ConfigureSupportInfo=$true;ConfigureSignInBranding=$false;
        ConfigureTerms=$false;ConfigureLoggingIntegration=$false;PreserveAutopatch=([bool]$Analysis.BranchHints.HasAutopatch)
    }
}

function Invoke-DERQuestionnaire {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Discovery,
        [Parameter(Mandatory)]$Analysis,
        [Parameter(Mandatory)][string]$RunId,
        $Preset,
        [switch]$NonInteractive
    )

    $started=Get-Date
    $script:DERQuestionnaireNonInteractive=[bool]$NonInteractive
    Write-DERQuestionnaireLog -Level STEP -Message 'Starting discovery-driven DER engineer questionnaire.' -Data @{tenantId=$Discovery.TenantId;classification=$Analysis.EnvironmentClassification}
    if ($NonInteractive -and -not $Preset) {throw 'NonInteractive questionnaire mode requires a Preset object.'}

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host ' DER INTUNE / ENTRA BUILDER - ENGINEER QUESTIONNAIRE' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host ("Tenant: {0} ({1})" -f $Discovery.TenantName,$Discovery.TenantId)
    Write-Host ("Detected: {0} users | {1} Entra devices | {2} managed devices" -f $Discovery.Summary.Users,$Discovery.Summary.EntraDevices,$Discovery.Summary.ManagedDevices)
    Write-Host ("Classification: {0}" -f $Analysis.EnvironmentClassification)
    Write-Host ''

    $orgName=Read-DERText -Prompt 'Organization display name' -Default $Discovery.TenantName -Required -PresetValue (Get-DERPresetValue $Preset 'OrganizationName')
    $suggestedAcronym=ConvertTo-DERSafeAcronym -Name $orgName
    $acronym=Read-DERText -Prompt 'Organization acronym/prefix' -Default $suggestedAcronym -Required -PresetValue (Get-DERPresetValue $Preset 'Acronym')
    $acronym=($acronym -replace '[^A-Za-z0-9]','').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($acronym)) {throw 'A usable organization acronym is required.'}

    $mode=Read-DERChoice -Prompt 'Configuration profile' -Options @('DER Standard','Custom') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'Profile')
    $defaults=New-DERStandardDefaults -Discovery $Discovery -Analysis $Analysis -Acronym $acronym

    $existingMode=if ($Analysis.BranchHints.ExistingTenant) {'Compare existing objects; never modify unless explicitly adopted'} else {'New / mostly empty tenant'}
    Write-Host ("Existing-object mode: {0}" -f $existingMode) -ForegroundColor Gray
    $allowPreview=Read-DERYesNo -Prompt 'Allow DER-tested Microsoft Graph Preview/Beta APIs when no supported v1.0 equivalent exists?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'AllowPreviewApis')
    $changeControl=Read-DERChoice -Prompt 'Change-control restriction for this run' -Options @('Normal safe DER build','Report-only / no tenant writes','No tenant-wide switch changes') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'ChangeControl')

    Write-Host ''
    Write-Host '--- Infrastructure ---' -ForegroundColor Cyan
    $createCore=Read-DERYesNo -Prompt 'Create DER standard core infrastructure groups?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateCoreGroups')
    $createDyn=Read-DERYesNo -Prompt 'Create standard dynamic inventory groups?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateDynamicInventoryGroups')
    $createExclusions=Read-DERYesNo -Prompt 'Create standard empty exclusion groups?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateExclusionGroups')
    $distributedAdmin=Read-DERYesNo -Prompt 'Do separate IT teams administer different locations/divisions/regions?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'DistributedAdministration')
    $createDepartments=Read-DERYesNo -Prompt 'Create department groups from an engineer-provided list?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'CreateDepartmentGroups')
    $departments=@()
    if ($createDepartments) {$departments=ConvertFrom-DERCommaList (Read-DERText -Prompt 'Departments, comma separated' -PresetValue (Get-DERPresetValue $Preset 'DepartmentsRaw'))}

    $siteCount=Read-DERInteger -Prompt 'How many physical locations should DER collect for Named Location/network planning?' -Default 1 -Minimum 0 -Maximum 100 -PresetValue (Get-DERPresetValue $Preset 'SiteCount')
    $sites=@()
    $sitePresets=Get-DERPresetValue $Preset 'Sites'
    for ($i=1;$i -le $siteCount;$i++) {
        $sp=$null;if ($sitePresets -and @($sitePresets).Count -ge $i) {$sp=@($sitePresets)[$i-1]}
        if ($NonInteractive -and -not $sp) {throw "NonInteractive questionnaire requires a site definition for Site $i because SiteCount is $siteCount."}
        $sites+=New-DERSiteQuestionnaireEntry -Index $i -Preset $sp
    }
    $hasVpn=Read-DERYesNo -Prompt 'Does the organization have a corporate VPN with known public egress IPs?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'HasCorporateVPN')
    $vpn=$null
    if ($hasVpn) {
        $vpnName=Read-DERText -Prompt 'VPN name' -Default 'Corporate VPN' -PresetValue (Get-DERPresetValue $Preset 'VPNName')
        $vpnIPs=ConvertFrom-DERCommaList (Read-DERText -Prompt 'VPN public egress IP/CIDR(s), comma separated' -PresetValue (Get-DERPresetValue $Preset 'VPNIPsRaw'))
        $vpn=[pscustomobject]@{Name=$vpnName;IPs=$vpnIPs;CreateNamedLocation=(Read-DERYesNo -Prompt 'Create VPN Named Location?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateVPNNamedLocation'));Trusted=(Read-DERYesNo -Prompt 'Mark VPN Named Location as Trusted?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'VPNTrusted'))}
    }
    $normalCountries=ConvertFrom-DERCommaList (Read-DERText -Prompt 'Countries/regions where users normally work, comma separated' -Default 'United States' -PresetValue (Get-DERPresetValue $Preset 'NormalCountriesRaw'))
    $internationalTravel=Read-DERChoice -Prompt 'International travel expectation' -Options @('Never','Rarely','Frequently','Only specific employees','Unknown') -DefaultIndex 1 -PresetValue (Get-DERPresetValue $Preset 'InternationalTravel')
    $geoPolicy=Read-DERYesNo -Prompt 'Create a Report-only geographic restriction policy for countries outside approved business/travel geography?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CreateGeoCAP')

    Write-Host ''
    Write-Host '--- Windows Enrollment / Autopilot ---' -ForegroundColor Cyan
    $useAutopilot=Read-DERYesNo -Prompt 'Use traditional Windows Autopilot?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'UseAutopilot')
    $endUserType=Read-DERChoice -Prompt 'Autopilot end-user account type' -Options @('Standard User','Local Administrator') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'EndUserAccountType')
    $gaLocal=Read-DERYesNo -Prompt 'Keep Global Administrators as local admins on Entra-joined Windows devices?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'GlobalAdminsLocalAdmins')
    $corporateOnly=Read-DERYesNo -Prompt 'Block personally owned Windows enrollment (corporate Windows only)?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'CorporateWindowsOnly')
    $blockNewWin10=$false
    if ($Analysis.BranchHints.NewOrMostlyEmpty) {$blockNewWin10=Read-DERYesNo -Prompt 'Block enrollment of new Windows 10 devices?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'BlockNewWindows10')}
    else {$blockNewWin10=Read-DERYesNo -Prompt 'Existing tenant: block new Windows 10 enrollments after review?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'BlockNewWindows10')}
    $maxEnroll=Read-DERInteger -Prompt 'Maximum Windows enrollments per user' -Default 5 -Minimum 1 -Maximum 15 -PresetValue (Get-DERPresetValue $Preset 'MaxEnrollmentsPerUser')
    $existingConversion=Read-DERChoice -Prompt 'Existing Windows devices and Autopilot registration' -Options @('Do not convert automatically','Report eligible devices first','Convert approved targeted devices') -DefaultIndex 1 -PresetValue (Get-DERPresetValue $Preset 'ExistingDeviceAutopilotAction')
    $groupTag=Read-DERText -Prompt 'Autopilot Group Tag' -Default ("$acronym - WIN") -PresetValue (Get-DERPresetValue $Preset 'AutopilotGroupTag')
    $computerPrefix=ConvertTo-DERComputerPrefix -Acronym $acronym
    $computerTemplate=Read-DERText -Prompt 'Autopilot computer naming template (Windows names cannot contain spaces)' -Default ("$computerPrefix-%RAND:7%") -PresetValue (Get-DERPresetValue $Preset 'ComputerNameTemplate')
    if ($computerTemplate.Length -gt 15 -and $computerTemplate -notmatch '%SERIAL%') {Write-Host 'Warning: generated Windows computer names must remain 15 characters or fewer. DER dry run will validate this template.' -ForegroundColor Yellow}
    $preProvision=Read-DERYesNo -Prompt 'Will IT/OEM pre-provision devices before the end user receives them?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'PreProvisioning')
    $shared=Read-DERYesNo -Prompt 'Does the organization have shared Windows PCs?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'SharedDevices')
    $selfDeploy=$false;if ($shared) {$selfDeploy=Read-DERYesNo -Prompt 'Do any shared/kiosk devices need self-deploying Autopilot?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'SelfDeploying')}
    $whfb=Read-DERYesNo -Prompt 'Enable Windows Hello for Business in Pilot?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'EnableWHfB')
    $staging=Read-DERYesNo -Prompt 'Do technicians need a dedicated staging/enrollment account for setup before the end user is available?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'CreateStagingAccount')
    $stagingName=$null
    if ($staging) {$stagingName=Read-DERText -Prompt 'Staging account name suggestion' -Default ("{0}_JOIN" -f $acronym) -PresetValue (Get-DERPresetValue $Preset 'StagingAccountName')}
    $dem=Read-DERYesNo -Prompt 'Use a Device Enrollment Manager account?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'UseDEM')
    $hashSource=Read-DERChoice -Prompt 'How will Autopilot devices be registered?' -Options @('OEM/reseller','Hardware hashes already available','Need manual hash collection','Existing devices','Unknown') -DefaultIndex 4 -PresetValue (Get-DERPresetValue $Preset 'AutopilotRegistrationSource')

    Write-Host ''
    Write-Host '--- Security ---' -ForegroundColor Cyan
    $av=Read-DERChoice -Prompt 'Primary endpoint antivirus' -Options @('Microsoft Defender','Third-party AV','Mixed environment','Unknown') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'PrimaryAV')
    $useDefender=($av -eq 'Microsoft Defender' -or $av -eq 'Unknown')
    $removable=Read-DERChoice -Prompt 'Removable storage policy' -Options @('Allow','Audit','Read only','Block') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'RemovableStorage')
    $smb=Read-DERChoice -Prompt 'SMB hardening behavior' -Options @('Audit/report only','Apply recommended hardening to Pilot','Skip') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'SMBMode')
    $lapsLength=20
    if ($mode -eq 'Custom') {$lapsLength=Read-DERInteger -Prompt 'LAPS password length' -Default 20 -Minimum 14 -Maximum 64 -PresetValue (Get-DERPresetValue $Preset 'LAPSPasswordLength')}

    Write-Host ''
    Write-Host '--- Identity / Conditional Access ---' -ForegroundColor Cyan
    $tap=Read-DERYesNo -Prompt 'Enable Temporary Access Pass authentication?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'EnableTAP')
    $voice=Read-DERYesNo -Prompt 'Enable voice authentication?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'EnableVoice')
    $guests=Read-DERYesNo -Prompt 'Use DER guest/external collaboration hardening?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'ConfigureGuests')
    $crossTenant=Read-DERYesNo -Prompt 'Configure specific cross-tenant partner access/trust?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'ConfigureCrossTenant')
    $partnerTenants=@()
    if ($crossTenant) {$partnerTenants=ConvertFrom-DERCommaList (Read-DERText -Prompt 'Partner tenant IDs/domains, comma separated' -PresetValue (Get-DERPresetValue $Preset 'PartnerTenantsRaw'))}
    $pim=$false
    if ($Analysis.BranchHints.HasEntraP2) {$pim=Read-DERYesNo -Prompt 'Configure Privileged Identity Management for selected admin roles?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'ConfigurePIM')}
    $pimApproval=$false
    if ($pim) {$pimApproval=Read-DERYesNo -Prompt 'Require another administrator to approve PIM activation?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'PIMRequireApproval')}

    Write-Host ''
    Write-Host '--- Updates / User Data / Operations ---' -ForegroundColor Cyan
    $preserveAutopatch=$false
    if ($Analysis.BranchHints.PSObject.Properties.Name -contains 'HasAutopatch' -and $Analysis.BranchHints.HasAutopatch) {$preserveAutopatch=Read-DERYesNo -Prompt 'Windows Autopatch indicators were detected. Preserve existing Autopatch-managed update configuration instead of creating overlapping update policies?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'PreserveAutopatch')}
    $drivers=Read-DERYesNo -Prompt 'Manage Windows drivers/firmware through Intune?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'ManageDrivers')
    $oneDrive=Read-DERYesNo -Prompt 'Does the organization use OneDrive for Business user storage?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'UseOneDrive')
    $bandwidthConstrained=Read-DERYesNo -Prompt 'Are any sites bandwidth-constrained enough to require Delivery Optimization planning?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'ConfigureDeliveryOptimization')
    $siem=Read-DERChoice -Prompt 'Existing SIEM / logging destination' -Options @('None','Microsoft Sentinel','Azure Log Analytics','Third-party SIEM','Unknown') -DefaultIndex 0 -PresetValue (Get-DERPresetValue $Preset 'SIEM')
    $configureLogging=($siem -notin @('None','Unknown')) -and (Read-DERYesNo -Prompt 'Configure DER-supported diagnostic/log export to the existing destination?' -Default $true -PresetValue (Get-DERPresetValue $Preset 'ConfigureLoggingIntegration'))
    $supportName=Read-DERText -Prompt 'IT/support team name (optional)' -PresetValue (Get-DERPresetValue $Preset 'SupportName')
    $supportEmail=Read-DERText -Prompt 'IT/support email (optional)' -PresetValue (Get-DERPresetValue $Preset 'SupportEmail')
    $supportPhone=Read-DERText -Prompt 'IT/support phone (optional)' -PresetValue (Get-DERPresetValue $Preset 'SupportPhone')
    $supportUrl=Read-DERText -Prompt 'IT/support URL (optional)' -PresetValue (Get-DERPresetValue $Preset 'SupportUrl')
    $branding=Read-DERYesNo -Prompt 'Configure customer Entra sign-in branding if assets are supplied?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'ConfigureSignInBranding')
    $terms=Read-DERYesNo -Prompt 'Create Intune Terms and Conditions if approved legal text is supplied?' -Default $false -PresetValue (Get-DERPresetValue $Preset 'ConfigureTerms')

    $answers=[pscustomobject][ordered]@{
        SchemaVersion='1.0';RunId=$RunId;TenantId=$Discovery.TenantId;TenantName=$Discovery.TenantName;AnsweredAt=Get-Date;Profile=$mode;
        Organization=[pscustomobject]@{Name=$orgName;Acronym=$acronym;NamingPattern='ACRONYM - TYPE - ### - Description';ComputerPrefix=$computerPrefix};
        Safety=[pscustomobject]@{AllowPreviewApis=$allowPreview;PilotFirst=$true;ExistingObjectMode='Compare/Adopt/Skip';NeverModifyUnowned=$true;ChangeControl=$changeControl;TenantSwitchMode='AskBeforeEachChange';UseBuiltInAllTargets=$true};
        Infrastructure=[pscustomobject]@{CreateCoreGroups=$createCore;CreateDynamicInventoryGroups=$createDyn;CreateExclusionGroups=$createExclusions;DistributedAdministration=$distributedAdmin;CreateDepartmentGroups=$createDepartments;Departments=$departments;Sites=$sites;CorporateVPN=$vpn;NormalCountries=$normalCountries;InternationalTravel=$internationalTravel;CreateGeoCAP=$geoPolicy};
        Enrollment=[pscustomobject]@{UseAutopilot=$useAutopilot;AutopilotMethod='Traditional Windows Autopilot';DeploymentScenario='User-driven Microsoft Entra Join';EndUserAccountType=$endUserType;GlobalAdminsLocalAdmins=$gaLocal;UseEnrollmentGroup=$true;MDMScope='Selected';CorporateWindowsOnly=$corporateOnly;BlockNewWindows10=$blockNewWin10;MaxEnrollmentsPerUser=$maxEnroll;ExistingDeviceAutopilotAction=$existingConversion;AutopilotGroupTag=$groupTag;ComputerNameTemplate=$computerTemplate;CreateESP=$true;ESPTimeoutMinutes=60;ESPAllowReset=$true;ESPAllowContinueOnFailure=$false;HidePrivacyOobe=$true;HideConsumerOobe=$true;PreProvisioning=$preProvision;SharedDevices=$shared;SelfDeploying=$selfDeploy;EnableWHfB=$whfb;EnableBiometrics=$true;CreateStagingAccount=$staging;StagingAccountName=$stagingName;UseDEM=$dem;AutopilotRegistrationSource=$hashSource;EnrollmentNotifications=$true};
        Security=[pscustomobject]@{PrimaryAV=$av;CreateCompliance=$true;RequireBitLocker=$true;RequireSecureBoot=$true;RequireTPM=$true;RequireCodeIntegrity=$true;RequireFirewallCompliance=$true;DefenderRiskCompliance=([bool]$Analysis.BranchHints.HasDefenderForEndpoint);MaximumMachineRisk='Medium';NonComplianceGraceDays=1;AutomaticRetireWipe=$false;MarkNoPolicyNoncompliant=$true;CreateBitLocker=$true;BitLockerCipher='XTS-AES 128';EncryptFixedDrives=$true;RemovableStorage=$removable;CreateLAPS=$true;LAPSPasswordLength=$lapsLength;LAPSRotationDays=30;LAPSPostAuthRotation=$true;CreateDefender=$useDefender;PUA='Block';CreateTamperProtection=$useDefender;CreateASR=$useDefender;CreateNetworkProtection=$useDefender;NetworkProtectionMode='Audit';CreateCFA=$useDefender;CFAMode='Audit';CreateFirewall=$true;AllowLocalFirewallRuleMerge=$true;CreateVBS=$true;DeviceLockMinutes=15;BlockConsumerFeatures=$true;SMBMode=$smb};
        Identity=[pscustomobject]@{PreserveSecurityDefaults=$true;EnableAuthenticator=$true;EnableFIDO2=$true;EnableTAP=$tap;EnableSMSFallback=$true;EnableVoice=$voice;EnableSoftwareOATH=$true;EnableSSPRPilot=$true;CreateConditionalAccess=$true;CreateRiskCAPs=([bool]$Analysis.BranchHints.HasEntraP2);ConfigureGuests=$guests;RestrictGuestVisibility=$true;ConfigureCrossTenant=$crossTenant;PartnerTenants=$partnerTenants;EnableAdminConsentWorkflow=$true;EnableCustomPasswordProtection=$true;ConfigurePIM=$pim;PIMRequireApproval=$pimApproval;PIMActivationHours=4};
        Updates=[pscustomobject]@{PreserveAutopatch=$preserveAutopatch;CreateUpdateRings=$true;CreateFeatureUpdatePolicies=$true;TargetFeatureUpdateVersion='Windows 11, version 25H2';PilotUpdateDeferralDays=0;ProductionUpdateDeferralDays=7;UpdateDeadlineDays=7;UpdateGraceDays=2;FeatureDeadlineDays=14;FeatureGraceDays=2;RespectSafeguards=$true;ManageDrivers=$drivers;DriverPilotDelayDays=3;DriverProductionDelayDays=14};
        UserData=[pscustomobject]@{UseOneDrive=$oneDrive;SilentSignIn=$oneDrive;KnownFolderMove=$oneDrive;FilesOnDemand=$oneDrive;SyncHealth=$oneDrive;AutoSyncSharePoint=$false;ConfigureDeliveryOptimization=$bandwidthConstrained};
        Operations=[pscustomobject]@{EnableDeviceCleanup=$true;DeviceCleanupDays=90;EnableEndpointAnalytics=$true;SIEM=$siem;ConfigureLoggingIntegration=$configureLogging;SupportName=$supportName;SupportEmail=$supportEmail;SupportPhone=$supportPhone;SupportUrl=$supportUrl;ConfigureSignInBranding=$branding;ConfigureTerms=$terms}
    }

    if (Test-DERQuestionnaireCommand -Name 'Save-DERQuestionnaireState') {Save-DERQuestionnaireState -Questionnaire $answers | Out-Null}
    Write-DERQuestionnaireLog -Level OK -Message 'DER questionnaire completed.' -Data @{profile=$mode;organization=$orgName;acronym=$acronym;sites=@($sites).Count;autopilot=$useAutopilot;primaryAV=$av;oneDrive=$oneDrive;pim=$pim;durationMs=[int]((Get-Date)-$started).TotalMilliseconds}
    $script:DERQuestionnaireNonInteractive=$false
    return $answers
}

Export-ModuleMember -Function @('ConvertTo-DERSafeAcronym','ConvertTo-DERComputerPrefix','Invoke-DERQuestionnaire')
