<#
.SYNOPSIS
    DER Microsoft Entra Named Locations workload.

.DESCRIPTION
    Creates DER-owned IP and country/region Named Locations using Microsoft
    Graph v1.0. Existing exact-name objects are never adopted implicitly.
    Trusted status is applied only when the engineer explicitly approved it.

.NOTES
    Required parent entry point: Invoke-DERNamedLocationsModule
#>


# Maintenance notes
# Responsibility: Creates approved Conditional Access named locations after validating IP/country inputs and collision state.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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


function Test-DERNamedLocationsCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERNamedLocationsLog {
    param([string]$Level,[string]$Message,$Data,[string]$ActionId)
    if (Test-DERNamedLocationsCommand 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'NamedLocations' -ActionId $ActionId -Message $Message -Data $Data
    }
}

function Save-DERNamedLocationsResult {
    param($Result)
    $ctx = if (Test-DERNamedLocationsCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath (Join-Path $dir 'NamedLocations.json') -Encoding UTF8
    }
}

function ConvertTo-DERCidrRange {
    param([Parameter(Mandatory)][string]$InputValue)
    $value = $InputValue.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    $isV6 = $value.Contains(':')
    if (-not $value.Contains('/')) { $value += $(if ($isV6) {'/128'} else {'/32'}) }
    $ipPart = $value.Split('/')[0]
    $prefixPart = $value.Split('/')[1]
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($ipPart,[ref]$parsedIp)) { throw (New-DERWorkloadFailureException -Message "Invalid IP/CIDR value: $InputValue") }
    $prefix = 0
    if (-not [int]::TryParse($prefixPart,[ref]$prefix)) { throw (New-DERWorkloadFailureException -Message "Invalid CIDR prefix: $InputValue") }
    if (($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and ($prefix -lt 0 -or $prefix -gt 32)) -or
        ($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and ($prefix -lt 0 -or $prefix -gt 128))) {
        throw (New-DERWorkloadFailureException -Message "Invalid CIDR prefix length: $InputValue")
    }
    return [ordered]@{
        '@odata.type' = $(if ($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {'#microsoft.graph.iPv6CidrRange'} else {'#microsoft.graph.iPv4CidrRange'})
        cidrAddress = $value
    }
}

function ConvertTo-DERCountryCode {
    param([Parameter(Mandatory)][string]$Country)
    $candidate = $Country.Trim()
    if ($candidate -match '^[A-Za-z]{2}$') { return $candidate.ToUpperInvariant() }
    $aliases = @{
        'United States'='US';'USA'='US';'United States of America'='US';'United Kingdom'='GB';'UK'='GB';'Great Britain'='GB';
        'Canada'='CA';'Mexico'='MX';'Australia'='AU';'New Zealand'='NZ';'Ireland'='IE';'Germany'='DE';'France'='FR';
        'Spain'='ES';'Italy'='IT';'Netherlands'='NL';'Belgium'='BE';'Switzerland'='CH';'Austria'='AT';'Poland'='PL';
        'India'='IN';'Japan'='JP';'South Korea'='KR';'Korea'='KR';'Singapore'='SG';'Brazil'='BR';'Argentina'='AR';
        'Puerto Rico'='PR';'US Virgin Islands'='VI'
    }
    if ($aliases.ContainsKey($candidate)) { return $aliases[$candidate] }
    try {
        foreach ($culture in [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)) {
            try {
                $region = [System.Globalization.RegionInfo]::new($culture.Name)
                if ($region.EnglishName -ieq $candidate -or $region.DisplayName -ieq $candidate -or $region.NativeName -ieq $candidate) {
                    return $region.TwoLetterISORegionName.ToUpperInvariant()
                }
            } catch {
                # Some platform cultures have no usable RegionInfo mapping.
                # Continue scanning other cultures; no tenant state is involved.
                $null=$_.Exception.Message
            }
        }
    } catch {
        # Runtime culture enumeration is a local conversion fallback only.
        $null=$_.Exception.Message
    }
    throw (New-DERWorkloadFailureException -Message "DER could not convert country/region '$Country' to a two-letter ISO region code. Enter a two-letter code such as US, CA, or GB.")
}

function New-DERNamedLocationBody {
    param([Parameter(Mandatory)]$PlannedObject)
    if ([string]$PlannedObject.DerId -eq 'DER-LOC-COUNTRY-010') {
        $codes = @($PlannedObject.Metadata.Countries | ForEach-Object { ConvertTo-DERCountryCode -Country ([string]$_) } | Sort-Object -Unique)
        if (-not $codes.Count) { throw (New-DERWorkloadFailureException -Message 'Approved countries Named Location has no countries/regions.') }
        return [ordered]@{
            '@odata.type' = '#microsoft.graph.countryNamedLocation'
            displayName = [string]$PlannedObject.DisplayName
            countriesAndRegions = $codes
            includeUnknownCountriesAndRegions = $false
            countryLookupMethod = 'clientIpAddress'
        }
    }

    $meta = $PlannedObject.Metadata
    $rawRanges = New-Object System.Collections.Generic.List[string]
    if ($meta) {
        if ($meta.PSObject.Properties.Name -contains 'IPv4') { foreach($r in @($meta.IPv4)) { if ($r) {$rawRanges.Add([string]$r)} } }
        if ($meta.PSObject.Properties.Name -contains 'IPv6') { foreach($r in @($meta.IPv6)) { if ($r) {$rawRanges.Add([string]$r)} } }
        if ($meta.PSObject.Properties.Name -contains 'IPs')   { foreach($r in @($meta.IPs))   { if ($r) {$rawRanges.Add([string]$r)} } }
    }
    $ranges = @($rawRanges | ForEach-Object { ConvertTo-DERCidrRange -InputValue $_ })
    if (-not $ranges.Count) { throw (New-DERWorkloadFailureException -Message "Named Location '$($PlannedObject.DisplayName)' has no valid public IP/CIDR ranges.") }
    $trusted = $false
    if ($meta -and $meta.PSObject.Properties.Name -contains 'Trusted') { $trusted = [bool]$meta.Trusted }
    return [ordered]@{
        '@odata.type' = '#microsoft.graph.ipNamedLocation'
        displayName = [string]$PlannedObject.DisplayName
        isTrusted = $trusted
        ipRanges = $ranges
    }
}

function Complete-DERNamedLocationsResult {
    param([System.Collections.Generic.List[object]]$Results,[string]$RunId)
    $s=[pscustomobject]@{
        Created=@($Results|Where-Object {$_.Status -eq 'Created'}).Count
        Existing=@($Results|Where-Object {$_.Status -eq 'Existing'}).Count
        Skipped=@($Results|Where-Object {$_.Status -eq 'Skipped'}).Count
        Failed=@($Results|Where-Object {$_.Status -eq 'Failed'}).Count
    }
    $out=[pscustomobject][ordered]@{Module='NamedLocations';RunId=$RunId;Status=if($s.Failed){'CompletedWithFailures'}elseif($s.Created-or$s.Existing){'Completed'}else{'Skipped'};CriticalFailure=$false;Summary=$s;Results=@($Results)}
    Save-DERNamedLocationsResult $out
    return $out
}

function Invoke-DERNamedLocationsModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$BuildPlan,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RuntimeRoot)

    $results = New-Object System.Collections.Generic.List[object]
    $planned = @($BuildPlan.Objects | Where-Object {$_.Enabled -and $_.Module -eq 'NamedLocations'})
    if (-not $planned.Count) { return Complete-DERNamedLocationsResult -Results $results -RunId $RunId }

    $existingLocations = @(Invoke-DERGraphCollectionRequest -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'v1.0' -Component 'NamedLocations' -ActionId 'LOC-SCAN')
    foreach ($p in $planned) {
        $actionId = if (Test-DERNamedLocationsCommand 'New-DERActionId') { New-DERActionId -Component 'LOC' } else { "LOC-$($p.DerId)" }
        try {
            $state = if (Test-DERNamedLocationsCommand 'Get-DERStateObject') { Get-DERStateObject -DerId $p.DerId } else { $null }
            if ($state) {
                Assert-DERManagedStateObject -StateRecord $state -Component 'NamedLocations' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$state.ObjectId;Status='Existing';Message='DER-managed Named Location exists and matches recorded Microsoft state.';ActionId=$actionId})
                continue
            }
            $collision = @($existingLocations | Where-Object {[string]$_.displayName -eq [string]$p.DisplayName})
            if ($collision.Count) {
                $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$collision[0].id;Status='Skipped';Message='Exact-name customer-owned Named Location exists; explicit adoption is required.';ActionId=$actionId})
                continue
            }
            $body = New-DERNamedLocationBody -PlannedObject $p
            if (Test-DERNamedLocationsCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase PRECHECK -Module 'NamedLocations' -DerId $p.DerId -Message 'Prepared DER Named Location create.' -Data $body | Out-Null }
            $created = Invoke-DERGraphRequest -Method POST -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'v1.0' -Body $body -Component 'NamedLocations' -DerId $p.DerId -ActionId $actionId
            if (-not $created.id) { throw (New-DERWorkloadFailureException -Message 'Named Location create response did not contain an object ID.') }
            $meta=[pscustomobject]@{Module='NamedLocations';ApiVersion='v1.0';ValidationUri=("identity/conditionalAccess/namedLocations/{0}" -f $created.id);DeleteUri=("identity/conditionalAccess/namedLocations/{0}" -f $created.id);ExpectedSubset=[pscustomobject]@{displayName=$p.DisplayName}}
            if (Test-DERNamedLocationsCommand 'Add-DERStateObject') { Add-DERStateObject -DerId $p.DerId -ObjectId $created.id -ObjectType $p.ObjectType -DisplayName $p.DisplayName -OwnershipClass 'DER-Owned' -Status Created -CreatedByRunId $RunId -BaselineVersion $BuildPlan.BaselineVersion -Metadata $meta | Out-Null }
            Assert-DERManagedStateObject -StateRecord (Get-DERStateObject -DerId $p.DerId) -Component 'NamedLocations' -ActionId $actionId -AllowedOwnershipClass @('DER-Owned') -MarkValidated | Out-Null
            if (Test-DERNamedLocationsCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase COMMIT -Module 'NamedLocations' -DerId $p.DerId -ObjectId $created.id -Message 'Named Location created and validated.' | Out-Null }
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;ObjectId=$created.id;Status='Created';Message='Named Location created and validated.';ActionId=$actionId})
            $existingLocations += $created
        } catch {
        $derCaughtError=$_
        $derFailureKind=if(Get-Command Get-DERFailureKindFromErrorRecord -ErrorAction SilentlyContinue){Get-DERFailureKindFromErrorRecord -ErrorRecord $derCaughtError}else{'Engine'}
        if(Get-Command Write-DERError -ErrorAction SilentlyContinue){Write-DERError -ErrorRecord $derCaughtError -Component 'NamedLocations' -ActionId $actionId -DerId $p.DerId}

            if (Test-DERNamedLocationsCommand 'Register-DERTransaction') { Register-DERTransaction -ActionId $actionId -Phase FAIL -Module 'NamedLocations' -DerId $p.DerId -Message $_.Exception.Message | Out-Null }
            $results.Add([pscustomobject]@{DerId=$p.DerId;DisplayName=$p.DisplayName;Status='Failed';FailureKind=$derFailureKind;Message=$_.Exception.Message;ActionId=$actionId})
        }
    }
    $out = Complete-DERNamedLocationsResult -Results $results -RunId $RunId
    Write-DERNamedLocationsLog -Level $(if($out.Summary.Failed){'WARN'}else{'OK'}) -Message 'Named Locations workload completed.' -Data $out.Summary
    return $out
}

Export-ModuleMember -Function @('ConvertTo-DERCidrRange','ConvertTo-DERCountryCode','New-DERNamedLocationBody','Invoke-DERNamedLocationsModule')
