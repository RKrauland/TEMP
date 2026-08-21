<#
.SYNOPSIS
    DER Microsoft Graph request engine.

.DESCRIPTION
    Centralizes Microsoft Graph REST traffic for DER, including URI handling,
    response metadata, request IDs, throttling, transient retries, paging, and
    forensic logging.

.NOTES
    Required parent entry point: Initialize-DERGraphEngine
#>


# Maintenance notes
# Responsibility: Sole production Microsoft Graph transport, retry policy, write guard, failure latch, SDK retry suppression, response-shape normalization, and write-outcome journaling boundary.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DERGraphContext = $null
$script:DERGraphCompatibilityCatalog = $null

function Test-DERLoggingCommand { param([Parameter(Mandatory)][string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }


function New-DERGraphControlException {
    <#
    .SYNOPSIS
        Creates a DER-tagged Graph control/safety exception.

    .DESCRIPTION
        Graph transport failures are tagged at their source so higher layers can
        preserve the distinction between ACTION failures (Microsoft/tenant/safety
        outcome) and ENGINE failures (DER/runtime/contract defect). ActionId is
        correlation only; callers must still select the correct FailureKind.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][ValidateSet('Action','Engine')][string]$FailureKind,
        [string]$ActionId,
        [string]$DerId,
        [string]$Component='Graph',
        $Data
    )
    $exception=[System.InvalidOperationException]::new($Message)
    $exception.Data['DERFailureKind']=$FailureKind
    if(-not [string]::IsNullOrWhiteSpace($ActionId)){$exception.Data['DERActionId']=$ActionId}
    if(-not [string]::IsNullOrWhiteSpace($DerId)){$exception.Data['DERDerId']=$DerId}
    if(-not [string]::IsNullOrWhiteSpace($Component)){$exception.Data['DERComponent']=$Component}
    if($null -ne $Data){$exception.Data['DERFailureData']=$Data}
    if((Get-Command New-DERIncidentId -ErrorAction SilentlyContinue)){$exception.Data['DERIncidentId']=New-DERIncidentId}
    return $exception
}

function Get-DERGraphExceptionIncidentId {
    <#
    .SYNOPSIS
        Returns the stable DER incident identifier carried by an exception.

    .DESCRIPTION
        One Graph failure can be observed at several layers: the transport,
        failure latch, workload, and parent orchestrator. This helper makes those
        observations one forensic incident instead of manufacturing a new
        incident at each logging boundary.
    #>
    param([Parameter(Mandatory)][System.Exception]$Exception)

    if($Exception.Data -and $Exception.Data.Contains('DERIncidentId')){
        $existing=[string]$Exception.Data['DERIncidentId']
        if(-not [string]::IsNullOrWhiteSpace($existing)){return $existing}
    }

    $incidentId=if(Get-Command 'New-DERIncidentId' -ErrorAction SilentlyContinue){
        New-DERIncidentId
    }else{
        'DER-ERR-{0}' -f ([guid]::NewGuid().ToString('N').ToUpperInvariant())
    }
    if($Exception.Data){$Exception.Data['DERIncidentId']=$incidentId}
    return $incidentId
}

function Write-DERGraphEngineLog {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$ActionId,
        [string]$DerId,
        [ValidateSet('Auto','None','Action','Engine')][string]$FailureKind='Auto',
        [string]$IncidentId,
        $Data
    )
    if (Test-DERLoggingCommand -Name 'Write-DERLog') {
        Write-DERLog -Level $Level -Component 'Graph' -ActionId $ActionId -DerId $DerId -FailureKind $FailureKind -IncidentId $IncidentId -Message $Message -Data $Data
    }
}

function Write-DERGraphForensic {
    param([Parameter(Mandatory)]$Data)
    if (Test-DERLoggingCommand -Name 'Write-DERGraphLog') { Write-DERGraphLog -Data $Data }
}

function Get-DERGraphEngineContext {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERGraphContext) {return $null}
    return [pscustomobject]@{
        Initialized=$script:DERGraphContext.Initialized;RunId=$script:DERGraphContext.RunId;Environment=$script:DERGraphContext.Environment;
        GraphEndpoint=$script:DERGraphContext.GraphEndpoint;DefaultApi=$script:DERGraphContext.DefaultApi;MaxRetries=$script:DERGraphContext.MaxRetries;
        BaseRetrySeconds=$script:DERGraphContext.BaseRetrySeconds;AllowPreviewWrites=$script:DERGraphContext.AllowPreviewWrites;
        WriteGuardMode=$script:DERGraphContext.WriteGuardMode;WriteGuardReason=$script:DERGraphContext.WriteGuardReason;
        WriteFailureLatched=[bool]$script:DERGraphContext.WriteFailureLatched;WriteFailureReason=$script:DERGraphContext.WriteFailureReason;
        RollbackWriteWindow=[bool]$script:DERGraphContext.RollbackWriteWindow;RollbackWriteReason=$script:DERGraphContext.RollbackWriteReason;
        SdkRetrySuppressed=[bool]$script:DERGraphContext.SdkRetrySuppressed;
        RequestAttemptCount=$script:DERGraphContext.RequestAttemptCount;TransportRequestCount=$script:DERGraphContext.TransportRequestCount;
        TransportReadCount=$script:DERGraphContext.TransportReadCount;TransportWriteCount=$script:DERGraphContext.TransportWriteCount;BlockedWriteCount=$script:DERGraphContext.BlockedWriteCount;
        CompatibilityCatalogPath=$script:DERGraphContext.CompatibilityCatalogPath;CompatibilityCatalogVersion=$script:DERGraphContext.CompatibilityCatalogVersion;InitializedAt=$script:DERGraphContext.InitializedAt
    }
}

function Initialize-DERGraphEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [string]$PackageRoot,
        [ValidateRange(0,10)][int]$MaxRetries=5,
        [ValidateRange(1,60)][int]$BaseRetrySeconds=2
    )
    foreach ($command in @('Invoke-MgGraphRequest','Get-MgContext','Set-MgRequestContext')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {throw "DER Graph engine requires $command. Microsoft.Graph.Authentication is not loaded or is too old."}
    }

    if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Split-Path -Parent $PSScriptRoot }
    $catalogPath = Join-Path $PackageRoot 'Definitions\Compatibility\DER-CompatibilityCatalog.json'
    if (-not (Test-Path -LiteralPath $catalogPath)) { throw "DER Graph compatibility catalog is missing: $catalogPath" }
    try {
        $script:DERGraphCompatibilityCatalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch { throw "DER Graph compatibility catalog is unreadable: $($_.Exception.Message)" }
    if (-not $script:DERGraphCompatibilityCatalog -or [string]$script:DERGraphCompatibilityCatalog.schemaVersion -ne '1.0') { throw 'DER Graph compatibility catalog schema version is unsupported.' }

    $script:DERGraphContext=[pscustomobject][ordered]@{
        Initialized=$true;RunId=$RunId;Environment='Global';GraphEndpoint='https://graph.microsoft.com';DefaultApi='v1.0';
        MaxRetries=$MaxRetries;BaseRetrySeconds=$BaseRetrySeconds;AllowPreviewWrites=$false;WriteGuardMode='Normal';WriteGuardReason=$null;
        WriteFailureLatched=$false;WriteFailureReason=$null;RollbackWriteWindow=$false;RollbackWriteReason=$null;SdkRetrySuppressed=$false;
        RequestAttemptCount=[long]0;TransportRequestCount=[long]0;TransportReadCount=[long]0;TransportWriteCount=[long]0;BlockedWriteCount=[long]0;
        AttemptByMethod=[ordered]@{GET=[long]0;POST=[long]0;PATCH=[long]0;PUT=[long]0;DELETE=[long]0};
        TransportByMethod=[ordered]@{GET=[long]0;POST=[long]0;PATCH=[long]0;PUT=[long]0;DELETE=[long]0};
        CompatibilityCatalogPath=$catalogPath;CompatibilityCatalogVersion=[string]$script:DERGraphCompatibilityCatalog.catalogVersion;InitializedAt=Get-Date
    }
    Assert-DERGraphSdkRetryDisabled | Out-Null
    Write-DERGraphEngineLog -Level OK -Message 'DER Graph engine initialized with Microsoft.Graph SDK retry middleware disabled. Preview writes remain fail-closed until explicitly enabled.' -Data (Get-DERGraphEngineContext)
    return Get-DERGraphEngineContext
}

function Assert-DERGraphSdkRetryDisabled {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    try {
        Set-MgRequestContext -MaxRetry 0 -ErrorAction Stop | Out-Null
        $script:DERGraphContext.SdkRetrySuppressed=$true
    } catch {
        $script:DERGraphContext.SdkRetrySuppressed=$false
        throw "DER cannot guarantee single-owner Graph retry behavior because Microsoft.Graph retry suppression failed: $($_.Exception.Message)"
    }
    return $true
}

function Assert-DERGraphWriteInfrastructure {
    [CmdletBinding()]
    param()
    if (-not (Get-Command 'Get-DERStateContext' -ErrorAction SilentlyContinue) -or -not (Get-Command 'Register-DERTransaction' -ErrorAction SilentlyContinue)) {
        throw 'DER blocked a Graph write because tenant state/transaction infrastructure is not loaded.'
    }
    $stateContext=Get-DERStateContext
    if (-not $stateContext -or -not [bool]$stateContext.Initialized) { throw 'DER blocked a Graph write because tenant state is not initialized.' }
    if ([string]$stateContext.RunId -ne [string]$script:DERGraphContext.RunId) { throw 'DER blocked a Graph write because Graph and State RunId values do not match.' }
    if ([string]::IsNullOrWhiteSpace([string]$stateContext.TransactionJournalPath)) { throw 'DER blocked a Graph write because the transaction journal path is not initialized.' }
    if ([string]::IsNullOrWhiteSpace([string]$stateContext.CurrentStatePath) -or -not (Test-Path -LiteralPath $stateContext.CurrentStatePath)) { throw 'DER blocked a Graph write because CurrentState.json is not initialized.' }
    return $stateContext
}

function Set-DERGraphRollbackWriteWindow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$Enabled,[string]$Reason)
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    $script:DERGraphContext.RollbackWriteWindow=$Enabled
    $script:DERGraphContext.RollbackWriteReason=if($Enabled){$Reason}else{$null}
    Write-DERGraphEngineLog -Level $(if($Enabled){'WARN'}else{'INFO'}) -Message ("DER rollback-only Graph write window {0}." -f $(if($Enabled){'opened'}else{'closed'})) -Data @{reason=$Reason;failureLatched=$script:DERGraphContext.WriteFailureLatched}
    return Get-DERGraphEngineContext
}

function Set-DERGraphWriteFailureLatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Reason,
        [string]$ActionId,[string]$Component,[string]$Uri,[string]$Method,[string]$DerId,$Data,
        [bool]$RequiresRecovery=$true,
        [ValidateSet('Action','Engine')][string]$FailureKind='Action',
        [string]$IncidentId
    )
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    $script:DERGraphContext.WriteFailureLatched=$true
    $script:DERGraphContext.WriteFailureReason=$Reason
    Write-DERGraphEngineLog -Level CRITICAL -ActionId $ActionId -DerId $DerId -FailureKind $FailureKind -IncidentId $IncidentId -Message $(if($RequiresRecovery){'DER latched normal tenant writes off because a write outcome is uncertain.'}else{'DER latched normal tenant writes off after a definite Graph write failure.'}) -Data @{reason=$Reason;component=$Component;method=$Method;uri=$Uri;requiresRecovery=$RequiresRecovery;details=$Data}
    if (Get-Command 'Set-DERRunState' -ErrorAction SilentlyContinue) {
        $status=if($RequiresRecovery){'RecoveryRequired'}else{'Failed'}
        $stage=if($RequiresRecovery){'WriteUncertain'}else{'WriteFailed'}
        $runData=@{actionId=$ActionId;component=$Component;derId=$DerId;method=$Method;uri=$Uri;requiresRecovery=$RequiresRecovery;details=$Data}
        try {
            if($RequiresRecovery){Set-DERRunState -Status $status -Stage $stage -Message $Reason -Data $runData -RecoveryEvidence $runData | Out-Null}
            else{Set-DERRunState -Status $status -Stage $stage -Message $Reason -Data $runData | Out-Null}
        }
        catch { Write-DERGraphEngineLog -Level CRITICAL -ActionId $ActionId -Message ("Unable to persist write-failure run state: {0}" -f $_.Exception.Message) }
    }
    return Get-DERGraphEngineContext
}

function Get-DERGraphResponseObjectId {
    param($Response,[string]$ResolvedUri,[Parameter(Mandatory)][ValidateSet('POST','PATCH','PUT','DELETE')][string]$Method)
    $responseId=Get-DERGraphPropertyValue -InputObject $Response -Name 'id'
    if (-not [string]::IsNullOrWhiteSpace([string]$responseId)) { return [string]$responseId }

    # Never invent an ObjectId for a POST collection create that returned no id.
    # For PATCH/PUT/DELETE, URI inference is allowed only when the final segment is
    # an actual GUID-shaped Microsoft ObjectId. Singleton resource names such as
    # authorizationPolicy are not ObjectIds and must remain unknown in the journal.
    if ($Method -eq 'POST') { return $null }
    try {
        $segments=@(([uri]$ResolvedUri).AbsolutePath.Trim('/') -split '/')
        if ($segments.Count -gt 0) {
            $candidate=[string]$segments[-1]
            $parsedGuid=[guid]::Empty
            if ([guid]::TryParse($candidate,[ref]$parsedGuid)) { return $candidate }
        }
    }
    catch { Write-DERGraphEngineLog -Level DEBUG -Message ("Could not infer ObjectId from Graph URI: {0}" -f $_.Exception.Message) }
    return $null
}

function Register-DERGraphWriteEvent {
    param([Parameter(Mandatory)][string]$ActionId,[Parameter(Mandatory)][string]$Phase,[string]$Component,[string]$DerId,[string]$ObjectId,[string]$Message,$Data)
    Register-DERTransaction -ActionId $ActionId -Phase $Phase -Module $Component -DerId $DerId -ObjectId $ObjectId -Message $Message -Data $Data | Out-Null
}

function Set-DERGraphWriteGuard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Normal','DenyAll')][string]$Mode,
        [string]$Reason
    )
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    $script:DERGraphContext.WriteGuardMode = $Mode
    $script:DERGraphContext.WriteGuardReason = if ($Reason) { $Reason } else { $null }
    Write-DERGraphEngineLog -Level $(if($Mode -eq 'DenyAll'){'WARN'}else{'INFO'}) -Message ("DER Graph write guard set to {0}." -f $Mode) -Data @{mode=$Mode;reason=$script:DERGraphContext.WriteGuardReason}
    Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;phase='write-guard';mode=$Mode;reason=$script:DERGraphContext.WriteGuardReason;transportInvoked=$false})
    return Get-DERGraphEngineContext
}

function Get-DERGraphRequestAuditSummary {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    return [pscustomobject][ordered]@{
        RunId=$script:DERGraphContext.RunId
        WriteGuardMode=$script:DERGraphContext.WriteGuardMode
        WriteGuardReason=$script:DERGraphContext.WriteGuardReason
        RequestAttemptCount=[long]$script:DERGraphContext.RequestAttemptCount
        TransportRequestCount=[long]$script:DERGraphContext.TransportRequestCount
        TransportReadCount=[long]$script:DERGraphContext.TransportReadCount
        TransportWriteCount=[long]$script:DERGraphContext.TransportWriteCount
        BlockedWriteCount=[long]$script:DERGraphContext.BlockedWriteCount
        AttemptByMethod=[pscustomobject]$script:DERGraphContext.AttemptByMethod
        TransportByMethod=[pscustomobject]$script:DERGraphContext.TransportByMethod
    }
}

function Set-DERGraphPreviewPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][bool]$AllowPreviewWrites)
    if ($null -eq $script:DERGraphContext) { throw 'DER Graph engine has not been initialized.' }
    $script:DERGraphContext.AllowPreviewWrites = $AllowPreviewWrites
    Write-DERGraphEngineLog -Level $(if($AllowPreviewWrites){'WARN'}else{'INFO'}) -Message ("DER Preview API write policy set to {0}." -f $(if($AllowPreviewWrites){'ALLOWLIST-ONLY'}else{'DENY'})) -Data @{allowPreviewWrites=$AllowPreviewWrites;catalogVersion=$script:DERGraphContext.CompatibilityCatalogVersion}
    return Get-DERGraphEngineContext
}

function Get-DERGraphCompatibilityRelativeUri {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$ApiVersion)
    $value = $Uri.Trim()
    if ($value -match '^https://') {
        $value = ([uri]$value).PathAndQuery.TrimStart('/')
    }
    $value = $value.TrimStart('/')
    if ($value -match '^(v1\.0|beta)/') { $value = $value.Substring($value.IndexOf('/') + 1) }
    $q = $value.IndexOf('?')
    if ($q -ge 0) { $value = $value.Substring(0,$q) }
    return $value.Trim('/')
}

function Assert-DERGraphWriteCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('POST','PATCH','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('v1.0','beta')][string]$ApiVersion,
        [string]$Component='Graph'
    )
    if ($ApiVersion -ne 'beta') { return $true }
    if ($null -eq $script:DERGraphContext -or $null -eq $script:DERGraphCompatibilityCatalog) { throw 'DER cannot evaluate Preview API safety because the Graph compatibility catalog is not initialized.' }
    if (-not [bool]$script:DERGraphContext.AllowPreviewWrites) { throw (New-DERGraphControlException -Message "DER blocked Graph beta $Method because Preview API writes are disabled for this run." -FailureKind Action -Component $Component) }

    $relative = Get-DERGraphCompatibilityRelativeUri -Uri $Uri -ApiVersion $ApiVersion
    $compatibilityMatches = @($script:DERGraphCompatibilityCatalog.entries | Where-Object {
        [string]$_.apiVersion -eq 'beta' -and [bool]$_.previewWriteAllowed -and @($_.methods) -contains $Method -and $relative -match ([string]$_.relativeUriRegex)
    })
    if ($Component -and $Component -notin @('Rollback','Recovery','Graph')) {
        # Intentional contract: Preview-write Component is the workload safety
        # identity and must exactly match the compatibility-catalog module name.
        # DER.Windows/Stabilization tests regression-check this string coupling so
        # a future workload rename fails visibly instead of widening Preview access.
        $compatibilityMatches = @($compatibilityMatches | Where-Object { [string]$_.module -eq $Component })
    }
    if (-not $compatibilityMatches.Count) { throw (New-DERGraphControlException -Message "DER Safe Preview blocked beta $Method '$relative' for component '$Component' because no enabled compatibility-catalog entry matches it." -FailureKind Action -Component $Component -Data @{method=$Method;relativeUri=$relative;apiVersion=$ApiVersion}) }
    return $true
}

function Get-DERGraphCompatibilityCatalog {
    [CmdletBinding()]
    param()
    if ($null -eq $script:DERGraphCompatibilityCatalog) { return $null }
    return $script:DERGraphCompatibilityCatalog
}

function Set-DERGraphEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Global','USGov','USGovDoD','China','BleuCloud','DelosCloud','GovSGCloud')][string]$Environment)
    if ($null -eq $script:DERGraphContext) {throw 'DER Graph engine has not been initialized.'}
    $endpoint=switch ($Environment) {
        'Global' {'https://graph.microsoft.com'};'USGov' {'https://graph.microsoft.us'};'USGovDoD' {'https://dod-graph.microsoft.us'};
        'China' {'https://microsoftgraph.chinacloudapi.cn'};'BleuCloud' {'https://graph.svc.sovcloud.fr'};
        'DelosCloud' {'https://graph.svc.sovcloud.de'};'GovSGCloud' {'https://graph.svc.sovcloud.sg'}
    }
    $script:DERGraphContext.Environment=$Environment;$script:DERGraphContext.GraphEndpoint=$endpoint
    Write-DERGraphEngineLog -Level INFO -Message ("Graph environment set to {0}." -f $Environment) -Data @{graphEndpoint=$endpoint}
    return Get-DERGraphEngineContext
}

function Resolve-DERGraphUri {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri,[ValidateSet('v1.0','beta')][string]$ApiVersion='v1.0')
    if ($null -eq $script:DERGraphContext) {throw 'DER Graph engine has not been initialized.'}
    $trimmed=$Uri.Trim()
    if ($trimmed -match '^https://') {
        $absolute=$null;$expected=$null
        try {$absolute=[uri]$trimmed;$expected=[uri]$script:DERGraphContext.GraphEndpoint}
        catch {throw "DER rejected an invalid absolute Microsoft Graph URI: $Uri"}
        if ($absolute.Scheme -ne 'https' -or $absolute.Host -ine $expected.Host -or $absolute.Port -ne $expected.Port) {
            throw "DER rejected an off-host Graph URI '$Uri'. Absolute Graph URLs must remain on '$($expected.Host)'."
        }
        return $absolute.AbsoluteUri
    }
    if ($trimmed -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { throw "DER rejected non-HTTPS Graph URI '$Uri'." }
    $relative=$trimmed.TrimStart('/')
    if ($relative -match '^(v1\.0|beta)/') {return ('{0}/{1}' -f $script:DERGraphContext.GraphEndpoint.TrimEnd('/'),$relative)}
    return ('{0}/{1}/{2}' -f $script:DERGraphContext.GraphEndpoint.TrimEnd('/'),$ApiVersion,$relative)
}

function Get-DERHeaderValue {
    param($Headers,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Headers) {return $null}
    try {
        if ($Headers -is [System.Collections.IDictionary]) {
            foreach ($key in $Headers.Keys) {
                if ([string]$key -ieq $Name) {
                    $value=$Headers[$key]
                    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {return (@($value)-join ',')}
                    return [string]$value
                }
            }
        }
        $property=$Headers.PSObject.Properties|Where-Object {$_.Name -ieq $Name}|Select-Object -First 1
        if ($property) {
            $value=$property.Value
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {return (@($value)-join ',')}
            return [string]$value
        }
    } catch {return $null}
    return $null
}

function Get-DERGraphPropertyValue {
    param($InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) { return $InputObject[$key] }
        }
        return $null
    }
    $property=$InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($property) { return $property.Value }
    return $null
}

function Test-DERGraphProperty {
    param($InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { if ([string]$key -ieq $Name) { return $true } }
        return $false
    }
    return [bool]($InputObject.PSObject.Properties.Name -icontains $Name)
}

function Get-DERRetryDelaySeconds {
    param($ResponseHeaders,[Parameter(Mandatory)][int]$Attempt)
    $retryAfter=Get-DERHeaderValue -Headers $ResponseHeaders -Name 'Retry-After'
    if ($retryAfter) {
        $seconds=0
        if ([int]::TryParse($retryAfter,[ref]$seconds)) {return [Math]::Max(1,$seconds)}
        $retryDate=[datetime]::MinValue
        $dateStyle=[System.Globalization.DateTimeStyles]::AllowWhiteSpaces -bor [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse($retryAfter,[System.Globalization.CultureInfo]::InvariantCulture,$dateStyle,[ref]$retryDate)) {
            $delay=[int][Math]::Ceiling(($retryDate-[datetime]::UtcNow).TotalSeconds)
            return [Math]::Max(1,$delay)
        }
    }
    $base=$script:DERGraphContext.BaseRetrySeconds*[Math]::Pow(2,[Math]::Max(0,$Attempt-1))
    $jitter=Get-Random -Minimum 0 -Maximum 750
    return [int][Math]::Ceiling($base+($jitter/1000.0))
}

function Test-DERGraphTransientStatus { param([int]$StatusCode) return ($StatusCode -eq 429 -or $StatusCode -eq 408 -or ($StatusCode -ge 500 -and $StatusCode -le 599)) }

function Get-DERGraphErrorMessage {
    param($ResponseBody,[int]$StatusCode)
    if ($null -eq $ResponseBody) {return "Microsoft Graph request failed with HTTP $StatusCode."}
    try {
        if ($ResponseBody.error) {
            $code=$ResponseBody.error.code;$message=$ResponseBody.error.message
            if ($code -and $message) {return "Microsoft Graph HTTP $StatusCode [$code]: $message"}
            if ($message) {return "Microsoft Graph HTTP $StatusCode: $message"}
        }
    } catch {
        # Error-body property inspection is diagnostic only. Fall through to the
        # JSON formatter without changing request/retry semantics.
        $null=$_.Exception.Message
    }
    try {
        $text=$ResponseBody|ConvertTo-Json -Depth 8 -Compress
        if ($text.Length -gt 1500) {$text=$text.Substring(0,1500)+'...[TRUNCATED]'}
        return "Microsoft Graph HTTP $StatusCode: $text"
    } catch {return "Microsoft Graph request failed with HTTP $StatusCode."}
}

function Assert-DERGraphSession {
    [CmdletBinding()]
    param()
    $context=Get-MgContext
    if (-not $context -or -not $context.TenantId) {throw 'DER is not authenticated to Microsoft Graph. Connect-DERDiscoverySession or Connect-DERWriteSession must run first.'}
    return $context
}

function Invoke-DERGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH','PUT','DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('v1.0','beta')][string]$ApiVersion='v1.0',
        $Body,[System.Collections.IDictionary]$Headers,[string]$ActionId,[string]$Component='Graph',[string]$DerId,
        [ValidateRange(-1,10)][int]$MaxRetries=-1,[switch]$AllowNotFound,[switch]$PassResponseMetadata
    )
    if ($null -eq $script:DERGraphContext) {throw 'DER Graph engine has not been initialized.'}
    $script:DERGraphContext.RequestAttemptCount++
    $script:DERGraphContext.AttemptByMethod[$Method] = [long]$script:DERGraphContext.AttemptByMethod[$Method] + 1
    $resolvedUri=Resolve-DERGraphUri -Uri $Uri -ApiVersion $ApiVersion
    $isWrite=($Method -ne 'GET')
    if($AllowNotFound -and $isWrite){throw 'DER AllowNotFound is valid only for Graph GET requests.'}
    $effectiveActionId=if(-not [string]::IsNullOrWhiteSpace($ActionId)){$ActionId}elseif(Get-Command 'New-DERActionId' -ErrorAction SilentlyContinue){New-DERActionId -Component 'GRAPH'}else{"GRAPH-$([guid]::NewGuid().ToString('N').Substring(0,12).ToUpperInvariant())"}

    if ($isWrite -and [string]$script:DERGraphContext.WriteGuardMode -eq 'DenyAll') {
        $script:DERGraphContext.BlockedWriteCount++
        Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;actionId=$effectiveActionId;component=$Component;phase='blocked-write';method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;transportInvoked=$false;guardMode=$script:DERGraphContext.WriteGuardMode;reason=$script:DERGraphContext.WriteGuardReason})
        $guardException=New-DERGraphControlException -Message ("DER NO-WRITE GUARD blocked Graph {0} '{1}' before Invoke-MgGraphRequest." -f $Method,$resolvedUri) -FailureKind Action -ActionId $effectiveActionId -DerId $DerId -Component $Component -Data @{method=$Method;uri=$resolvedUri;guardMode=$script:DERGraphContext.WriteGuardMode}
        $guardIncidentId=Get-DERGraphExceptionIncidentId -Exception $guardException
        Write-DERGraphEngineLog -Level CRITICAL -ActionId $effectiveActionId -DerId $DerId -FailureKind Action -IncidentId $guardIncidentId -Message ("DER no-write guard blocked Graph {0} before transport." -f $Method) -Data @{uri=$resolvedUri;component=$Component;guardMode=$script:DERGraphContext.WriteGuardMode}
        throw $guardException
    }
    $null=Assert-DERGraphSession
    if ($MaxRetries -lt 0) {$MaxRetries=$script:DERGraphContext.MaxRetries}
    if ($isWrite) {
        if([string]::IsNullOrWhiteSpace($DerId)){throw "DER Graph write rejected: every tenant write requires a non-empty DER ID for transaction/recovery correlation. Method=$Method; Uri=$resolvedUri"}
        $null=Assert-DERGraphWriteInfrastructure
        $null=Assert-DERGraphSdkRetryDisabled
        if([bool]$script:DERGraphContext.WriteFailureLatched -and -not [bool]$script:DERGraphContext.RollbackWriteWindow){
            $script:DERGraphContext.BlockedWriteCount++
            throw (New-DERGraphControlException -Message "DER blocked Graph $Method because a prior tenant write outcome is uncertain. Recovery/reconciliation is required before additional normal writes." -FailureKind Action -ActionId $effectiveActionId -DerId $DerId -Component $Component -Data @{method=$Method;uri=$resolvedUri;writeFailureReason=$script:DERGraphContext.WriteFailureReason})
        }
        if([bool]$script:DERGraphContext.RollbackWriteWindow -and $Component -notin @('Rollback','Recovery')){
            $script:DERGraphContext.BlockedWriteCount++
            throw "DER rollback-only write window rejected component '$Component'. Only the central Rollback/Recovery engines may write while this window is open."
        }
        $null = Assert-DERGraphWriteCompatibility -Method $Method -Uri $Uri -ApiVersion $ApiVersion -Component $Component
    }

    $clientRequestId=[guid]::NewGuid().ToString()
    $requestHeaders=[ordered]@{'client-request-id'=$clientRequestId;'return-client-request-id'='true';'Accept'='application/json'}
    if ($Headers) {foreach ($key in $Headers.Keys) {$requestHeaders[[string]$key]=$Headers[$key]}}

    if($isWrite){
        Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase EXECUTE -Component $Component -DerId $DerId -Message 'Central Graph transport is about to issue a tenant write. This request is never automatically replayed after an ambiguous outcome.' -Data @{method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;clientRequestId=$clientRequestId}
    }

    $attempt=0
    while ($attempt -le $MaxRetries) {
        $attempt++;$responseHeaders=$null;$statusCode=$null;$response=$null;$transportInvoked=$false;$timer=[System.Diagnostics.Stopwatch]::StartNew()
        Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;actionId=$effectiveActionId;component=$Component;phase='request';method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;clientRequestId=$clientRequestId;attempt=$attempt;headers=$requestHeaders;body=$Body})
        try {
            if($isWrite){$null=Assert-DERGraphSdkRetryDisabled}
            $p=@{Method=$Method;Uri=$resolvedUri;Headers=$requestHeaders;ResponseHeadersVariable='responseHeaders';StatusCodeVariable='statusCode';SkipHttpErrorCheck=$true;OutputType='PSObject';ErrorAction='Stop'}
            if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {$p.Body=$Body;$p.ContentType='application/json'}
            $script:DERGraphContext.TransportRequestCount++
            $script:DERGraphContext.TransportByMethod[$Method] = [long]$script:DERGraphContext.TransportByMethod[$Method] + 1
            if ($Method -eq 'GET') {$script:DERGraphContext.TransportReadCount++} else {$script:DERGraphContext.TransportWriteCount++}
            Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;actionId=$effectiveActionId;component=$Component;phase='transport-start';method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;clientRequestId=$clientRequestId;attempt=$attempt;transportInvoked=$false})
            $transportInvoked=$true
            $response=Invoke-MgGraphRequest @p
            $timer.Stop()
            $status=if ($null -eq $statusCode) {0} else {[int]$statusCode}
            $requestId=Get-DERHeaderValue -Headers $responseHeaders -Name 'request-id'
            if (-not $requestId) {$requestId=Get-DERHeaderValue -Headers $responseHeaders -Name 'x-ms-request-id'}
            Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;actionId=$effectiveActionId;component=$Component;phase='response';method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;clientRequestId=$clientRequestId;microsoftRequestId=$requestId;attempt=$attempt;statusCode=$status;durationMs=$timer.ElapsedMilliseconds;responseHeaders=$responseHeaders;responseBody=$response})

            if ($status -ge 200 -and $status -le 299) {
                if($isWrite){
                    $objectId=Get-DERGraphResponseObjectId -Response $response -ResolvedUri $resolvedUri -Method $Method
                    $phase=if($resolvedUri -match '/assign(?:ments)?(?:\?|$)'){'ASSIGNED'}elseif($Method -eq 'POST' -and -not [string]::IsNullOrWhiteSpace([string]$objectId)){'CREATED'}else{'UPDATED'}
                    try {
                        Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase $phase -Component $Component -DerId $DerId -ObjectId $objectId -Message 'Central Graph transport received a successful write response.' -Data @{method=$Method;uri=$resolvedUri;apiVersion=$ApiVersion;statusCode=$status;requestId=$requestId;clientRequestId=$clientRequestId;returnedObjectId=$objectId}
                    } catch {
                        $journalError=$_.Exception.Message
                        $ex=[System.InvalidOperationException]::new("DER WRITE_UNCERTAIN: Microsoft returned HTTP $status for $Method, but the success journal could not be persisted. ObjectId='$objectId'. $journalError")
                        $ex.Data['DERWriteOutcome']='Uncertain';$ex.Data['DERObjectId']=$objectId;$ex.Data['DERUri']=$resolvedUri;$ex.Data['DERFailureKind']='Engine';$ex.Data['DERActionId']=$effectiveActionId;$ex.Data['DERDerId']=$DerId;$ex.Data['DERComponent']=$Component
                        $incidentId=Get-DERGraphExceptionIncidentId -Exception $ex
                        Set-DERGraphWriteFailureLatch -Reason "Microsoft accepted a DER write, but DER could not persist the successful-write journal record. ObjectId='$objectId'. Recovery is required." -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{objectId=$objectId;journalError=$journalError} -FailureKind Engine -IncidentId $incidentId | Out-Null
                        throw $ex
                    }
                }
                Write-DERGraphEngineLog -Level DEBUG -ActionId $effectiveActionId -Message ("Graph {0} completed HTTP {1} in {2} ms." -f $Method,$status,$timer.ElapsedMilliseconds) -Data @{uri=$resolvedUri;requestId=$requestId;clientRequestId=$clientRequestId;attempt=$attempt}
                if ($PassResponseMetadata) {return [pscustomobject]@{Body=$response;StatusCode=$status;Headers=$responseHeaders;RequestId=$requestId;ClientRequestId=$clientRequestId;Attempt=$attempt;DurationMs=$timer.ElapsedMilliseconds;Uri=$resolvedUri;Method=$Method}}
                return $response
            }
            if ($status -eq 404 -and $AllowNotFound) {return $null}

            if($isWrite -and ($status -eq 408 -or $status -eq 0 -or ($status -ge 500 -and $status -le 599))){
                $message=Get-DERGraphErrorMessage -ResponseBody $response -StatusCode $status
                $exception=[System.InvalidOperationException]::new("DER WRITE_UNCERTAIN: $message The request was not replayed; rediscover and reconcile Microsoft state.")
                $exception.Data['DERStatusCode']=$status;$exception.Data['DERRequestId']=$requestId;$exception.Data['DERClientRequestId']=$clientRequestId;$exception.Data['DERUri']=$resolvedUri;$exception.Data['DERWriteOutcome']='Uncertain';$exception.Data['DERFailureKind']='Action';$exception.Data['DERActionId']=$effectiveActionId;$exception.Data['DERDerId']=$DerId;$exception.Data['DERComponent']=$Component
                $incidentId=Get-DERGraphExceptionIncidentId -Exception $exception
                try{Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase FAIL -Component $Component -DerId $DerId -Message 'Graph write outcome is uncertain; DER will not replay it.' -Data @{writeOutcome='Uncertain';statusCode=$status;method=$Method;uri=$resolvedUri;requestId=$requestId;clientRequestId=$clientRequestId}}catch{Write-DERGraphEngineLog -Level CRITICAL -ActionId $effectiveActionId -DerId $DerId -FailureKind Engine -Message ("Could not append uncertain-write FAIL journal record: {0}" -f $_.Exception.Message)}
                Set-DERGraphWriteFailureLatch -Reason "DER WRITE_UNCERTAIN after Graph HTTP $status. The $Method request will not be replayed automatically." -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{statusCode=$status;requestId=$requestId;clientRequestId=$clientRequestId} -IncidentId $incidentId | Out-Null
                throw $exception
            }

            $retryable = if($isWrite){$status -eq 429}else{Test-DERGraphTransientStatus -StatusCode $status}
            if ($retryable -and $attempt -le $MaxRetries) {
                $delay=Get-DERRetryDelaySeconds -ResponseHeaders $responseHeaders -Attempt $attempt
                Write-DERGraphEngineLog -Level WARN -ActionId $effectiveActionId -Message ("Graph HTTP {0}; retrying in {1}s (attempt {2}/{3})." -f $status,$delay,$attempt,($MaxRetries+1)) -Data @{requestId=$requestId;uri=$resolvedUri;write=$isWrite}
                Start-Sleep -Seconds $delay;continue
            }
            $message=Get-DERGraphErrorMessage -ResponseBody $response -StatusCode $status
            $exception=[System.InvalidOperationException]::new($message)
            $exception.Data['DERStatusCode']=$status;$exception.Data['DERRequestId']=$requestId;$exception.Data['DERClientRequestId']=$clientRequestId;$exception.Data['DERUri']=$resolvedUri;$exception.Data['DERFailureKind']='Action';$exception.Data['DERActionId']=$effectiveActionId;$exception.Data['DERDerId']=$DerId;$exception.Data['DERComponent']=$Component
            if($isWrite){$exception.Data['DERWriteOutcome']='DefiniteNoWrite'}
            $incidentId=Get-DERGraphExceptionIncidentId -Exception $exception
            if($isWrite){
                try{
                    Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase FAIL -Component $Component -DerId $DerId -Message 'Graph returned a definite non-success response; no automatic write replay will occur.' -Data @{writeOutcome='DefiniteNoWrite';statusCode=$status;method=$Method;uri=$resolvedUri;requestId=$requestId;clientRequestId=$clientRequestId}
                } catch {
                    $journalError=$_.Exception.Message
                    $journalException=[System.InvalidOperationException]::new("DER JOURNAL_FAILURE: Graph returned HTTP $status without applying the write, but the terminal FAIL event could not be persisted. $journalError")
                    $journalException.Data['DERWriteOutcome']='DefiniteNoWrite';$journalException.Data['DERStatusCode']=$status;$journalException.Data['DERUri']=$resolvedUri;$journalException.Data['DERFailureKind']='Engine';$journalException.Data['DERActionId']=$effectiveActionId;$journalException.Data['DERDerId']=$DerId;$journalException.Data['DERComponent']=$Component
                    $journalIncidentId=Get-DERGraphExceptionIncidentId -Exception $journalException
                    Set-DERGraphWriteFailureLatch -Reason 'Graph returned a definite no-write response, but DER could not persist the terminal FAIL journal event. Recovery review is required because the transaction journal is incomplete.' -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{statusCode=$status;journalError=$journalError} -RequiresRecovery $true -FailureKind Engine -IncidentId $journalIncidentId | Out-Null
                    throw $journalException
                }
                Set-DERGraphWriteFailureLatch -Reason "DER stopped further normal tenant writes after definite Graph HTTP $status for $Method." -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{statusCode=$status;requestId=$requestId;clientRequestId=$clientRequestId} -RequiresRecovery $false -IncidentId $incidentId | Out-Null
            }
            throw $exception
        } catch {
            if ($timer.IsRunning) {$timer.Stop()}
            # Preserve action correlation on the exception itself so higher
            # layers can classify/log it even after an intermediate catch.
            if($_.Exception -and $_.Exception.Data){
                if(-not $_.Exception.Data.Contains('DERActionId')){$_.Exception.Data['DERActionId']=$effectiveActionId}
                if(-not $_.Exception.Data.Contains('DERDerId')){$_.Exception.Data['DERDerId']=$DerId}
                if(-not $_.Exception.Data.Contains('DERComponent')){$_.Exception.Data['DERComponent']=$Component}
            }
            $knownStatus=$null
            if ($_.Exception.Data -and $_.Exception.Data.Contains('DERStatusCode')) {$knownStatus=[int]$_.Exception.Data['DERStatusCode']}
            $knownOutcome=$null
            if ($_.Exception.Data -and $_.Exception.Data.Contains('DERWriteOutcome')) {$knownOutcome=[string]$_.Exception.Data['DERWriteOutcome']}
            if ($null -ne $knownStatus -or $knownOutcome) {
                $failureKind=if($_.Exception.Data -and $_.Exception.Data.Contains('DERFailureKind')){[string]$_.Exception.Data['DERFailureKind']}else{'Action'}
                $incidentId=Get-DERGraphExceptionIncidentId -Exception $_.Exception
                Write-DERGraphEngineLog -Level ERROR -ActionId $effectiveActionId -DerId $DerId -FailureKind $failureKind -IncidentId $incidentId -Message $_.Exception.Message -Data @{statusCode=$knownStatus;writeOutcome=$knownOutcome;uri=$resolvedUri;attempt=$attempt}
                throw
            }
            Write-DERGraphForensic -Data ([ordered]@{timestamp=(Get-Date).ToString('o');runId=$script:DERGraphContext.RunId;actionId=$effectiveActionId;component=$Component;phase='exception';method=$Method;uri=$resolvedUri;clientRequestId=$clientRequestId;attempt=$attempt;durationMs=$timer.ElapsedMilliseconds;transportInvoked=$transportInvoked;exceptionType=$_.Exception.GetType().FullName;message=$_.Exception.Message})
            if($isWrite){
                $transportErrorRecord=$_
                $sourceIncidentId=Get-DERGraphExceptionIncidentId -Exception $transportErrorRecord.Exception
                if(-not $transportInvoked){
                    $originalError=$transportErrorRecord.Exception.Message
                    try{
                        Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase FAIL -Component $Component -DerId $DerId -Message 'Graph write failed before Microsoft.Graph transport invocation; DER can prove no request was sent.' -Data @{writeOutcome='DefiniteNoWrite';method=$Method;uri=$resolvedUri;clientRequestId=$clientRequestId;exceptionType=$transportErrorRecord.Exception.GetType().FullName;exception=$originalError;transportInvoked=$false}
                    } catch {
                        $journalError=$_.Exception.Message
                        $journalException=[System.InvalidOperationException]::new("DER JOURNAL_FAILURE: the $Method request was not sent, but the terminal pre-transport FAIL event could not be persisted. $journalError")
                        $journalException.Data['DERWriteOutcome']='DefiniteNoWrite';$journalException.Data['DERUri']=$resolvedUri;$journalException.Data['DERFailureKind']='Engine';$journalException.Data['DERActionId']=$effectiveActionId;$journalException.Data['DERDerId']=$DerId;$journalException.Data['DERComponent']=$Component
                        $journalIncidentId=Get-DERGraphExceptionIncidentId -Exception $journalException
                        Set-DERGraphWriteFailureLatch -Reason 'DER write preparation failed before transport, but DER could not persist the terminal FAIL event. Recovery review is required because the transaction journal is incomplete.' -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{originalError=$originalError;journalError=$journalError;transportInvoked=$false} -RequiresRecovery $true -FailureKind Engine -IncidentId $journalIncidentId | Out-Null
                        throw $journalException
                    }
                    $ex=[System.InvalidOperationException]::new("DER Graph write failed before transport; no Microsoft request was sent. Original error: $originalError")
                    $ex.Data['DERWriteOutcome']='DefiniteNoWrite';$ex.Data['DERUri']=$resolvedUri;$ex.Data['DERFailureKind']='Engine';$ex.Data['DERActionId']=$effectiveActionId;$ex.Data['DERDerId']=$DerId;$ex.Data['DERComponent']=$Component;$ex.Data['DERIncidentId']=$sourceIncidentId
                    Set-DERGraphWriteFailureLatch -Reason "DER stopped further normal tenant writes after a pre-transport failure for $Method. No Microsoft Graph request was sent." -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{clientRequestId=$clientRequestId;exception=$originalError;transportInvoked=$false} -RequiresRecovery $false -FailureKind Engine -IncidentId $sourceIncidentId | Out-Null
                    throw $ex
                }
                $originalError=$transportErrorRecord.Exception.Message
                try{Register-DERGraphWriteEvent -ActionId $effectiveActionId -Phase FAIL -Component $Component -DerId $DerId -Message 'Graph write transport exception produced an uncertain outcome; DER will not replay it.' -Data @{writeOutcome='Uncertain';method=$Method;uri=$resolvedUri;clientRequestId=$clientRequestId;exceptionType=$transportErrorRecord.Exception.GetType().FullName;exception=$originalError;transportInvoked=$true}}catch{Write-DERGraphEngineLog -Level CRITICAL -ActionId $effectiveActionId -DerId $DerId -FailureKind Engine -Message ("Could not append uncertain-write transport FAIL journal record: {0}" -f $_.Exception.Message)}
                $ex=[System.InvalidOperationException]::new("DER WRITE_UNCERTAIN: Graph/network transport failed after the $Method request may have reached Microsoft. DER will not replay it. Rediscover and reconcile state. Original error: $originalError")
                $ex.Data['DERWriteOutcome']='Uncertain';$ex.Data['DERClientRequestId']=$clientRequestId;$ex.Data['DERUri']=$resolvedUri;$ex.Data['DERFailureKind']='Action';$ex.Data['DERActionId']=$effectiveActionId;$ex.Data['DERDerId']=$DerId;$ex.Data['DERComponent']=$Component;$ex.Data['DERIncidentId']=$sourceIncidentId
                Set-DERGraphWriteFailureLatch -Reason 'DER WRITE_UNCERTAIN after a Graph/network transport exception. The write will not be replayed automatically.' -ActionId $effectiveActionId -Component $Component -Uri $resolvedUri -Method $Method -DerId $DerId -Data @{clientRequestId=$clientRequestId;exception=$originalError;transportInvoked=$true} -IncidentId $sourceIncidentId | Out-Null
                throw $ex
            }
            if ($attempt -le $MaxRetries) {
                $delay=Get-DERRetryDelaySeconds -ResponseHeaders $responseHeaders -Attempt $attempt
                Write-DERGraphEngineLog -Level WARN -ActionId $effectiveActionId -Message ("Transient Graph/network read exception; retrying in {0}s: {1}" -f $delay,$_.Exception.Message)
                Start-Sleep -Seconds $delay;continue
            }
            $_.Exception.Data['DERFailureKind']='Action'
            $incidentId=Get-DERGraphExceptionIncidentId -Exception $_.Exception
            Write-DERGraphEngineLog -Level ERROR -ActionId $effectiveActionId -FailureKind Action -IncidentId $incidentId -Message ("Graph read request failed after {0} attempt(s): {1}" -f $attempt,$_.Exception.Message) -Data @{uri=$resolvedUri;method=$Method;clientRequestId=$clientRequestId}
            throw
        }
    }
}

function Invoke-DERGraphCollectionRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri,[ValidateSet('v1.0','beta')][string]$ApiVersion='v1.0',[string]$ActionId,[string]$Component='Graph',[ValidateRange(1,10000)][int]$MaxPages=1000)
    $items=New-Object System.Collections.Generic.List[object]
    $nextUri=Resolve-DERGraphUri -Uri $Uri -ApiVersion $ApiVersion;$page=0
    while ($nextUri) {
        $page++;if ($page -gt $MaxPages) {throw (New-DERGraphControlException -Message "DER Graph paging exceeded MaxPages ($MaxPages) for $Uri." -FailureKind Action -ActionId $ActionId -Component $Component -Data @{uri=$Uri;maxPages=$MaxPages})}
        $response=Invoke-DERGraphRequest -Method GET -Uri $nextUri -ApiVersion $ApiVersion -ActionId $ActionId -Component $Component
        if ($null -eq $response) {break}
        if (Test-DERGraphProperty -InputObject $response -Name 'value') {
            foreach ($item in @((Get-DERGraphPropertyValue -InputObject $response -Name 'value'))) { $items.Add($item) }
        }
        else { $items.Add($response) }
        $nextLink=Get-DERGraphPropertyValue -InputObject $response -Name '@odata.nextLink'
        $nextUri=if ($nextLink) { [string]$nextLink } else { $null }
        Write-DERGraphEngineLog -Level DEBUG -ActionId $ActionId -Message ("Graph collection page {0} processed." -f $page) -Data @{sourceUri=$Uri;itemCount=$items.Count;hasNextPage=[bool]$nextUri}
    }
    return @($items)
}

function Test-DERGraphConnection {
    [CmdletBinding()]
    param()
    try {
        $response=Invoke-DERGraphRequest -Method GET -Uri 'organization?$select=id,displayName' -ApiVersion 'v1.0' -Component 'GraphTest' -MaxRetries 1
        return [pscustomobject]@{Success=$true;Organization=$response.value|Select-Object -First 1;Error=$null}
    } catch {return [pscustomobject]@{Success=$false;Organization=$null;Error=$_.Exception.Message}}
}

Export-ModuleMember -Function @('Initialize-DERGraphEngine','Get-DERGraphEngineContext','Set-DERGraphEnvironment','Set-DERGraphPreviewPolicy','Set-DERGraphWriteGuard','Set-DERGraphRollbackWriteWindow','Set-DERGraphWriteFailureLatch','Assert-DERGraphSdkRetryDisabled','Get-DERGraphRequestAuditSummary','Get-DERGraphCompatibilityCatalog','Resolve-DERGraphUri','Assert-DERGraphSession','Assert-DERGraphWriteCompatibility','Invoke-DERGraphRequest','Invoke-DERGraphCollectionRequest','Test-DERGraphConnection')
