<#
.SYNOPSIS
    DER centralized logging engine.

.DESCRIPTION
    Provides the centralized observability and failure-classification layer for
    the DER Intune / Entra Environment Builder. Every normal log event is
    correlated to the current Run ID and, when applicable, an Action ID and
    DER ID. Structured streams are redacted before persistence.

    DER deliberately distinguishes two failure origins:

      ENGINE - DER/PowerShell/runtime/infrastructure did not execute correctly.
               Examples include parameter binding, undefined variables,
               serialization, filesystem/state persistence, command-loading,
               and unexpected runtime exceptions.

      ACTION - DER executed the intended operation path, but Microsoft Graph,
               tenant state, validation, ownership, rollback validation, or a
               requested safety precondition prevented completion.

    Action ID is correlation only. It is never treated as proof that a failure
    was caused by Microsoft or the tenant. Untagged terminating exceptions fail
    toward ENGINE classification so DER does not hide its own defects inside an
    action/business-failure bucket.

    The logging engine writes a combined technical stream plus focused action,
    engine, Graph, validation, rollback, and error streams. Incident IDs allow
    the same underlying exception to be correlated when it is observed at more
    than one layer of the application.

.NOTES
    Required parent entry point: Initialize-DERLogging

    Safety contract:
      - Redact sensitive values before structured persistence.
      - Preserve Run/Action/DER correlation whenever the source provides it.
      - Preserve original exception diagnostics before a workload converts an
        exception into a friendly result object.
      - Keep ENGINE and ACTION failures in separate dedicated files.
      - Keep a combined error stream for one-place triage.
      - Treat logging persistence failures as engine/runtime failures; DER does
        not silently downgrade loss of forensic evidence.
      - Transcript capture is supplemental. Failure to start a transcript is
        logged as a warning because the structured forensic streams remain the
        authoritative diagnostic record.
#>


# Maintenance notes
# Responsibility: Owns structured/human logging, failure provenance, redaction, run/action/DER/incident correlation, and per-run log paths.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:DERLogContext = $null
[long]$script:DERActionCounter = 0
[long]$script:DERLogEventCounter = 0

# Incident sets count unique failures independently from the number of log events.
# A single exception can legitimately be logged at multiple layers while it
# propagates; DERIncidentId lets operators recognize those as one incident.
$script:DERAllIncidentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:DEREngineIncidentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:DERActionIncidentIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Test-DERLoggingInitialized {
    [CmdletBinding()]
    param()
    return ($null -ne $script:DERLogContext -and $script:DERLogContext.Initialized)
}

function Get-DERRedactionPattern {
    return '(?i)(authorization|access.?token|refresh.?token|id.?token|client.?secret|secret|password|passwd|pwd|credential|private.?key|recovery.?key|recovery.?password|bitlocker.?key|laps.?password|temporary.?access.?pass|tap.?value|certificate.?password)'
}

function Protect-DERLogData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$InputObject,
        [ValidateRange(0, 12)][int]$Depth = 0
    )

    process {
        if ($null -eq $InputObject) { return $null }
        if ($Depth -ge 10) { return '[MAX-DEPTH]' }

        if ($InputObject -is [string]) {
            $value = [string]$InputObject
            $value = $value -replace '(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED]'
            $value = $value -replace '(?i)\bBasic\s+[A-Za-z0-9\+\/]+=*', 'Basic [REDACTED]'
            $value = $value -replace '(?i)(client_secret|password|access_token|refresh_token|id_token)\s*[:=]\s*["'']?[^&\s,"'']+', '$1=[REDACTED]'
            return $value
        }

        if ($InputObject -is [System.Security.SecureString]) { return '[REDACTED]' }
        if ($InputObject -is [System.Management.Automation.PSCredential]) { return '[REDACTED-CREDENTIAL]' }

        if (
            $InputObject -is [bool] -or $InputObject -is [byte] -or
            $InputObject -is [int16] -or $InputObject -is [int32] -or $InputObject -is [int64] -or
            $InputObject -is [uint16] -or $InputObject -is [uint32] -or $InputObject -is [uint64] -or
            $InputObject -is [single] -or $InputObject -is [double] -or $InputObject -is [decimal] -or
            $InputObject -is [datetime] -or $InputObject -is [guid]
        ) { return $InputObject }

        $redactionPattern = Get-DERRedactionPattern

        if ($InputObject -is [System.Collections.IDictionary]) {
            $safe = [ordered]@{}
            foreach ($key in $InputObject.Keys) {
                $name = [string]$key
                if ($name -match $redactionPattern) { $safe[$name] = '[REDACTED]' }
                else { $safe[$name] = Protect-DERLogData -InputObject $InputObject[$key] -Depth ($Depth + 1) }
            }
            return $safe
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            $items = @()
            foreach ($item in $InputObject) {
                $items += ,(Protect-DERLogData -InputObject $item -Depth ($Depth + 1))
            }
            return $items
        }

        $properties = @($InputObject.PSObject.Properties | Where-Object {
            $_.MemberType -in @('NoteProperty','Property','AliasProperty','ScriptProperty')
        })

        if ($properties.Count -gt 0) {
            $safeObject = [ordered]@{}
            foreach ($property in $properties) {
                $name = [string]$property.Name
                if ($name -match $redactionPattern) {
                    $safeObject[$name] = '[REDACTED]'
                    continue
                }
                try { $safeObject[$name] = Protect-DERLogData -InputObject $property.Value -Depth ($Depth + 1) }
                catch { $safeObject[$name] = '[UNREADABLE]' }
            }
            return [pscustomobject]$safeObject
        }

        return [string]$InputObject
    }
}

function Add-DERTextLine {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Line)
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllText($Path, ($Line + [Environment]::NewLine), $utf8)
}

function Add-DERJsonLine {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Object)
    $safe = Protect-DERLogData -InputObject $Object
    try { $json = $safe | ConvertTo-Json -Depth 20 -Compress }
    catch {
        $json = [ordered]@{
            timestamp = (Get-Date).ToString('o')
            eventType = 'LoggingSerializationFailure'
            message   = $_.Exception.Message
        } | ConvertTo-Json -Compress
    }
    Add-DERTextLine -Path $Path -Line $json
}

function Get-DERLoggingContext {
    [CmdletBinding()]
    param()
    if (-not (Test-DERLoggingInitialized)) { return $null }
    return [pscustomobject]@{
        Initialized     = $script:DERLogContext.Initialized
        RunId           = $script:DERLogContext.RunId
        RuntimeRoot     = $script:DERLogContext.RuntimeRoot
        RunLogDirectory = $script:DERLogContext.RunLogDirectory
        HumanLog        = $script:DERLogContext.HumanLog
        TechnicalLog    = $script:DERLogContext.TechnicalLog
        EngineLog       = $script:DERLogContext.EngineLog
        ErrorLog        = $script:DERLogContext.ErrorLog
        StructuredErrorLog = $script:DERLogContext.StructuredErrorLog
        ActionLog       = $script:DERLogContext.ActionLog
        EngineErrorLog  = $script:DERLogContext.EngineErrorLog
        ActionErrorLog  = $script:DERLogContext.ActionErrorLog
        GraphLog        = $script:DERLogContext.GraphLog
        ValidationLog   = $script:DERLogContext.ValidationLog
        RollbackLog     = $script:DERLogContext.RollbackLog
        TranscriptLog   = $script:DERLogContext.TranscriptLog
        TranscriptOn    = $script:DERLogContext.TranscriptOn
        EngineVersion   = $script:DERLogContext.EngineVersion
        PackageVersion  = $script:DERLogContext.PackageVersion
        BuildNumber      = [int]$script:DERLogContext.BuildNumber
        BaselineVersion = $script:DERLogContext.BaselineVersion
        WarningCount     = [long]$script:DERLogContext.WarningCount
        TotalErrorCount  = [long]$script:DERLogContext.TotalErrorCount
        EngineErrorCount = [long]$script:DERLogContext.EngineErrorCount
        ActionErrorCount = [long]$script:DERLogContext.ActionErrorCount
        UniqueIncidentCount = [long]$script:DERAllIncidentIds.Count
        EngineIncidentCount = [long]$script:DEREngineIncidentIds.Count
        ActionIncidentCount = [long]$script:DERActionIncidentIds.Count
    }
}

function Get-DERLoggingSummary {
    [CmdletBinding()]
    param()
    if (-not (Test-DERLoggingInitialized)) { return $null }
    return [pscustomobject][ordered]@{
        RunId=$script:DERLogContext.RunId
        EngineVersion=$script:DERLogContext.EngineVersion
        PackageVersion=$script:DERLogContext.PackageVersion
        BuildNumber=[int]$script:DERLogContext.BuildNumber
        BaselineVersion=$script:DERLogContext.BaselineVersion
        WarningCount=[long]$script:DERLogContext.WarningCount
        TotalErrorCount=[long]$script:DERLogContext.TotalErrorCount
        EngineErrorCount=[long]$script:DERLogContext.EngineErrorCount
        ActionErrorCount=[long]$script:DERLogContext.ActionErrorCount
        UniqueIncidentCount=[long]$script:DERAllIncidentIds.Count
        EngineIncidentCount=[long]$script:DEREngineIncidentIds.Count
        ActionIncidentCount=[long]$script:DERActionIncidentIds.Count
        HumanLog=$script:DERLogContext.HumanLog
        TechnicalLog=$script:DERLogContext.TechnicalLog
        EngineLog=$script:DERLogContext.EngineLog
        ActionLog=$script:DERLogContext.ActionLog
        CombinedErrorLog=$script:DERLogContext.ErrorLog
        StructuredErrorLog=$script:DERLogContext.StructuredErrorLog
        EngineErrorLog=$script:DERLogContext.EngineErrorLog
        ActionErrorLog=$script:DERLogContext.ActionErrorLog
        GraphLog=$script:DERLogContext.GraphLog
        ValidationLog=$script:DERLogContext.ValidationLog
        RollbackLog=$script:DERLogContext.RollbackLog
        TranscriptLog=$script:DERLogContext.TranscriptLog
        LogIndex=$script:DERLogContext.LogIndex
    }
}


function New-DERIncidentId {
    [CmdletBinding()]
    param()
    return ('DER-ERR-{0}' -f ([guid]::NewGuid().ToString('N').ToUpperInvariant()))
}

function New-DERFailureException {
    <#
    .SYNOPSIS
        Creates an exception with DER failure-origin and correlation metadata.

    .DESCRIPTION
        Workload/core code should use this helper for deliberate terminating
        conditions whose origin is known. Unexpected PowerShell exceptions must
        not be converted to ACTION merely because they occurred while an action
        was in progress.

        The returned exception can be thrown normally. PowerShell preserves the
        Exception.Data values as the error travels through intermediate catch
        blocks, allowing Write-DERError to recover failure origin, incident,
        action, DER ID, and component at higher layers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][ValidateSet('Action','Engine')][string]$FailureKind,
        [string]$Component='Core',
        [string]$ActionId,
        [string]$DerId,
        [System.Exception]$InnerException,
        $Data
    )

    $exception = if ($InnerException) {
        [System.InvalidOperationException]::new($Message,$InnerException)
    } else {
        [System.InvalidOperationException]::new($Message)
    }

    $exception.Data['DERFailureKind']=$FailureKind
    $exception.Data['DERIncidentId']=New-DERIncidentId
    if(-not [string]::IsNullOrWhiteSpace($ActionId)){$exception.Data['DERActionId']=$ActionId}
    if(-not [string]::IsNullOrWhiteSpace($DerId)){$exception.Data['DERDerId']=$DerId}
    if(-not [string]::IsNullOrWhiteSpace($Component)){$exception.Data['DERComponent']=$Component}
    if($null -ne $Data){$exception.Data['DERFailureData']=$Data}
    return $exception
}

function Resolve-DERLogFailureKind {
    param(
        [ValidateSet('Auto','None','Action','Engine')][string]$FailureKind='Auto',
        [string]$ActionId,
        [string]$EventDomain='General'
    )
    if ($FailureKind -ne 'Auto') { return $FailureKind }
    if ($EventDomain -eq 'Action') { return 'Action' }
    if ($EventDomain -eq 'Engine') { return 'Engine' }
    # ActionId is correlation, not proof of provenance. An unclassified failure
    # defaults to ENGINE so DER never blames Microsoft/the tenant for its own bug.
    return 'Engine'
}

function Write-DERLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('TRACE','DEBUG','INFO','STEP','OK','WARN','ERROR','CRITICAL')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [string]$Component = 'Core',
        [string]$ActionId,
        [string]$DerId,
        [ValidateSet('General','Action','Engine')][string]$EventDomain = 'General',
        [ValidateSet('Auto','None','Action','Engine')][string]$FailureKind = 'Auto',
        [string]$IncidentId,
        $Data,
        [switch]$NoConsole
    )

    $now = Get-Date
    $timestamp = $now.ToString('yyyy-MM-dd HH:mm:ss.fff')
    $iso = $now.ToString('o')
    $isFailure = $Level -in @('ERROR','CRITICAL')
    $effectiveFailureKind = if ($isFailure) { Resolve-DERLogFailureKind -FailureKind $FailureKind -ActionId $ActionId -EventDomain $EventDomain } else { 'None' }
    if($isFailure -and [string]::IsNullOrWhiteSpace($IncidentId)){$IncidentId=New-DERIncidentId}

    if (-not $NoConsole) {
        $color = switch ($Level) {
            'TRACE' {'DarkGray'}; 'DEBUG' {'DarkGray'}; 'INFO' {'Gray'}; 'STEP' {'Cyan'};
            'OK' {'Green'}; 'WARN' {'Yellow'}; 'ERROR' {'Red'}; 'CRITICAL' {'Magenta'}; default {'Gray'}
        }
        $prefix = switch ($Level) {
            'STEP' {'[>]'}; 'OK' {'[+]'}; 'WARN' {'[!]'}; 'ERROR' {'[X]'}; 'CRITICAL' {'[!!]'}; default {'[i]'}
        }
        $actionText = if ($ActionId) { " [$ActionId]" } else { '' }
        $failureText = if ($isFailure) { " [$effectiveFailureKind]" } else { '' }
        Write-Host ("{0} {1} [{2}]{3}{4} {5}" -f $prefix,$timestamp,$Component,$actionText,$failureText,$Message) -ForegroundColor $color
    }

    if (-not (Test-DERLoggingInitialized)) { return }

    if($Level -eq 'WARN'){$script:DERLogContext.WarningCount=[long]$script:DERLogContext.WarningCount+1}
    if($isFailure){
        $script:DERLogContext.TotalErrorCount=[long]$script:DERLogContext.TotalErrorCount+1
        if($effectiveFailureKind -eq 'Action'){$script:DERLogContext.ActionErrorCount=[long]$script:DERLogContext.ActionErrorCount+1}
        elseif($effectiveFailureKind -eq 'Engine'){$script:DERLogContext.EngineErrorCount=[long]$script:DERLogContext.EngineErrorCount+1}
        if(-not [string]::IsNullOrWhiteSpace($IncidentId)){
            $null=$script:DERAllIncidentIds.Add($IncidentId)
            if($effectiveFailureKind -eq 'Action'){$null=$script:DERActionIncidentIds.Add($IncidentId)}
            elseif($effectiveFailureKind -eq 'Engine'){$null=$script:DEREngineIncidentIds.Add($IncidentId)}
        }
    }
    $script:DERLogEventCounter++
    $sequence = $script:DERLogEventCounter
    $eventId=('{0}:{1:D8}' -f $script:DERLogContext.RunId,$sequence)
    $actionText = if ($ActionId) { " [$ActionId]" } else { '' }
    $failureText = if ($isFailure) { " [$effectiveFailureKind]" } else { '' }
    Add-DERTextLine -Path $script:DERLogContext.HumanLog -Line (
        "{0} [{1}] [{2}]{3}{4} {5}" -f $timestamp,$Level,$Component,$actionText,$failureText,$Message
    )

    $event = [ordered]@{
        timestamp       = $iso
        timestampUtc    = $now.ToUniversalTime().ToString('o')
        sequence        = $sequence
        eventId         = $eventId
        incidentId      = $IncidentId
        runId           = $script:DERLogContext.RunId
        level           = $Level
        eventDomain     = $EventDomain
        failureKind     = $effectiveFailureKind
        component       = $Component
        actionId        = $ActionId
        derId           = $DerId
        message         = $Message
        engineVersion   = $script:DERLogContext.EngineVersion
        packageVersion  = $script:DERLogContext.PackageVersion
        buildNumber      = [int]$script:DERLogContext.BuildNumber
        baselineVersion = $script:DERLogContext.BaselineVersion
        elapsedMs       = [long]$script:DERLogContext.Stopwatch.ElapsedMilliseconds
        hostName        = [Environment]::MachineName
        processId       = $PID
        threadId        = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        data            = $Data
    }
    Add-DERJsonLine -Path $script:DERLogContext.TechnicalLog -Object $event

    # DER-Engine.jsonl is intentionally not a duplicate of the action timeline.
    # General events with no ActionId belong to the engine/run timeline. Explicit
    # ENGINE-domain events also belong there. An ENGINE failure that occurs during
    # an action is written to BOTH timelines because the failure origin is DER while
    # the ActionId remains valuable correlation. Ordinary action progress does not
    # pollute the engine timeline merely because a caller left EventDomain=General.
    $writeEngineTimeline = (
        $EventDomain -eq 'Engine' -or
        ($EventDomain -eq 'General' -and [string]::IsNullOrWhiteSpace($ActionId)) -or
        ($isFailure -and $effectiveFailureKind -eq 'Engine')
    )
    if ($writeEngineTimeline) {
        Add-DERJsonLine -Path $script:DERLogContext.EngineLog -Object $event
    }

    # DER-Actions.jsonl is the complete logical-action timeline. Every ActionId
    # event appears here regardless of failure provenance, including ENGINE errors
    # that happened while processing the action.
    if ($EventDomain -eq 'Action' -or -not [string]::IsNullOrWhiteSpace($ActionId)) {
        Add-DERJsonLine -Path $script:DERLogContext.ActionLog -Object $event
    }

    if ($isFailure) {
        Add-DERJsonLine -Path $script:DERLogContext.StructuredErrorLog -Object $event
        Add-DERTextLine -Path $script:DERLogContext.ErrorLog -Line (
            "{0} [{1}] [{2}] [{3}]{4} {5}" -f $timestamp,$Level,$effectiveFailureKind,$Component,$actionText,$Message
        )
        if ($effectiveFailureKind -eq 'Action') {
            Add-DERJsonLine -Path $script:DERLogContext.ActionErrorLog -Object $event
        }
        elseif ($effectiveFailureKind -eq 'Engine') {
            Add-DERJsonLine -Path $script:DERLogContext.EngineErrorLog -Object $event
        }
    }
}

function Write-DERForensicEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)]$Data,
        [string]$Component='Core',
        [string]$ActionId,
        [string]$DerId
    )
    if (-not (Test-DERLoggingInitialized)) { return }
    $script:DERLogEventCounter++
    $now=Get-Date
    $sequence=$script:DERLogEventCounter
    $event=[ordered]@{
        timestamp=$now.ToString('o')
        timestampUtc=$now.ToUniversalTime().ToString('o')
        sequence=$sequence
        eventId=('{0}:{1:D8}' -f $script:DERLogContext.RunId,$sequence)
        incidentId=$null
        runId=$script:DERLogContext.RunId
        eventType=$EventType
        eventDomain=$(if($ActionId){'Action'}else{'General'})
        component=$Component
        actionId=$ActionId
        derId=$DerId
        engineVersion=$script:DERLogContext.EngineVersion
        packageVersion=$script:DERLogContext.PackageVersion
        buildNumber=[int]$script:DERLogContext.BuildNumber
        baselineVersion=$script:DERLogContext.BaselineVersion
        elapsedMs=[long]$script:DERLogContext.Stopwatch.ElapsedMilliseconds
        hostName=[Environment]::MachineName
        processId=$PID
        threadId=[System.Threading.Thread]::CurrentThread.ManagedThreadId
        data=$Data
    }
    Add-DERJsonLine -Path $script:DERLogContext.TechnicalLog -Object $event
    if([string]::IsNullOrWhiteSpace($ActionId)){Add-DERJsonLine -Path $script:DERLogContext.EngineLog -Object $event}
    if (-not [string]::IsNullOrWhiteSpace($ActionId)) {
        Add-DERJsonLine -Path $script:DERLogContext.ActionLog -Object $event
    }
}

function Write-DERGraphLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)
    if (Test-DERLoggingInitialized) { Add-DERJsonLine -Path $script:DERLogContext.GraphLog -Object $Data }
}

function New-DERFocusedForensicRecord {
    <#
    .SYNOPSIS
        Builds one self-contained focused forensic record.

    .DESCRIPTION
        Validation and rollback logs must remain understandable even when copied
        away from the rest of a run directory. The focused record therefore carries
        exact v1/internal-build identity, Run/Action/DER correlation, status/message,
        host/process context, and the redacted detail payload. Focused records are
        also mirrored into the master technical/action timeline with one shared event
        sequence so the same event can be reconstructed chronologically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Validation','Rollback')][string]$EventType,
        [Parameter(Mandatory)][string]$Component,
        [string]$ActionId,
        [string]$DerId,
        [string]$Status,
        [string]$Message,
        $Data
    )
    if (-not (Test-DERLoggingInitialized)) { return $null }

    $script:DERLogEventCounter++
    $now=Get-Date
    $sequence=$script:DERLogEventCounter
    $record=[ordered]@{
        timestamp=$now.ToString('o')
        timestampUtc=$now.ToUniversalTime().ToString('o')
        sequence=$sequence
        eventId=('{0}:{1:D8}' -f $script:DERLogContext.RunId,$sequence)
        runId=$script:DERLogContext.RunId
        eventType=$EventType
        component=$Component
        actionId=$ActionId
        derId=$DerId
        status=$Status
        message=$Message
        engineVersion=$script:DERLogContext.EngineVersion
        packageVersion=$script:DERLogContext.PackageVersion
        buildNumber=[int]$script:DERLogContext.BuildNumber
        baselineVersion=$script:DERLogContext.BaselineVersion
        elapsedMs=[long]$script:DERLogContext.Stopwatch.ElapsedMilliseconds
        hostName=[Environment]::MachineName
        processId=$PID
        threadId=[System.Threading.Thread]::CurrentThread.ManagedThreadId
        data=$Data
    }
    return $record
}

function Add-DERFocusedForensicRecord {
    <#
    .SYNOPSIS
        Persists one validation/rollback record to both its focused stream and the master timeline.

    .DESCRIPTION
        This helper is intentionally private to DER.Logging. Keeping focused-log
        routing here prevents Validation/Rollback modules from having to understand
        log-file paths or duplicate event-envelope rules. The identical record is
        written to the focused stream, DER-Technical.jsonl, and the Action timeline
        when an Action ID exists. Without an Action ID it is also visible on the
        Engine/general timeline for run-level reconstruction.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Record
    )
    Add-DERJsonLine -Path $Path -Object $Record
    Add-DERJsonLine -Path $script:DERLogContext.TechnicalLog -Object $Record
    if (-not [string]::IsNullOrWhiteSpace([string]$Record.actionId)) {
        Add-DERJsonLine -Path $script:DERLogContext.ActionLog -Object $Record
    } else {
        Add-DERJsonLine -Path $script:DERLogContext.EngineLog -Object $Record
    }
}

function Write-DERValidationLog {
    <#
    .SYNOPSIS
        Writes one read-back/validation forensic event with full DER correlation.

    .DESCRIPTION
        Callers provide the logical module, Action ID, DER ID, result status, friendly
        explanation, and detailed evidence. This parameter contract intentionally
        matches DER.Validation call sites. A validation failure is evidence about
        tenant/action outcome; exception provenance itself is still recorded through
        Write-DERError when an exception exists.
    #>
    [CmdletBinding()]
    param(
        [string]$ActionId,
        [Parameter(Mandatory)][string]$Module,
        [string]$DerId,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Message,
        $Data
    )
    if (-not (Test-DERLoggingInitialized)) { return }
    $record=New-DERFocusedForensicRecord -EventType Validation -Component $Module -ActionId $ActionId -DerId $DerId -Status $Status -Message $Message -Data $Data
    Add-DERFocusedForensicRecord -Path $script:DERLogContext.ValidationLog -Record $record
}

function Write-DERRollbackLog {
    <#
    .SYNOPSIS
        Writes one rollback forensic event with full DER correlation.

    .DESCRIPTION
        Rollback is a safety boundary, so every per-object decision must be readable
        without reconstructing state from friendly console text. This parameter
        contract intentionally matches DER.Rollback call sites and preserves module,
        Action ID, DER ID, status, message, exact v1/internal build, and result data.
    #>
    [CmdletBinding()]
    param(
        [string]$ActionId,
        [Parameter(Mandatory)][string]$Module,
        [string]$DerId,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Message,
        $Data
    )
    if (-not (Test-DERLoggingInitialized)) { return }
    $record=New-DERFocusedForensicRecord -EventType Rollback -Component $Module -ActionId $ActionId -DerId $DerId -Status $Status -Message $Message -Data $Data
    Add-DERFocusedForensicRecord -Path $script:DERLogContext.RollbackLog -Record $record
}

function Get-DERErrorDiagnosticData {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $exceptionChain = New-Object System.Collections.Generic.List[object]
    $cursor = $ErrorRecord.Exception
    $depth = 0
    while ($null -ne $cursor -and $depth -lt 6) {
        $exceptionChain.Add([ordered]@{
            type=$cursor.GetType().FullName
            message=$cursor.Message
            hResult=('0x{0}' -f $cursor.HResult.ToString('X8'))
            source=$cursor.Source
        })
        $cursor=$cursor.InnerException
        $depth++
    }

    $exceptionData=[ordered]@{}
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Data) {
        foreach ($key in $ErrorRecord.Exception.Data.Keys) {
            $exceptionData[[string]$key]=$ErrorRecord.Exception.Data[$key]
        }
    }

    return [ordered]@{
        exceptionType=$ErrorRecord.Exception.GetType().FullName
        exceptionMessage=$ErrorRecord.Exception.Message
        exceptionHResult=('0x{0}' -f $ErrorRecord.Exception.HResult.ToString('X8'))
        exceptionChain=@($exceptionChain)
        exceptionData=$exceptionData
        category=[string]$ErrorRecord.CategoryInfo.Category
        categoryReason=[string]$ErrorRecord.CategoryInfo.Reason
        categoryActivity=[string]$ErrorRecord.CategoryInfo.Activity
        targetName=[string]$ErrorRecord.CategoryInfo.TargetName
        targetType=[string]$ErrorRecord.CategoryInfo.TargetType
        fullyQualifiedId=$ErrorRecord.FullyQualifiedErrorId
        scriptStackTrace=$ErrorRecord.ScriptStackTrace
        invocation=if ($ErrorRecord.InvocationInfo) {
            [ordered]@{
                scriptName=$ErrorRecord.InvocationInfo.ScriptName
                line=$ErrorRecord.InvocationInfo.ScriptLineNumber
                offset=$ErrorRecord.InvocationInfo.OffsetInLine
                positionMessage=$ErrorRecord.InvocationInfo.PositionMessage
                statement=$ErrorRecord.InvocationInfo.Line
            }
        } else {$null}
    }
}

function Get-DERFailureKindFromErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateSet('Auto','Action','Engine')][string]$FailureKind='Auto',
        [string]$ActionId
    )
    if ($FailureKind -ne 'Auto') { return $FailureKind }
    try {
        if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Data -and $ErrorRecord.Exception.Data.Contains('DERFailureKind')) {
            $tag=[string]$ErrorRecord.Exception.Data['DERFailureKind']
            if ($tag -in @('Action','Engine')) { return $tag }
        }
    } catch {
        # Failure classification itself must not hide the original exception.
    }
    # An untagged terminating exception is treated as an ENGINE failure even
    # when it occurred during an action. Expected tenant/Graph failures are
    # tagged at their source or logged with Write-DERActionFailure. This keeps
    # command/runtime defects separate from a valid action that Microsoft or
    # validation could not complete.
    return 'Engine'
}

function Write-DERError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Component='Core',[string]$ActionId,[string]$DerId,[string]$Message,
        [ValidateSet('Auto','Action','Engine')][string]$FailureKind='Auto'
    )
    # Recover correlation stamped at the source (Graph/validation/etc.) when
    # an intermediate workload catches and rethrows/converts the error.
    $exceptionData=if($ErrorRecord.Exception){$ErrorRecord.Exception.Data}else{$null}
    if($exceptionData){
        if([string]::IsNullOrWhiteSpace($ActionId) -and $exceptionData.Contains('DERActionId')){$ActionId=[string]$exceptionData['DERActionId']}
        if([string]::IsNullOrWhiteSpace($DerId) -and $exceptionData.Contains('DERDerId')){$DerId=[string]$exceptionData['DERDerId']}
        if(($Component -eq 'Core' -or [string]::IsNullOrWhiteSpace($Component)) -and $exceptionData.Contains('DERComponent')){$Component=[string]$exceptionData['DERComponent']}
    }
    $incidentId=$null
    if($exceptionData -and $exceptionData.Contains('DERIncidentId')){$incidentId=[string]$exceptionData['DERIncidentId']}
    if([string]::IsNullOrWhiteSpace($incidentId)){
        $incidentId=New-DERIncidentId
        if($ErrorRecord.Exception -and $ErrorRecord.Exception.Data){$ErrorRecord.Exception.Data['DERIncidentId']=$incidentId}
    }
    $effective = if ($Message) { $Message } else { $ErrorRecord.Exception.Message }
    $kind=Get-DERFailureKindFromErrorRecord -ErrorRecord $ErrorRecord -FailureKind $FailureKind -ActionId $ActionId
    $data=Get-DERErrorDiagnosticData -ErrorRecord $ErrorRecord
    Write-DERLog -Level ERROR -Component $Component -ActionId $ActionId -DerId $DerId -EventDomain $(if($kind -eq 'Action'){'Action'}else{'Engine'}) -FailureKind $kind -IncidentId $incidentId -Message $effective -Data $data
}

function Write-DEREngineFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Component='Core',[string]$ActionId,[string]$DerId,$Data,[string]$IncidentId,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateSet('ERROR','CRITICAL')][string]$Level='ERROR'
    )
    if([string]::IsNullOrWhiteSpace($IncidentId)){$IncidentId=New-DERIncidentId}
    $details=if($ErrorRecord){Get-DERErrorDiagnosticData -ErrorRecord $ErrorRecord}else{$Data}
    Write-DERLog -Level $Level -Component $Component -ActionId $ActionId -DerId $DerId -EventDomain Engine -FailureKind Engine -IncidentId $IncidentId -Message $Message -Data $details
}

function Write-DERActionFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Component='Action',[string]$ActionId,[string]$DerId,$Data,[string]$IncidentId,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [ValidateSet('ERROR','CRITICAL')][string]$Level='ERROR'
    )
    if([string]::IsNullOrWhiteSpace($IncidentId)){$IncidentId=New-DERIncidentId}
    $details=if($ErrorRecord){Get-DERErrorDiagnosticData -ErrorRecord $ErrorRecord}else{$Data}
    Write-DERLog -Level $Level -Component $Component -ActionId $ActionId -DerId $DerId -EventDomain Action -FailureKind Action -IncidentId $IncidentId -Message $Message -Data $details
}

function New-DERActionId {
    [CmdletBinding()]
    param([ValidatePattern('^[A-Za-z0-9]{2,12}$')][string]$Component='CORE')
    $script:DERActionCounter++
    return ('DER-{0}-{1:D5}' -f $Component.ToUpperInvariant(),$script:DERActionCounter)
}

function Start-DERAction {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Component,[Parameter(Mandatory)][string]$Description,[string]$ActionId,$Data)
    if (-not $ActionId) {
        $short = ($Component -replace '[^A-Za-z0-9]','')
        if ($short.Length -gt 8) {$short=$short.Substring(0,8)}
        if ($short.Length -lt 2) {$short='CORE'}
        $ActionId = New-DERActionId -Component $short
    }
    $action = [pscustomobject]@{ActionId=$ActionId;Component=$Component;Description=$Description;StartedAt=Get-Date;Stopwatch=[System.Diagnostics.Stopwatch]::StartNew()}
    Write-DERLog -Level STEP -Component $Component -ActionId $ActionId -EventDomain Action -Message $Description -Data $Data
    return $action
}

function Complete-DERAction {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Action,[ValidateSet('OK','WARN','ERROR')][string]$Status='OK',[string]$Message,$Data,[ValidateSet('Action','Engine')][string]$FailureKind='Action')
    if ($Action.Stopwatch) {$Action.Stopwatch.Stop()}
    $duration = if ($Action.Stopwatch) {$Action.Stopwatch.ElapsedMilliseconds} else {$null}
    $finalMessage = if ($Message) {$Message} else {$Action.Description}
    Write-DERLog -Level $Status -Component $Action.Component -ActionId $Action.ActionId -EventDomain Action -FailureKind $(if($Status -eq 'ERROR'){$FailureKind}else{'None'}) -Message $finalMessage -Data ([ordered]@{durationMs=$duration;result=$Data})
}

function Initialize-DERLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$EngineVersion,
        [Parameter(Mandatory)][string]$PackageVersion,
        [Parameter(Mandatory)][int]$BuildNumber,
        [Parameter(Mandatory)][string]$BaselineVersion
    )

    $logsRoot = Join-Path $RuntimeRoot 'Logs'
    $runDir = Join-Path $logsRoot $RunId
    foreach ($path in @($logsRoot,$runDir)) {
        if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    }

    $script:DERLogEventCounter = 0
    $script:DERAllIncidentIds.Clear()
    $script:DEREngineIncidentIds.Clear()
    $script:DERActionIncidentIds.Clear()
    $script:DERLogContext = [pscustomobject][ordered]@{
        Initialized=$true;RunId=$RunId;RuntimeRoot=$RuntimeRoot;RunLogDirectory=$runDir
        HumanLog=Join-Path $runDir 'DER-Human.log'
        TechnicalLog=Join-Path $runDir 'DER-Technical.jsonl'
        EngineLog=Join-Path $runDir 'DER-Engine.jsonl'
        ErrorLog=Join-Path $runDir 'DER-Errors.log'
        StructuredErrorLog=Join-Path $runDir 'DER-Errors.jsonl'
        ActionLog=Join-Path $runDir 'DER-Actions.jsonl'
        EngineErrorLog=Join-Path $runDir 'DER-EngineErrors.jsonl'
        ActionErrorLog=Join-Path $runDir 'DER-ActionErrors.jsonl'
        GraphLog=Join-Path $runDir 'DER-Graph.jsonl'
        ValidationLog=Join-Path $runDir 'DER-Validation.jsonl'
        RollbackLog=Join-Path $runDir 'DER-Rollback.jsonl'
        TranscriptLog=Join-Path $runDir 'PowerShell-Transcript.txt'
        LogIndex=Join-Path $runDir 'DER-LogIndex.json'
        TranscriptOn=$false;EngineVersion=$EngineVersion;PackageVersion=$PackageVersion;BuildNumber=$BuildNumber;BaselineVersion=$BaselineVersion;InitializedAt=Get-Date;Stopwatch=[System.Diagnostics.Stopwatch]::StartNew();WarningCount=[long]0;TotalErrorCount=[long]0;EngineErrorCount=[long]0;ActionErrorCount=[long]0
    }

    foreach ($file in @($script:DERLogContext.HumanLog,$script:DERLogContext.TechnicalLog,$script:DERLogContext.EngineLog,$script:DERLogContext.ErrorLog,$script:DERLogContext.StructuredErrorLog,$script:DERLogContext.ActionLog,$script:DERLogContext.EngineErrorLog,$script:DERLogContext.ActionErrorLog,$script:DERLogContext.GraphLog,$script:DERLogContext.ValidationLog,$script:DERLogContext.RollbackLog)) {
        if (-not (Test-Path -LiteralPath $file)) {[System.IO.File]::WriteAllText($file,'',[System.Text.UTF8Encoding]::new($false))}
    }

    $transcriptStartError=$null
    try {
        Start-Transcript -LiteralPath $script:DERLogContext.TranscriptLog -Append -Force -ErrorAction Stop | Out-Null
        $script:DERLogContext.TranscriptOn=$true
    } catch {
        $script:DERLogContext.TranscriptOn=$false
        $transcriptStartError=$_
    }

    Write-DERLog -Level OK -Component 'Logging' -Message 'DER logging engine initialized.' -Data ([ordered]@{
        runId=$RunId;logDirectory=$runDir;engineVersion=$EngineVersion;packageVersion=$PackageVersion;buildNumber=$BuildNumber;baselineVersion=$BaselineVersion;
        transcript=$script:DERLogContext.TranscriptOn;hostVersion=[string]$PSVersionTable.PSVersion;psEdition=$PSVersionTable.PSEdition;
        machine=$env:COMPUTERNAME;user=[Environment]::UserName;actionLog=$script:DERLogContext.ActionLog;engineLog=$script:DERLogContext.EngineLog;engineErrorLog=$script:DERLogContext.EngineErrorLog;actionErrorLog=$script:DERLogContext.ActionErrorLog
    })
    if($transcriptStartError){
        Write-DERLog -Level WARN -Component 'Logging' -EventDomain Engine -Message 'PowerShell transcript could not be started. Structured DER logging remains active.' -Data (Get-DERErrorDiagnosticData -ErrorRecord $transcriptStartError)
    }
    Write-DERLogIndex
    return Get-DERLoggingContext
}

function Write-DERLogIndex {
    <#
    .SYNOPSIS
        Persists the one-file index for all diagnostic streams in the current run.

    .DESCRIPTION
        DER creates many focused logs so an engineer can answer different questions
        without filtering one enormous transcript. This index is the starting point:
        it identifies the exact v1 internal build, run, classification contract,
        stream purpose, file path, and current incident/error counters. It is rewritten
        at initialization and shutdown so a partially completed run still has a usable
        map of its forensic artifacts.

        This file is diagnostic metadata only. It is never an ownership authority and
        is never used to decide whether a Microsoft tenant write is safe.
    #>
    [CmdletBinding()]
    param([switch]$Completed)
    if (-not (Test-DERLoggingInitialized)) { return }
    $context=$script:DERLogContext
    $document=[ordered]@{
        schemaVersion='1.0'
        product='DER Intune / Entra Environment Builder'
        productVersion='v1'
        packageVersion=$context.PackageVersion
        buildNumber=[int]$context.BuildNumber
        engineVersion=$context.EngineVersion
        baselineVersion=$context.BaselineVersion
        runId=$context.RunId
        initializedAt=$context.InitializedAt.ToString('o')
        completedAt=$(if($Completed){(Get-Date).ToString('o')}else{$null})
        classification=[ordered]@{
            engine='DER/PowerShell/runtime/infrastructure failed to execute correctly.'
            action='DER executed the intended path, but Microsoft/tenant state/validation/rollback/safety outcome prevented completion.'
            rule='ActionId is correlation only. Untagged terminating exceptions default to ENGINE.'
        }
        counts=[ordered]@{
            warnings=[long]$context.WarningCount
            errors=[long]$context.TotalErrorCount
            engineErrors=[long]$context.EngineErrorCount
            actionErrors=[long]$context.ActionErrorCount
            uniqueIncidents=[long]$script:DERAllIncidentIds.Count
            engineIncidents=[long]$script:DEREngineIncidentIds.Count
            actionIncidents=[long]$script:DERActionIncidentIds.Count
        }
        streams=[ordered]@{
            human=[ordered]@{path=$context.HumanLog;purpose='Readable chronological operator/engine summary.'}
            technical=[ordered]@{path=$context.TechnicalLog;purpose='Authoritative redacted structured event timeline.'}
            engine=[ordered]@{path=$context.EngineLog;purpose='DER/runtime/general events plus ENGINE failures, including failures correlated to an action.'}
            actions=[ordered]@{path=$context.ActionLog;purpose='Action-correlated timeline regardless of failure origin.'}
            combinedErrors=[ordered]@{path=$context.StructuredErrorLog;purpose='All structured ERROR/CRITICAL events in one place.'}
            engineErrors=[ordered]@{path=$context.EngineErrorLog;purpose='Only confirmed/default ENGINE failures.'}
            actionErrors=[ordered]@{path=$context.ActionErrorLog;purpose='Only positively classified ACTION failures.'}
            graph=[ordered]@{path=$context.GraphLog;purpose='Graph request/transport forensic events.'}
            validation=[ordered]@{path=$context.ValidationLog;purpose='Microsoft read-back and validation evidence.'}
            rollback=[ordered]@{path=$context.RollbackLog;purpose='Rollback decisions, writes, and validation evidence.'}
            transcript=[ordered]@{path=$context.TranscriptLog;purpose='Supplemental PowerShell transcript; structured logs remain authoritative.'}
        }
    }
    $json=$document|ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($context.LogIndex,$json,[System.Text.UTF8Encoding]::new($false))
}

function Stop-DERLogging {
    [CmdletBinding()]
    param()
    if (-not (Test-DERLoggingInitialized)) {return}
    Write-DERLog -Level INFO -Component 'Logging' -Message 'DER logging engine shutting down.'
    if ($script:DERLogContext.TranscriptOn) {
        try {Stop-Transcript | Out-Null}
        catch {Write-DERLog -Level WARN -Component 'Logging' -EventDomain Engine -Message 'PowerShell transcript shutdown reported an error.' -Data (Get-DERErrorDiagnosticData -ErrorRecord $_)}
    }
    $script:DERLogContext.TranscriptOn=$false
    if($script:DERLogContext.Stopwatch){$script:DERLogContext.Stopwatch.Stop()}
    Write-DERLogIndex -Completed
}

Export-ModuleMember -Function @(
    'Initialize-DERLogging','Stop-DERLogging','Test-DERLoggingInitialized','Get-DERLoggingContext','Get-DERLoggingSummary','Write-DERLogIndex','Protect-DERLogData',
    'Write-DERLog','Write-DERForensicEvent','Write-DERGraphLog','Write-DERValidationLog','Write-DERRollbackLog','Write-DERError','Write-DEREngineFailure','Write-DERActionFailure','Get-DERFailureKindFromErrorRecord',
    'New-DERIncidentId','New-DERFailureException','New-DERActionId','Start-DERAction','Complete-DERAction'
)
