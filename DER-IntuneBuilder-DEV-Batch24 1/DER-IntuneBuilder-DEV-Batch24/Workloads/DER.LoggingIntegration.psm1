<#
.SYNOPSIS
    DER Intune diagnostic logging integration compatibility workload.

.DESCRIPTION
    DER's current authentication/transport engine is Microsoft Graph-centric.
    Intune Diagnostics Settings route logs through Azure Monitor resources and
    require Azure subscription/resource context that the current questionnaire
    does not collect or validate end-to-end. Per DER safety rules this module
    does not fake a partial implementation. It records an exact manual action
    and returns Skipped until an Azure Resource Manager integration engine is
    supplied by an approved environment-specific integration layer.
#>


# Maintenance notes
# Responsibility: Represents optional environment-specific logging integration without assuming a universal third-party destination.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERLoggingIntegrationCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Save-DERLoggingIntegrationResult {
    param($Result)
    $ctx = if (Test-DERLoggingIntegrationCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath (Join-Path $dir 'LoggingIntegration.json') -Encoding UTF8
    }
}

function Invoke-DERLoggingIntegrationModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $planned = @($BuildPlan.Objects | Where-Object { $_.Enabled -and $_.Module -eq 'LoggingIntegration' })
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($p in $planned) {
        $results.Add([pscustomobject]@{
            DerId = $p.DerId
            DisplayName = $p.DisplayName
            Status = 'Skipped'
            Message = 'Manual action required: Intune Diagnostics Settings use Azure Monitor destinations. DER currently does not collect/validate the required Azure subscription, Log Analytics workspace, Storage, or Event Hub resource context end-to-end.'
            RequestedDestination = [string]$BuildPlan.Answers.Operations.SIEM
            ManualPath = 'Microsoft Intune admin center > Reports > Diagnostics settings'
            RecommendedLogs = @('AuditLogs','OperationalLogs','DeviceComplianceOrg','IntuneDevices')
        })
    }

    $summary = [pscustomobject]@{Created=0;Existing=0;Skipped=@($results).Count;Failed=0}
    $out = [pscustomobject]@{
        Module='LoggingIntegration';RunId=$RunId;Status='Skipped';CriticalFailure=$false
        Summary=$summary;Results=@($results)
    }
    Save-DERLoggingIntegrationResult -Result $out
    return $out
}

Export-ModuleMember -Function @('Invoke-DERLoggingIntegrationModule')
