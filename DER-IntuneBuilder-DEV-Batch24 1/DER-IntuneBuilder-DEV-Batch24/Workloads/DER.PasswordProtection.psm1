<#
.SYNOPSIS
    DER Microsoft Entra custom Password Protection compatibility workload.

.DESCRIPTION
    DER does not currently perform a tenant write for custom banned-password
    terms because the project has not validated a supported Microsoft Graph
    write API for that ordinary tenant configuration. When the engineer selects
    this feature, the module records a clean Manual/Skipped outcome so reporting
    distinguishes the required manual task from an automation failure.

.NOTES
    Required parent entry point: Invoke-DERPasswordProtectionModule
#>

# Maintenance notes
# Responsibility: Represents the approved password-protection workload contract and emits manual/managed results without bypassing central safety.
# Graph access: Use the central DER Graph wrapper for every Microsoft Graph request.
# Ownership: Microsoft Object ID is authoritative. Names and collisions never establish DER ownership.
# Existing state: Re-read tracked Microsoft objects before using them or declaring them valid.
# Failure handling: Expected tenant/precondition/read-back refusals are ACTION failures; unexpected PowerShell/runtime defects are ENGINE failures.
# Logging: Keep Action ID, DER ID, Microsoft Object ID, and Incident ID attached whenever they are available.
# Design: Retry, state, rollback, and recovery policy belong in the shared core modules, not in workload-local substitutes.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-DERPasswordCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Save-DERPasswordProtectionResult {
    param($Result)
    $ctx = if (Test-DERPasswordCommand 'Get-DERStateContext') { Get-DERStateContext } else { $null }
    if ($ctx) {
        $dir = Join-Path $ctx.RunRoot 'Workloads'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $Result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $dir 'PasswordProtection.json') -Encoding UTF8
    }
}

function Invoke-DERPasswordProtectionModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    if (-not [bool]$BuildPlan.Answers.Identity.EnableCustomPasswordProtection) {
        $out = [pscustomobject][ordered]@{
            Module = 'PasswordProtection'
            RunId = $RunId
            Status = 'Skipped'
            CriticalFailure = $false
            Summary = [pscustomobject]@{ Updated=0; Skipped=0; Failed=0 }
            Results = @()
        }
        Save-DERPasswordProtectionResult -Result $out
        return $out
    }

    $terms = @(
        [string]$BuildPlan.Organization.Name,
        [string]$BuildPlan.Organization.Acronym
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

    $result = [pscustomobject]@{
        DerId = 'MAN-PASS-001'
        DisplayName = 'Microsoft Entra Custom Password Protection'
        Status = 'Skipped'
        Message = ("Manual by design. Suggested organization-specific banned terms: {0}. A supported Microsoft Graph write path for this tenant setting has not been validated, so no tenant change was attempted." -f ($terms -join ', '))
        ActionId = 'PASS-MANUAL'
    }

    if (Test-DERPasswordCommand 'Register-DERTransaction') {
        Register-DERTransaction -ActionId 'PASS-MANUAL' -Phase 'SKIP' -Module 'PasswordProtection' -DerId 'MAN-PASS-001' -Message $result.Message | Out-Null
    }

    $out = [pscustomobject][ordered]@{
        Module = 'PasswordProtection'
        RunId = $RunId
        Status = 'Skipped'
        CriticalFailure = $false
        Summary = [pscustomobject]@{ Updated=0; Skipped=1; Failed=0 }
        Results = @($result)
    }
    Save-DERPasswordProtectionResult -Result $out
    return $out
}

Export-ModuleMember -Function @('Invoke-DERPasswordProtectionModule')
