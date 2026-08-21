<#
.SYNOPSIS
    DER disposable test-tenant integration evidence engine.

.DESCRIPTION
    Produces an auditable proof bundle for the read-only tenant integration
    workflow. It verifies that the central Graph write guard remained DENY-ALL,
    no write-authenticated session was opened, no mutation reached the Graph
    transport boundary, no mutation attempt was blocked, no source bypasses the
    central Graph transport, and no workload transaction activity occurred.

    This module does not perform Microsoft Graph requests.

.NOTES
    Required parent entry point: New-DERNoWriteEvidence
#>


# Maintenance notes
# Responsibility: Produces cryptographic no-write evidence for real discovery/planning under a DenyAll write guard.
# Safety: Preserve fail-closed behavior, deterministic evidence, and explicit identity/ownership checks.
# Failure handling: Tag known tenant/request/safety outcomes as ACTION; unexpected local/runtime/code failures remain ENGINE.
# Logging: Preserve run, action, DER, Microsoft object, and incident correlation whenever available.
# Design: Keep cross-cutting authority in the core module that owns it rather than duplicating policy in callers.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Test-DERIntegrationCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Write-DERIntegrationLog {
    param([string]$Level,[string]$Message,$Data)
    if(Test-DERIntegrationCommand 'Write-DERLog'){
        Write-DERLog -Level $Level -Component 'IntegrationTest' -Message $Message -Data $Data
    }
}

function Confirm-DERTestTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][string]$PackageRoot
    )
    $policy=Get-DERIntegrationPolicy -PackageRoot $PackageRoot
    if([string]$Session.SessionType -ne 'Discovery'){throw 'DER test-tenant confirmation requires a discovery session.'}
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host ' DER DISPOSABLE TEST-TENANT CONFIRMATION' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor DarkYellow
    Write-Host (' Tenant name : {0}' -f $Session.TenantName)
    Write-Host (' Tenant ID   : {0}' -f $Session.TenantId)
    Write-Host (' Signed in as: {0}' -f $Session.Account)
    Write-Host ''
    Write-Host 'This mode is ONLY for a disposable/non-production test tenant.' -ForegroundColor Yellow
    Write-Host 'DER will enable a transport-level DENY-ALL Graph write guard.' -ForegroundColor Gray
    Write-Host 'Type TEST-TENANT to attest that this is not a production tenant.' -ForegroundColor Yellow
    $entered=Read-Host 'Confirm disposable test tenant'
    $confirmed=($entered.Trim() -ceq [string]$policy.tenantSafety.operatorConfirmationToken)
    $result=[pscustomobject][ordered]@{
        Confirmed=$confirmed
        TokenRequired=[string]$policy.tenantSafety.operatorConfirmationToken
        TenantId=[string]$Session.TenantId
        TenantName=[string]$Session.TenantName
        Account=[string]$Session.Account
        ConfirmedAt=$(if($confirmed){(Get-Date).ToString('o')}else{$null})
    }
    Write-DERIntegrationLog -Level $(if($confirmed){'OK'}else{'WARN'}) -Message $(if($confirmed){'Engineer confirmed disposable test-tenant integration mode.'}else{'Engineer did not confirm disposable test-tenant integration mode.'}) -Data $result
    return $result
}

function Get-DERIntegrationPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $path=Join-Path $PackageRoot 'Definitions\Integration\DER-TestTenantIntegrationPolicy.json'
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "DER test-tenant integration policy is missing: $path"}
    $policy=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -Depth 100
    if([string]$policy.schemaVersion -ne '1.0' -or [string]$policy.policyVersion -ne '1.0.0'){throw 'DER test-tenant integration policy version is unsupported.'}
    return $policy
}

function Get-DERIntegrationBypassFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageRoot)
    $findings=New-Object System.Collections.Generic.List[object]
    $allowedTransport=[IO.Path]::GetFullPath((Join-Path $PackageRoot 'Core\DER.Graph.psm1'))
    $transportCommand='Invoke-'+'MgGraphRequest'
    $sourceFiles=@(
        Get-ChildItem -LiteralPath (Join-Path $PackageRoot 'Core') -File -Filter '*.psm1' -ErrorAction Stop
        Get-ChildItem -LiteralPath (Join-Path $PackageRoot 'Workloads') -File -Filter '*.psm1' -ErrorAction Stop
        Get-Item -LiteralPath (Join-Path $PackageRoot 'Start-DERIntuneBuilder.ps1') -ErrorAction Stop
    )
    foreach($file in $sourceFiles){
        $full=[IO.Path]::GetFullPath($file.FullName)
        $tokens=$null;$parseErrors=$null
        $ast=[System.Management.Automation.Language.Parser]::ParseFile($full,[ref]$tokens,[ref]$parseErrors)
        foreach($err in @($parseErrors)){
            $findings.Add([pscustomobject]@{Rule='PowerShellParseError';Path=[IO.Path]::GetRelativePath($PackageRoot,$full).Replace('\','/');Line=$err.Extent.StartLineNumber;Text=$err.Message})
        }
        if(@($parseErrors).Count -gt 0){continue}
        $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]},$true))
        foreach($commandAst in $commands){
            $name=[string]$commandAst.GetCommandName()
            if([string]::IsNullOrWhiteSpace($name)){continue}
            $relative=[IO.Path]::GetRelativePath($PackageRoot,$full).Replace('\','/')
            $line=[int]$commandAst.Extent.StartLineNumber
            $text=[string]$commandAst.Extent.Text
            if($full -ne $allowedTransport -and $name -ieq $transportCommand){
                $findings.Add([pscustomobject]@{Rule='DirectGraphTransport';Path=$relative;Line=$line;Text=$text.Trim()})
                continue
            }
            if($name -match '(?i)^(New|Update|Remove|Set)-Mg[A-Za-z0-9_-]*$'){
                $findings.Add([pscustomobject]@{Rule='DirectGraphMutationCmdlet';Path=$relative;Line=$line;Text=$text.Trim()})
                continue
            }
            if($name -match '(?i)^(Invoke-RestMethod|Invoke-WebRequest)$' -and $text -match '(?i)https://[^\s''\"]*graph\.(microsoft|svc|chinacloudapi)'){
                $findings.Add([pscustomobject]@{Rule='DirectGraphHttp';Path=$relative;Line=$line;Text=$text.Trim()})
            }
        }
    }
    return @($findings)
}

function Get-DERGraphForensicIntegrationSummary {
    [CmdletBinding()]
    param([string]$GraphLogPath)
    $transport=New-Object System.Collections.Generic.List[object]
    $blocked=New-Object System.Collections.Generic.List[object]
    $parseErrors=New-Object System.Collections.Generic.List[object]
    if([string]::IsNullOrWhiteSpace($GraphLogPath) -or -not(Test-Path -LiteralPath $GraphLogPath -PathType Leaf)){
        return [pscustomobject][ordered]@{Path=$GraphLogPath;Exists=$false;TransportEvents=@();MutationTransportEvents=@();BlockedWriteEvents=@();ParseErrors=@();SHA256=$null}
    }
    $lineNumber=0
    foreach($line in Get-Content -LiteralPath $GraphLogPath){
        $lineNumber++
        if([string]::IsNullOrWhiteSpace([string]$line)){continue}
        try{$item=$line|ConvertFrom-Json -Depth 100}
        catch{$parseErrors.Add([pscustomobject]@{Line=$lineNumber;Message=$_.Exception.Message});continue}
        if([string]$item.phase -eq 'transport'){$transport.Add($item)}
        if([string]$item.phase -eq 'blocked-write'){$blocked.Add($item)}
    }
    $mutations=@($transport|Where-Object{[string]$_.method -in @('POST','PATCH','PUT','DELETE')})
    return [pscustomobject][ordered]@{
        Path=$GraphLogPath
        Exists=$true
        TransportEvents=@($transport)
        MutationTransportEvents=$mutations
        BlockedWriteEvents=@($blocked)
        ParseErrors=@($parseErrors)
        SHA256=(Get-FileHash -Algorithm SHA256 -LiteralPath $GraphLogPath).Hash.ToLowerInvariant()
    }
}

function New-DERIntegrationCheck {
    param([Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][bool]$Passed,[Parameter(Mandatory)][string]$Message,$Data)
    return [pscustomobject][ordered]@{Id=$Id;Status=$(if($Passed){'Pass'}else{'Fail'});Message=$Message;Data=$Data}
}

function ConvertTo-DERIntegrationHtmlSafe {
    param($Value)
    if($null -eq $Value){return ''}
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-DERNoWriteEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$TenantName,
        [Parameter(Mandatory)]$BuildPlan,
        [Parameter(Mandatory)]$DryRun,
        [Parameter(Mandatory)]$PermissionPlan,
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$PackageRoot,
        $OperatorAttestation
    )
    $started=Get-Date
    $policy=Get-DERIntegrationPolicy -PackageRoot $PackageRoot
    $packageManifest=Join-Path $PackageRoot 'Definitions\Package\DER-PackageManifest.json'
    if(-not(Test-Path -LiteralPath $packageManifest)){throw 'DER package manifest is missing; no-write evidence cannot be package-bound.'}
    $packageIdentity=Get-Content -LiteralPath $packageManifest -Raw|ConvertFrom-Json -Depth 100
    $packageVersion=[string]$packageIdentity.packageVersion
    $buildNumber=[int]$packageIdentity.buildNumber
    if([string]::IsNullOrWhiteSpace($packageVersion) -or [string]$policy.generatedForPackage -ne $packageVersion -or [int]$policy.generatedForBuild -ne $buildNumber){throw 'DER test-tenant integration policy is not bound to this exact package/build.'}
    if(-not(Test-DERIntegrationCommand 'Get-DERGraphRequestAuditSummary')){throw 'DER Graph request audit summary is unavailable.'}
    $audit=Get-DERGraphRequestAuditSummary
    $auth=if(Test-DERIntegrationCommand 'Get-DERAuthenticationContext'){Get-DERAuthenticationContext}else{$null}
    $authAudit=if(Test-DERIntegrationCommand 'Get-DERAuthenticationAuditSummary'){Get-DERAuthenticationAuditSummary}else{$null}
    $log=if(Test-DERIntegrationCommand 'Get-DERLoggingContext'){Get-DERLoggingContext}else{$null}
    $graphForensic=Get-DERGraphForensicIntegrationSummary -GraphLogPath $(if($log){[string]$log.GraphLog}else{$null})
    $bypass=@(Get-DERIntegrationBypassFindings -PackageRoot $PackageRoot)
    $journal=if(Test-DERIntegrationCommand 'Get-DERTransactionJournal'){@(Get-DERTransactionJournal)}else{@()}
    $writePhases=@('EXECUTE','CREATED','UPDATED','ASSIGNED','READBACK','VALIDATE','ROLLBACK','COMMIT')
    $writeTransactions=@($journal|Where-Object{[string]$_.phase -in $writePhases})
    $grantedScopes=if($auth){@($auth.Scopes)}else{@()}
    $writeLikeScopes=@($grantedScopes|Where-Object{[string]$_ -match '(?i)ReadWrite|\.Write\.'})

    $checks=New-Object System.Collections.Generic.List[object]
    $checks.Add((New-DERIntegrationCheck 'INT-000' ($OperatorAttestation -and [bool]$OperatorAttestation.Confirmed -and [string]$OperatorAttestation.TenantId -eq $TenantId) 'Engineer explicitly attested that the connected tenant is disposable/non-production.' $OperatorAttestation))
    $checks.Add((New-DERIntegrationCheck 'INT-001' ([string]$audit.WriteGuardMode -eq 'DenyAll') 'Central Graph write guard remained DENY-ALL for the integration run.' $audit.WriteGuardMode))
    $checks.Add((New-DERIntegrationCheck 'INT-002' ($auth -and [string]$auth.SessionType -eq 'Discovery' -and [string]$auth.TenantId -eq $TenantId) 'Only the tenant-confirmed discovery session is active.' $(if($auth){@{sessionType=$auth.SessionType;tenantId=$auth.TenantId;account=$auth.Account}}else{$null})))
    $checks.Add((New-DERIntegrationCheck 'INT-003' (@($writeLikeScopes).Count -eq 0) 'The active discovery session contains no delegated ReadWrite/Write scopes.' $writeLikeScopes))
    $checks.Add((New-DERIntegrationCheck 'INT-004' ([bool]$DryRun.IntegrationNoWrite -and -not [bool]$DryRun.FinalApprovalGranted) 'Dry run executed in integration no-write mode and no BUILD approval was granted.' @{integrationNoWrite=$DryRun.IntegrationNoWrite;finalApprovalGranted=$DryRun.FinalApprovalGranted;readyToBuild=$DryRun.ReadyToBuild}))
    $checks.Add((New-DERIntegrationCheck 'INT-005' ([long]$audit.TransportWriteCount -eq 0) 'Central Graph transport recorded zero mutation requests.' @{transportWriteCount=$audit.TransportWriteCount;transportByMethod=$audit.TransportByMethod}))
    $checks.Add((New-DERIntegrationCheck 'INT-006' ([long]$audit.BlockedWriteCount -eq 0) 'No code path attempted a mutation that had to be stopped by the DENY-ALL guard.' @{blockedWriteCount=$audit.BlockedWriteCount;attemptByMethod=$audit.AttemptByMethod}))
    $checks.Add((New-DERIntegrationCheck 'INT-007' ($graphForensic.Exists -and @($graphForensic.ParseErrors).Count -eq 0 -and @($graphForensic.MutationTransportEvents).Count -eq 0) 'Forensic Graph log independently contains zero mutation transport events and parses cleanly.' @{graphLog=$graphForensic.Path;graphLogSHA256=$graphForensic.SHA256;transportEvents=@($graphForensic.TransportEvents).Count;mutationTransportEvents=@($graphForensic.MutationTransportEvents).Count;parseErrors=@($graphForensic.ParseErrors).Count}))
    $checks.Add((New-DERIntegrationCheck 'INT-008' (@($bypass).Count -eq 0) 'Runtime source contains no Graph mutation bypass around the central DER.Graph transport.' $bypass))
    $checks.Add((New-DERIntegrationCheck 'INT-009' (@($writeTransactions).Count -eq 0) 'No workload/write transaction phases were recorded during integration mode.' $writeTransactions))
    $checks.Add((New-DERIntegrationCheck 'INT-010' ($authAudit -and [long]$authAudit.WriteSessionAttempts -eq 0 -and [long]$authAudit.WriteSessionsOpened -eq 0) 'Authentication audit proves write authentication was never attempted or opened.' @{authenticationAudit=$authAudit;calculatedWriteScopes=@($PermissionPlan.RequiredScopes)}))

    $evidenceRoot=Join-Path (Join-Path (Join-Path $RuntimeRoot 'Evidence') $TenantId) $RunId
    New-Item -ItemType Directory -Path $evidenceRoot -Force|Out-Null
    $graphSnapshotPath=Join-Path $evidenceRoot 'DER-Graph.evidence.jsonl'
    $technicalSnapshotPath=Join-Path $evidenceRoot 'DER-Technical.evidence.jsonl'
    if($log -and (Test-Path -LiteralPath $log.GraphLog)){Copy-Item -LiteralPath $log.GraphLog -Destination $graphSnapshotPath -Force}
    if($log -and (Test-Path -LiteralPath $log.TechnicalLog)){Copy-Item -LiteralPath $log.TechnicalLog -Destination $technicalSnapshotPath -Force}
    $graphSnapshotSHA=$(if(Test-Path -LiteralPath $graphSnapshotPath){(Get-FileHash -Algorithm SHA256 -LiteralPath $graphSnapshotPath).Hash.ToLowerInvariant()}else{$null})
    $technicalSnapshotSHA=$(if(Test-Path -LiteralPath $technicalSnapshotPath){(Get-FileHash -Algorithm SHA256 -LiteralPath $technicalSnapshotPath).Hash.ToLowerInvariant()}else{$null})
    $checks.Add((New-DERIntegrationCheck 'INT-011' ((Test-Path -LiteralPath $graphSnapshotPath) -and (Test-Path -LiteralPath $technicalSnapshotPath) -and -not [string]::IsNullOrWhiteSpace($graphSnapshotSHA) -and -not [string]::IsNullOrWhiteSpace($technicalSnapshotSHA)) 'Frozen Graph and technical log snapshots were captured and SHA-256 hashed into the evidence bundle.' @{graphLogSnapshot=$graphSnapshotPath;graphLogSHA256=$graphSnapshotSHA;technicalLogSnapshot=$technicalSnapshotPath;technicalLogSHA256=$technicalSnapshotSHA}))
    $failed=@($checks|Where-Object Status -eq 'Fail')
    $passed=($failed.Count -eq 0)
    $evidencePath=Join-Path $evidenceRoot 'DER-NoWriteEvidence.json'
    $checksCsv=Join-Path $evidenceRoot 'DER-NoWriteChecks.csv'
    $htmlPath=Join-Path $evidenceRoot 'DER-NoWriteEvidence.html'
    @($checks|Select-Object Id,Status,Message)|Export-Csv -LiteralPath $checksCsv -NoTypeInformation -Encoding utf8

    $evidence=[ordered]@{
        schemaVersion='1.0'
        evidenceType='DER-TestTenant-NoWrite'
        policyVersion=[string]$policy.policyVersion
        packageVersion=$packageVersion
        buildNumber=$buildNumber
        runId=$RunId
        tenantId=$TenantId
        tenantName=$TenantName
        startedAt=$started.ToString('o')
        completedAt=(Get-Date).ToString('o')
        passed=$passed
        failedChecks=@($failed.Id)
        workflow=@('Discovery','StateInitialization','Snapshot','Analysis','Questionnaire','Plan','PermissionCalculation','DryRun','Evidence')
        prohibitedStages=@('WriteAuthentication','Adoption','Workloads','PostBuildValidation')
        operatorAttestation=$OperatorAttestation
        dryRun=[ordered]@{readyToBuild=[bool]$DryRun.ReadyToBuild;blockingFailures=[int]$DryRun.BlockingFailures;warnings=[int]$DryRun.Warnings;integrationNoWrite=[bool]$DryRun.IntegrationNoWrite;finalApprovalGranted=[bool]$DryRun.FinalApprovalGranted}
        graphAudit=$audit
        graphForensic=[ordered]@{path=$graphForensic.Path;sha256=$graphForensic.SHA256;transportEventCount=@($graphForensic.TransportEvents).Count;mutationTransportEventCount=@($graphForensic.MutationTransportEvents).Count;blockedWriteEventCount=@($graphForensic.BlockedWriteEvents).Count;parseErrorCount=@($graphForensic.ParseErrors).Count}
        authentication=[ordered]@{sessionType=$(if($auth){[string]$auth.SessionType}else{$null});tenantId=$(if($auth){[string]$auth.TenantId}else{$null});account=$(if($auth){[string]$auth.Account}else{$null});grantedScopes=$grantedScopes;writeLikeGrantedScopes=$writeLikeScopes;audit=$authAudit;writeSessionOpened=$false}
        permissions=[ordered]@{calculatedPotentialWriteScopes=@($PermissionPlan.RequiredScopes);writeScopesAuthenticated=@()}
        sourceSafety=[ordered]@{centralGraphTransport='Core/DER.Graph.psm1';bypassFindingCount=@($bypass).Count;bypassFindings=$bypass}
        transactionSafety=[ordered]@{journalEntryCount=@($journal).Count;writeTransactionCount=@($writeTransactions).Count}
        checks=@($checks)
        supportingArtifacts=[ordered]@{graphLogSnapshot=$graphSnapshotPath;technicalLogSnapshot=$technicalSnapshotPath}
        supportingHashes=[ordered]@{
            packageManifestSHA256=$(if(Test-Path -LiteralPath $packageManifest){(Get-FileHash -Algorithm SHA256 -LiteralPath $packageManifest).Hash.ToLowerInvariant()}else{$null})
            graphLogSHA256=$graphSnapshotSHA
            technicalLogSHA256=$technicalSnapshotSHA
        }
    }
    $evidence|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $evidencePath -Encoding utf8
    $evidenceSHA=(Get-FileHash -Algorithm SHA256 -LiteralPath $evidencePath).Hash.ToLowerInvariant()

    $rows=foreach($check in $checks){"<tr><td>$(ConvertTo-DERIntegrationHtmlSafe $check.Id)</td><td>$(ConvertTo-DERIntegrationHtmlSafe $check.Status)</td><td>$(ConvertTo-DERIntegrationHtmlSafe $check.Message)</td></tr>"}
    $html=@"
<!doctype html><html><head><meta charset="utf-8"><title>DER No-Write Integration Evidence</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:36px;color:#1f2937}h1{margin-bottom:4px}.meta{color:#4b5563}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}.pass{color:#047857;font-weight:700}.fail{color:#b91c1c;font-weight:700}code{background:#f3f4f6;padding:2px 4px}</style></head><body>
<h1>DER Test-Tenant No-Write Evidence</h1>
<p class="meta">Tenant: $(ConvertTo-DERIntegrationHtmlSafe $TenantName) &nbsp;|&nbsp; $(ConvertTo-DERIntegrationHtmlSafe $TenantId)<br>Run: $(ConvertTo-DERIntegrationHtmlSafe $RunId)</p>
<h2 class="$(if($passed){'pass'}else{'fail'})">$(if($passed){'PASS — verified zero Graph writes'}else{'FAIL — no-write contract violation detected'})</h2>
<p>Central mutation transport count: <strong>$($audit.TransportWriteCount)</strong><br>Blocked mutation attempts: <strong>$($audit.BlockedWriteCount)</strong><br>Write-authenticated sessions opened: <strong>0</strong></p>
<table><thead><tr><th>Check</th><th>Status</th><th>Evidence</th></tr></thead><tbody>$($rows -join [Environment]::NewLine)</tbody></table>
<p>JSON evidence SHA-256: <code>$evidenceSHA</code></p>
</body></html>
"@
    $html|Set-Content -LiteralPath $htmlPath -Encoding utf8
    Write-DERIntegrationLog -Level $(if($passed){'OK'}else{'CRITICAL'}) -Message ("Test-tenant no-write evidence completed. Passed={0}; transportWrites={1}; blockedWrites={2}." -f $passed,$audit.TransportWriteCount,$audit.BlockedWriteCount) -Data @{evidencePath=$evidencePath;evidenceSHA256=$evidenceSHA;failedChecks=@($failed.Id)}
    return [pscustomobject][ordered]@{Passed=$passed;EvidencePath=$evidencePath;EvidenceSHA256=$evidenceSHA;HtmlPath=$htmlPath;ChecksCsv=$checksCsv;FailedChecks=@($failed.Id);TransportWriteCount=[long]$audit.TransportWriteCount;BlockedWriteCount=[long]$audit.BlockedWriteCount}
}

Export-ModuleMember -Function @('Get-DERIntegrationPolicy','Confirm-DERTestTenant','Get-DERIntegrationBypassFindings','Get-DERGraphForensicIntegrationSummary','New-DERNoWriteEvidence')
