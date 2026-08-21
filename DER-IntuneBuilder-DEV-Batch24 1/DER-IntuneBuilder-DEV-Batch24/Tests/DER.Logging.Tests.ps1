# Requires -Version 7.4
# Pester 5.x

<#
.SYNOPSIS
    DER v1 Pester suite — Logging and failure-provenance contract.

.DESCRIPTION
    Proves ENGINE versus ACTION classification, incident correlation, redaction, sequence ordering, and dedicated forensic streams.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves ENGINE versus ACTION classification, incident correlation, redaction, sequence ordering, and dedicated forensic streams.
# Failure significance: A failure here means troubleshooting evidence may misidentify DER defects as tenant failures or lose correlation.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
    $LoggingPath = Join-Path $ProjectRoot 'Core\DER.Logging.psm1'
}

Describe 'DER logging failure taxonomy and forensic correlation' {
    BeforeEach {
        Remove-Module DER.Logging -Force -ErrorAction SilentlyContinue
        Import-Module $LoggingPath -Force
        Mock -ModuleName DER.Logging Start-Transcript { 'synthetic transcript' }
        Mock -ModuleName DER.Logging Stop-Transcript { 'synthetic transcript stop' }
        $script:Runtime = Join-Path ([System.IO.Path]::GetTempPath()) ('DER-LoggingTest-' + [guid]::NewGuid().ToString('N'))
        $null = Initialize-DERLogging -RunId 'LOG-TEST-RUN' -RuntimeRoot $script:Runtime -EngineVersion '1.0.0-test' -PackageVersion '1.0.0-dev' -BuildNumber 24 -BaselineVersion '1.0.0'
    }

    AfterEach {
        Stop-DERLogging -ErrorAction SilentlyContinue
        Remove-Module DER.Logging -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:Runtime -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'keeps action failures and engine failures in separate dedicated logs' {
        Write-DERActionFailure -Message 'Microsoft rejected the requested tenant action.' -Component 'TestWorkload' -ActionId 'ACT-001' -DerId 'DER-TEST-001' -Data @{statusCode=403}

        try {
            Get-Item -LiteralPath (Join-Path $script:Runtime 'does-not-exist.file') -ErrorAction Stop | Out-Null
        }
        catch {
            Write-DERError -ErrorRecord $_ -Component 'TestWorkload' -ActionId 'ACT-002' -DerId 'DER-TEST-002'
        }

        $ctx=Get-DERLoggingContext
        $actionErrors=@(Get-Content -LiteralPath $ctx.ActionErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})
        $engineErrors=@(Get-Content -LiteralPath $ctx.EngineErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})

        @($actionErrors).Count | Should -Be 1
        $actionErrors[0].failureKind | Should -Be 'Action'
        $actionErrors[0].actionId | Should -Be 'ACT-001'
        $actionErrors[0].derId | Should -Be 'DER-TEST-001'

        @($engineErrors).Count | Should -Be 1
        $engineErrors[0].failureKind | Should -Be 'Engine'
        $engineErrors[0].actionId | Should -Be 'ACT-002'
        $engineErrors[0].derId | Should -Be 'DER-TEST-002'
    }

    It 'preserves explicit ACTION classification across a rethrown ErrorRecord' {
        $exception=[System.InvalidOperationException]::new('Synthetic Graph action failure')
        $exception.Data['DERFailureKind']='Action'
        try { throw $exception }
        catch { Write-DERError -ErrorRecord $_ -Component 'Graph' -ActionId 'ACT-GRAPH' -DerId 'DER-TEST-003' }

        $ctx=Get-DERLoggingContext
        $actionErrors=@(Get-Content -LiteralPath $ctx.ActionErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})
        $engineErrors=@(Get-Content -LiteralPath $ctx.EngineErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})
        @($actionErrors | Where-Object actionId -eq 'ACT-GRAPH').Count | Should -Be 1
        @($engineErrors | Where-Object actionId -eq 'ACT-GRAPH').Count | Should -Be 0
    }

    It 'keeps ordinary action progress out of the engine-only timeline' {
        Write-DERLog -Level INFO -Component 'SyntheticWorkload' -ActionId 'ACT-ACTION-ONLY' -DerId 'DER-ACTION-ONLY' -Message 'Normal action progress.'
        $ctx=Get-DERLoggingContext
        $actions=@(Get-Content -LiteralPath $ctx.ActionLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-ACTION-ONLY')
        $engine=@(Get-Content -LiteralPath $ctx.EngineLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-ACTION-ONLY')
        @($actions).Count | Should -Be 1
        @($engine).Count | Should -Be 0
    }

    It 'keeps engine failures that occur during an action on the action timeline too' {
        try { throw [System.InvalidOperationException]::new('Synthetic DER code failure') }
        catch { Write-DERError -ErrorRecord $_ -Component 'Planner' -ActionId 'ACT-ENGINE' -DerId 'DER-TEST-004' }

        $ctx=Get-DERLoggingContext
        $timeline=@(Get-Content -LiteralPath $ctx.ActionLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})
        $row=@($timeline | Where-Object actionId -eq 'ACT-ENGINE') | Select-Object -Last 1
        $row.failureKind | Should -Be 'Engine'
        $row.eventDomain | Should -Be 'Engine'
        $row.derId | Should -Be 'DER-TEST-004'
    }

    It 'redacts secrets in dedicated action-error logs' {
        Write-DERActionFailure -Message 'Synthetic action failure.' -Component 'Test' -ActionId 'ACT-SECRET' -Data @{clientSecret='do-not-log-me';nested=@{password='also-secret';safe='visible'}}
        $ctx=Get-DERLoggingContext
        $raw=Get-Content -LiteralPath $ctx.ActionErrorLog -Raw
        $raw | Should -Not -Match 'do-not-log-me'
        $raw | Should -Not -Match 'also-secret'
        $raw | Should -Match '\[REDACTED\]'
        $raw | Should -Match 'visible'
    }

    It 'writes monotonically increasing sequence numbers with run/action/DER correlation' {
        Write-DERLog -Level INFO -Component 'Test' -Message 'First correlated event.' -ActionId 'ACT-SEQUENCE' -DerId 'DER-TEST-005' -EventDomain Action
        Write-DERForensicEvent -EventType 'SyntheticForensic' -Component 'Test' -ActionId 'ACT-SEQUENCE' -DerId 'DER-TEST-005' -Data @{step=2}
        $ctx=Get-DERLoggingContext
        $rows=@(Get-Content -LiteralPath $ctx.ActionLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-SEQUENCE')
        @($rows).Count | Should -Be 2
        [long]$rows[1].sequence | Should -BeGreaterThan ([long]$rows[0].sequence)
        @($rows | Where-Object runId -ne 'LOG-TEST-RUN').Count | Should -Be 0
        @($rows | Where-Object derId -ne 'DER-TEST-005').Count | Should -Be 0
    }
    It 'recovers action and DER correlation stamped on an exception when callers omit them' {
        $exception=[System.InvalidOperationException]::new('Synthetic correlated Graph failure')
        $exception.Data['DERFailureKind']='Action'
        $exception.Data['DERActionId']='ACT-TAGGED'
        $exception.Data['DERDerId']='DER-TEST-TAGGED'
        $exception.Data['DERComponent']='Graph'
        try { throw $exception }
        catch { Write-DERError -ErrorRecord $_ }

        $ctx=Get-DERLoggingContext
        $rows=@(Get-Content -LiteralPath $ctx.ActionErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-TAGGED')
        @($rows).Count | Should -Be 1
        $rows[0].derId | Should -Be 'DER-TEST-TAGGED'
        $rows[0].component | Should -Be 'Graph'
        $rows[0].failureKind | Should -Be 'Action'
    }

    It 'does not mistake an ActionId for proof that an unclassified error is an action failure' {
        Write-DERLog -Level ERROR -Component 'Synthetic' -ActionId 'ACT-CORRELATION-ONLY' -DerId 'DER-TEST-006' -Message 'Synthetic unclassified runtime failure.'
        $ctx=Get-DERLoggingContext
        $engineRows=@(Get-Content -LiteralPath $ctx.EngineErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-CORRELATION-ONLY')
        $actionRows=@(Get-Content -LiteralPath $ctx.ActionErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-CORRELATION-ONLY')
        @($engineRows).Count | Should -Be 1
        @($actionRows).Count | Should -Be 0
        $engineRows[0].failureKind | Should -Be 'Engine'
    }

    It 'maintains independent engine/action error counters for handoff reporting' {
        Write-DERActionFailure -Message 'Action count probe.' -Component 'Test' -ActionId 'ACT-COUNT-A'
        Write-DEREngineFailure -Message 'Engine count probe.' -Component 'Test' -ActionId 'ACT-COUNT-E'
        Write-DERLog -Level WARN -Component 'Test' -Message 'Warning count probe.'
        $summary=Get-DERLoggingSummary
        $summary.ActionErrorCount | Should -Be 1
        $summary.EngineErrorCount | Should -Be 1
        $summary.TotalErrorCount | Should -Be 2
        $summary.WarningCount | Should -Be 1
        $summary.ActionErrorLog | Should -Not -BeNullOrEmpty
        $summary.EngineErrorLog | Should -Not -BeNullOrEmpty
    }

    It 'writes a separate engine timeline and a structured combined error stream' {
        Write-DERLog -Level INFO -Component 'Planner' -Message 'Engine timeline probe.'
        Write-DERActionFailure -Message 'Action failure probe.' -Component 'Test' -ActionId 'ACT-COMB-A' -DerId 'DER-COMB-A'
        Write-DEREngineFailure -Message 'Engine failure probe.' -Component 'Test' -ActionId 'ACT-COMB-E' -DerId 'DER-COMB-E'

        $ctx=Get-DERLoggingContext
        $engineTimeline=@(Get-Content -LiteralPath $ctx.EngineLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})
        $combined=@(Get-Content -LiteralPath $ctx.StructuredErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})

        @($engineTimeline | Where-Object message -eq 'Engine timeline probe.').Count | Should -Be 1
        @($combined | Where-Object failureKind -eq 'Action').Count | Should -Be 1
        @($combined | Where-Object failureKind -eq 'Engine').Count | Should -Be 1
    }

    It 'preserves one incident ID when the same exception is logged at multiple layers' {
        $exception=New-DERFailureException -Message 'Synthetic correlated action failure.' -FailureKind Action -Component Graph -ActionId 'ACT-INCIDENT' -DerId 'DER-INCIDENT'
        try { throw $exception }
        catch {
            Write-DERError -ErrorRecord $_ -Component Graph
            Write-DERError -ErrorRecord $_ -Component Orchestrator
        }

        $ctx=Get-DERLoggingContext
        $rows=@(Get-Content -LiteralPath $ctx.StructuredErrorLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-INCIDENT')
        @($rows).Count | Should -Be 2
        @($rows.incidentId | Select-Object -Unique).Count | Should -Be 1
        $summary=Get-DERLoggingSummary
        $summary.UniqueIncidentCount | Should -Be 1
        $summary.ActionIncidentCount | Should -Be 1
        $summary.EngineIncidentCount | Should -Be 0
    }

    It 'stamps package identity, UTC timestamp, event ID, and elapsed time on structured events' {
        Write-DERLog -Level INFO -Component 'Test' -Message 'Metadata probe.' -ActionId 'ACT-META' -DerId 'DER-META' -EventDomain Action
        $ctx=Get-DERLoggingContext
        $row=@(Get-Content -LiteralPath $ctx.ActionLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40} | Where-Object actionId -eq 'ACT-META') | Select-Object -Last 1
        $row.packageVersion | Should -Be '1.0.0-dev'
        [int]$row.buildNumber | Should -Be 23
        $row.timestampUtc | Should -Not -BeNullOrEmpty
        $row.eventId | Should -Match '^LOG-TEST-RUN:[0-9]{8}$'
        [long]$row.elapsedMs | Should -BeGreaterOrEqual 0
    }

    It 'writes a run log index that explains every focused diagnostic stream and exact internal build' {
        $ctx=Get-DERLoggingContext
        Test-Path -LiteralPath $ctx.LogIndex | Should -BeTrue
        $index=Get-Content -LiteralPath $ctx.LogIndex -Raw | ConvertFrom-Json -Depth 40
        $index.productVersion | Should -Be 'v1'
        $index.packageVersion | Should -Be '1.0.0-dev'
        [int]$index.buildNumber | Should -Be 23
        $index.classification.engine | Should -Not -BeNullOrEmpty
        $index.classification.action | Should -Not -BeNullOrEmpty
        $index.classification.rule | Should -Match 'ActionId is correlation only'
        foreach($stream in @('technical','engine','actions','combinedErrors','engineErrors','actionErrors','graph','validation','rollback','transcript')){
            $index.streams.PSObject.Properties.Name | Should -Contain $stream
            [string]$index.streams.$stream.path | Should -Not -BeNullOrEmpty
            [string]$index.streams.$stream.purpose | Should -Not -BeNullOrEmpty
        }
    }

    It 'accepts the real Validation and Rollback caller contracts and preserves full focused correlation' {
        Write-DERValidationLog -ActionId 'ACT-VAL-001' -Module 'Compliance' -DerId 'DER-CMP-010' -Status 'Passed' -Message 'Validation evidence probe.' -Data @{objectId='00000000-0000-0000-0000-000000000001';check='ExpectedSubset'}
        Write-DERRollbackLog -ActionId 'ACT-RBK-001' -Module 'Compliance' -DerId 'DER-CMP-010' -Status 'RolledBack' -Message 'Rollback evidence probe.' -Data @{objectId='00000000-0000-0000-0000-000000000001';validated=$true}

        $ctx=Get-DERLoggingContext
        $validation=@(Get-Content -LiteralPath $ctx.ValidationLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40}) | Select-Object -Last 1
        $rollback=@(Get-Content -LiteralPath $ctx.RollbackLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40}) | Select-Object -Last 1
        $actions=@(Get-Content -LiteralPath $ctx.ActionLog | Where-Object {$_} | ForEach-Object {$_ | ConvertFrom-Json -Depth 40})

        $validation.eventType | Should -Be 'Validation'
        $validation.actionId | Should -Be 'ACT-VAL-001'
        $validation.derId | Should -Be 'DER-CMP-010'
        $validation.component | Should -Be 'Compliance'
        $validation.packageVersion | Should -Be '1.0.0-dev'
        [int]$validation.buildNumber | Should -Be 23

        $rollback.eventType | Should -Be 'Rollback'
        $rollback.actionId | Should -Be 'ACT-RBK-001'
        $rollback.derId | Should -Be 'DER-CMP-010'
        $rollback.status | Should -Be 'RolledBack'
        [int]$rollback.buildNumber | Should -Be 23

        @($actions | Where-Object {$_.eventType -eq 'Validation' -and $_.actionId -eq 'ACT-VAL-001'}).Count | Should -Be 1
        @($actions | Where-Object {$_.eventType -eq 'Rollback' -and $_.actionId -eq 'ACT-RBK-001'}).Count | Should -Be 1
    }

    It 'keeps the final fatal bootstrap echo out of structured error counters after Write-DERError owns the incident' {
        $parent=Get-Content -LiteralPath (Join-Path $ProjectRoot 'Start-DERIntuneBuilder.ps1') -Raw
        $parent | Should -Match 'Write-DERError -ErrorRecord \$fatalError'
        $parent | Should -Match 'Write-DERBootstrapMessage -Level ERROR -Message \$fatalError\.Exception\.Message -SkipStructuredMirror'
        $parent | Should -Match 'Write-DERBootstrapMessage -Level ERROR -Message .*ScriptStackTrace.*-SkipStructuredMirror'
    }

}

Describe 'DER workload failure provenance source contract' {
    It 'requires authored workload throws to use the workload failure factory' {
        $workloadRoot = Join-Path $ProjectRoot 'Workloads'
        foreach ($file in Get-ChildItem -LiteralPath $workloadRoot -Filter '*.psm1' -File) {
            $tokens=$null;$parseErrors=$null
            $ast=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because "$($file.Name) must parse before its failure-provenance contract can be trusted"
            $throws=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.ThrowStatementAst]},$true))
            foreach($throwAst in $throws){
                $text=[string]$throwAst.Extent.Text
                # Bare `throw` is a rethrow and deliberately preserves the original
                # exception metadata. Any authored/new throw must use the factory.
                if($text.Trim() -eq 'throw'){continue}
                $text | Should -Match 'New-DERWorkloadFailureException' -Because ("authored workload failure at {0}:{1} must declare provenance" -f $file.Name,$throwAst.Extent.StartLineNumber)
            }
        }
    }

    It 'does not allow caught workload failures to be logged without ActionId correlation' {
        $workloadRoot = Join-Path $ProjectRoot 'Workloads'
        foreach ($file in Get-ChildItem -LiteralPath $workloadRoot -Filter '*.psm1' -File) {
            foreach($line in Get-Content -LiteralPath $file.FullName){
                if($line -match '\bWrite-DERError\b' -and $line -match '-ErrorRecord'){
                    $line | Should -Match '-ActionId' -Because "$($file.Name) caught failures must retain logical-action correlation"
                }
            }
        }
    }
}
