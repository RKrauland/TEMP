# Requires -Version 7.4
# Pester 5.x

<#
.SYNOPSIS
    DER v1 Pester suite — Behavioral stabilization contract.

.DESCRIPTION
    Exercises failure modes that static text checks cannot prove: transport shape, write uncertainty, rollback validation, state corruption, recovery correlation, and latches.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Exercises failure modes that static text checks cannot prove: transport shape, write uncertainty, rollback validation, state corruption, recovery correlation, and latches.
# Failure significance: A failure here means a previously modeled safety behavior is not actually enforced by the code path under test.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot

    # The Graph transport tests intentionally replace these SDK entry points with
    # process-local stubs. DER.Graph still exercises its real retry, journaling,
    # and failure-latch code; no network request can escape this test process.
    function global:New-DERActionId { param([string]$Component) return ('TEST-' + $(if($Component){$Component}else{'ACTION'})) }
    function global:New-DERIncidentId { return ('DER-ERR-TEST-{0}' -f ([guid]::NewGuid().ToString('N').ToUpperInvariant())) }
    function global:Write-DERLog {
        param($Level,$Component,$ActionId,$DerId,$FailureKind,$IncidentId,$Message,$Data)
        if($null -eq $global:DERTestGraphLogRows){$global:DERTestGraphLogRows=[System.Collections.Generic.List[object]]::new()}
        $global:DERTestGraphLogRows.Add([pscustomobject]@{
            Level=$Level;Component=$Component;ActionId=$ActionId;DerId=$DerId
            FailureKind=$FailureKind;IncidentId=$IncidentId;Message=$Message;Data=$Data
        })
    }
    function global:Get-MgContext {
        [pscustomobject]@{ TenantId='00000000-0000-4000-8000-000000000001' }
    }
    function global:Set-MgRequestContext {
        param([int]$MaxRetry,$ErrorAction)
        $global:DERTestSdkContextCalls=[int]$global:DERTestSdkContextCalls+1
        if([string]$global:DERTestGraphScenario -eq 'RetrySuppressionFailureInsideTransport' -and $global:DERTestSdkContextCalls -ge 3){
            throw 'synthetic SDK retry suppression failure before transport invocation'
        }
        $global:DERTestSdkMaxRetry=$MaxRetry
    }
    function global:Invoke-MgGraphRequest {
        param($Method,$Uri,$Headers,[string]$ResponseHeadersVariable,[string]$StatusCodeVariable,[switch]$SkipHttpErrorCheck,[string]$OutputType,$ErrorAction,$Body,$ContentType)
        $global:DERTestTransportCalls=[int]$global:DERTestTransportCalls+1
        $global:DERTestLastOutputType=$OutputType
        switch([string]$global:DERTestGraphScenario){
            'NetworkFailure' { throw [System.Net.Http.HttpRequestException]::new('synthetic lost Graph response') }
            'Forbidden' {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 403 -Scope 1
                return [pscustomobject]@{error=[pscustomobject]@{code='Authorization_RequestDenied';message='synthetic forbidden'}}
            }
            'ServerError' {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 503 -Scope 1
                return @{error=@{code='ServiceUnavailable';message='synthetic service unavailable'}}
            }
            'ThrottleThenSuccess' {
                Set-Variable -Name $ResponseHeadersVariable -Value $(if($global:DERTestTransportCalls -eq 1){@{'Retry-After'='0'}}else{@{}}) -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value $(if($global:DERTestTransportCalls -eq 1){429}else{201}) -Scope 1
                if($global:DERTestTransportCalls -eq 1){return [pscustomobject]@{error=[pscustomobject]@{code='TooManyRequests';message='synthetic throttle'}}}
                return [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';displayName='Synthetic'}
            }
            'HashtableCreateSuccess' {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 201 -Scope 1
                return @{id='22222222-2222-4222-8222-222222222222';displayName='Hashtable Synthetic'}
            }
            'HashtablePaged' {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 200 -Scope 1
                if($global:DERTestTransportCalls -eq 1){
                    return @{
                        value=@(@{id='PAGE-1';displayName='First'})
                        '@odata.nextLink'='https://graph.microsoft.com/v1.0/groups?$skiptoken=next'
                    }
                }
                return @{value=@(@{id='PAGE-2';displayName='Second'})}
            }
            'EmptyPatchSuccess' {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 204 -Scope 1
                return $null
            }
            default {
                Set-Variable -Name $ResponseHeadersVariable -Value @{} -Scope 1
                Set-Variable -Name $StatusCodeVariable -Value 200 -Scope 1
                return [pscustomobject]@{id='11111111-1111-4111-8111-111111111111'}
            }
        }
    }

    Import-Module (Join-Path $ProjectRoot 'Core\DER.State.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Graph.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Validation.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Rollback.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Core\DER.Recovery.psm1') -Force -Global
    Import-Module (Join-Path $ProjectRoot 'Workloads\DER.LAPS.psm1') -Force -Global
}

AfterAll {
    Remove-Item function:\global:New-DERActionId -ErrorAction SilentlyContinue
    Remove-Item function:\global:New-DERIncidentId -ErrorAction SilentlyContinue
    Remove-Item function:\global:Write-DERLog -ErrorAction SilentlyContinue
    Remove-Item function:\global:Get-MgContext -ErrorAction SilentlyContinue
    Remove-Item function:\global:Set-MgRequestContext -ErrorAction SilentlyContinue
    Remove-Item function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Variable DERTestSdkMaxRetry -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable DERTestSdkContextCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable DERTestTransportCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable DERTestGraphScenario -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable DERTestLastOutputType -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable DERTestGraphLogRows -Scope Global -ErrorAction SilentlyContinue
}

Describe 'DER Graph write stabilization behavior' {
    BeforeEach {
        $global:DERTestSdkMaxRetry=$null
        $global:DERTestSdkContextCalls=0
        $global:DERTestTransportCalls=0
        $global:DERTestGraphScenario='Success'
        $global:DERTestLastOutputType=$null
        $global:DERTestGraphLogRows=[System.Collections.Generic.List[object]]::new()
        $script:CurrentStatePath=Join-Path $TestDrive 'CurrentState.json'
        '{}' | Set-Content -LiteralPath $script:CurrentStatePath -Encoding UTF8

        Mock -ModuleName DER.Graph Get-DERStateContext {
            [pscustomobject]@{Initialized=$true;RunId='TEST-GRAPH';TenantId='00000000-0000-4000-8000-000000000001';TransactionJournalPath=(Join-Path $TestDrive 'TransactionJournal.jsonl');CurrentStatePath=$script:CurrentStatePath}
        }
        Mock -ModuleName DER.Graph Register-DERTransaction {}
        Mock -ModuleName DER.Graph Set-DERRunState {}
        Mock -ModuleName DER.Graph Start-Sleep {}
        Initialize-DERGraphEngine -RunId 'TEST-GRAPH' -PackageRoot $ProjectRoot -MaxRetries 5 -BaseRetrySeconds 1 | Out-Null
    }

    It 'disables Microsoft.Graph SDK retry middleware' {
        $global:DERTestSdkMaxRetry | Should -Be 0
        (Get-DERGraphEngineContext).SdkRetrySuppressed | Should -BeTrue
    }


    It 'forces PSObject output at the Microsoft.Graph SDK boundary while paging a hashtable-shaped response safely' {
        $global:DERTestGraphScenario='HashtablePaged'
        $items=@(Invoke-DERGraphCollectionRequest -Uri 'groups' -ApiVersion v1.0 -Component 'Groups' -ActionId 'A-PAGE')
        $global:DERTestLastOutputType | Should -Be 'PSObject'
        $global:DERTestTransportCalls | Should -Be 2
        $items.Count | Should -Be 2
        $items[0]['id'] | Should -Be 'PAGE-1'
        $items[1]['id'] | Should -Be 'PAGE-2'
    }

    It 'extracts and journals a Microsoft ObjectId from a hashtable-shaped create response' {
        $global:DERTestGraphScenario='HashtableCreateSuccess'
        $result=Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Synthetic'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-HASH-ID' -MaxRetries 0
        $result['id'] | Should -Be '22222222-2222-4222-8222-222222222222'
        $global:DERTestLastOutputType | Should -Be 'PSObject'
        Assert-MockCalled -ModuleName DER.Graph Register-DERTransaction -Times 1 -ParameterFilter {$ActionId -eq 'A-HASH-ID' -and $Phase -eq 'CREATED' -and $ObjectId -eq '22222222-2222-4222-8222-222222222222'}
    }

    It 'does not invent a singleton resource name as a Microsoft ObjectId' {
        $global:DERTestGraphScenario='EmptyPatchSuccess'
        Invoke-DERGraphRequest -Method PATCH -Uri 'policies/authorizationPolicy' -ApiVersion v1.0 -Body @{allowedToSignUpEmailBasedSubscriptions=$false} -Component 'TenantSettings' -DerId 'DER-TENANT-SETTINGS' -ActionId 'A-SINGLETON' -MaxRetries 0 | Out-Null
        Assert-MockCalled -ModuleName DER.Graph Register-DERTransaction -Times 1 -ParameterFilter {$ActionId -eq 'A-SINGLETON' -and $Phase -eq 'UPDATED' -and [string]::IsNullOrWhiteSpace([string]$ObjectId)}
    }

    It 'classifies a caught failure before SDK transport as definite no-write rather than WRITE_UNCERTAIN' {
        $global:DERTestGraphScenario='RetrySuppressionFailureInsideTransport'
        { Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Never sent'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-PRETRANSPORT' -MaxRetries 5 } | Should -Throw '*before transport*'
        $global:DERTestTransportCalls | Should -Be 0
        (Get-DERGraphEngineContext).WriteFailureLatched | Should -BeTrue
        Assert-MockCalled -ModuleName DER.Graph Set-DERRunState -Times 1 -ParameterFilter {$Status -eq 'Failed' -and $Stage -eq 'WriteFailed'}
        Assert-MockCalled -ModuleName DER.Graph Register-DERTransaction -Times 1 -ParameterFilter {$ActionId -eq 'A-PRETRANSPORT' -and $Phase -eq 'FAIL' -and $Data.writeOutcome -eq 'DefiniteNoWrite' -and $Data.transportInvoked -eq $false}
    }

    It 'never replays an ambiguous POST after a transport exception and latches later writes off' {
        $global:DERTestGraphScenario='NetworkFailure'
        { Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Synthetic'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-NET' -MaxRetries 5 } | Should -Throw '*WRITE_UNCERTAIN*'
        $global:DERTestTransportCalls | Should -Be 1
        (Get-DERGraphEngineContext).WriteFailureLatched | Should -BeTrue

        { Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Never sent'} -Component 'Groups' -DerId 'DER-GRP-D-020' -ActionId 'A-BLOCKED' } | Should -Throw '*prior tenant write*'
        $global:DERTestTransportCalls | Should -Be 1
    }


    It 'keeps one incident id across Graph transport failure, write latch, and rethrow' {
        $global:DERTestGraphScenario='NetworkFailure'
        $caught=$null
        try {
            Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Synthetic'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-INCIDENT' -MaxRetries 0 | Out-Null
        }
        catch {
            $caught=$_
        }

        $caught | Should -Not -BeNullOrEmpty
        $incidentId=[string]$caught.Exception.Data['DERIncidentId']
        $incidentId | Should -Match '^DER-ERR-'
        $failureRows=@($global:DERTestGraphLogRows | Where-Object {$_.Level -in @('ERROR','CRITICAL') -and $_.ActionId -eq 'A-INCIDENT'})
        @($failureRows).Count | Should -BeGreaterThan 0
        @($failureRows | Where-Object {[string]$_.IncidentId -eq $incidentId}).Count | Should -BeGreaterThan 0
        @($failureRows | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_.IncidentId) -and [string]$_.IncidentId -ne $incidentId}).Count | Should -Be 0
    }

    It 'latches a definite Graph write failure and performs no automatic retry' {
        $global:DERTestGraphScenario='Forbidden'
        { Invoke-DERGraphRequest -Method PATCH -Uri 'groups/11111111-1111-4111-8111-111111111111' -ApiVersion v1.0 -Body @{displayName='Denied'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-403' -MaxRetries 5 } | Should -Throw '*403*'
        $global:DERTestTransportCalls | Should -Be 1
        (Get-DERGraphEngineContext).WriteFailureLatched | Should -BeTrue
        Assert-MockCalled -ModuleName DER.Graph Set-DERRunState -Times 1 -ParameterFilter {$Status -eq 'Failed' -and $Stage -eq 'WriteFailed'}
    }


    It 'does not replay PATCH after an ambiguous 503 response' {
        $global:DERTestGraphScenario='ServerError'
        { Invoke-DERGraphRequest -Method PATCH -Uri 'groups/11111111-1111-4111-8111-111111111111' -ApiVersion v1.0 -Body @{displayName='Maybe applied'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-503' -MaxRetries 5 } | Should -Throw '*WRITE_UNCERTAIN*'
        $global:DERTestTransportCalls | Should -Be 1
        (Get-DERGraphEngineContext).WriteFailureLatched | Should -BeTrue
        Assert-MockCalled -ModuleName DER.Graph Set-DERRunState -Times 1 -ParameterFilter {$Status -eq 'RecoveryRequired' -and $Stage -eq 'WriteUncertain'}
    }

    It 'preserves a returned ObjectId in RecoveryRequired run-state if the success journal append fails' {
        Mock -ModuleName DER.Graph Register-DERTransaction {
            param($Phase)
            if($Phase -eq 'CREATED'){throw 'synthetic success journal write failure'}
        }
        { Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Synthetic'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-RECEIPT' -MaxRetries 0 } | Should -Throw '*success journal*'
        $global:DERTestTransportCalls | Should -Be 1
        Assert-MockCalled -ModuleName DER.Graph Set-DERRunState -Times 1 -ParameterFilter {$Status -eq 'RecoveryRequired' -and $Stage -eq 'WriteUncertain' -and $Data.actionId -eq 'A-RECEIPT' -and $RecoveryEvidence.actionId -eq 'A-RECEIPT' -and $RecoveryEvidence.derId -eq 'DER-GRP-D-010' -and $RecoveryEvidence.details.objectId -eq '11111111-1111-4111-8111-111111111111'}
    }

    It 'retries a definite 429 only and succeeds after Retry-After' {
        $global:DERTestGraphScenario='ThrottleThenSuccess'
        $result=Invoke-DERGraphRequest -Method POST -Uri 'groups' -ApiVersion v1.0 -Body @{displayName='Synthetic'} -Component 'Groups' -DerId 'DER-GRP-D-010' -ActionId 'A-429' -MaxRetries 2
        $result.id | Should -Be '11111111-1111-4111-8111-111111111111'
        $global:DERTestTransportCalls | Should -Be 2
        (Get-DERGraphEngineContext).WriteFailureLatched | Should -BeFalse
    }

    It 'rejects a Graph URL outside the configured Microsoft Graph host before transport' {
        { Invoke-DERGraphRequest -Method GET -Uri 'https://example.invalid/v1.0/groups' -ApiVersion v1.0 -Component 'Test' -ActionId 'A-OFFHOST' } | Should -Throw '*host*'
        $global:DERTestTransportCalls | Should -Be 0
    }
}

Describe 'DER expected-subset comparison behavior' {
    It 'does not call Graph array ordering drift when the same entries are returned in a different order' {
        $expected=[pscustomobject]@{enabledRules=@('mfa','approval');reviewers=@([pscustomobject]@{query='/users/one';queryType='MicrosoftGraph'},[pscustomobject]@{query='/users/two';queryType='MicrosoftGraph'})}
        $actual=[pscustomobject]@{enabledRules=@('approval','mfa');reviewers=@([pscustomobject]@{query='/users/two';queryType='MicrosoftGraph';extra='ignored'},[pscustomobject]@{query='/users/one';queryType='MicrosoftGraph';extra='ignored'})}
        (Test-DERExpectedSubset -Actual $actual -Expected $expected).Success | Should -BeTrue
    }
}

Describe 'DER tracked-object validation behavior' {
    BeforeEach {
        $script:Record=[pscustomobject]@{
            DerId='DER-TEST-010';ObjectId='11111111-1111-4111-8111-111111111111';OwnershipClass='DER-Owned';
            Metadata=[pscustomobject]@{ValidationUri='deviceManagement/configurationPolicies/11111111-1111-4111-8111-111111111111';ApiVersion='beta';ExpectedSubset=[pscustomobject]@{name='Expected'}}
        }
        Mock -ModuleName DER.Validation Update-DERStateObject {}
    }

    It 'turns a tracked Microsoft 404 into reconciliation instead of replacement logic' {
        Mock -ModuleName DER.Validation Invoke-DERGraphRequest { $null }
        { Assert-DERManagedStateObject -StateRecord $script:Record -Component 'Test' -ActionId 'VAL-404' } | Should -Throw '*RECONCILIATION_REQUIRED*'
        Assert-MockCalled -ModuleName DER.Validation Invoke-DERGraphRequest -Times 1 -ParameterFilter {$Method -eq 'GET' -and $AllowNotFound}
        Assert-MockCalled -ModuleName DER.Validation Update-DERStateObject -Times 1 -ParameterFilter {$Status -eq 'Drifted'}
    }

    It 'propagates a non-404 read failure instead of treating the object as absent' {
        Mock -ModuleName DER.Validation Invoke-DERGraphRequest { throw '403 Forbidden synthetic read failure' }
        { Assert-DERManagedStateObject -StateRecord $script:Record -Component 'Test' -ActionId 'VAL-403' } | Should -Throw '*403 Forbidden*'
    }

    It 'fails closed on assignment drift' {
        $script:Record.Metadata | Add-Member -NotePropertyName ExpectedAssignmentTargetId -NotePropertyValue '22222222-2222-4222-8222-222222222222'
        $script:Record.Metadata | Add-Member -NotePropertyName AssignmentUri -NotePropertyValue 'deviceManagement/configurationPolicies/11111111-1111-4111-8111-111111111111/assignments'
        Mock -ModuleName DER.Validation Invoke-DERGraphRequest {
            param($Method,$Uri)
            if($Uri -like '*/assignments'){return [pscustomobject]@{value=@()}}
            return [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';name='Expected'}
        }
        { Assert-DERManagedStateObject -StateRecord $script:Record -Component 'Test' -ActionId 'VAL-ASSIGN' } | Should -Throw '*DRIFT_DETECTED*'
    }

    It 'fails closed when Settings Catalog read-back has fewer settings than recorded' {
        $script:Record.Metadata | Add-Member -NotePropertyName SettingsUri -NotePropertyValue 'deviceManagement/configurationPolicies/11111111-1111-4111-8111-111111111111/settings'
        $script:Record.Metadata | Add-Member -NotePropertyName MinimumSettingsCount -NotePropertyValue 2
        Mock -ModuleName DER.Validation Invoke-DERGraphRequest {
            param($Method,$Uri)
            if($Uri -like '*/settings'){return [pscustomobject]@{value=@([pscustomobject]@{id='one'})}}
            return [pscustomobject]@{id='11111111-1111-4111-8111-111111111111';name='Expected'}
        }
        { Assert-DERManagedStateObject -StateRecord $script:Record -Component 'Test' -ActionId 'VAL-SETTINGS' } | Should -Throw '*DRIFT_DETECTED*'
    }
}



Describe 'DER adopted prepared validation behavior' {
    It 'uses current-run prepared desired metadata for post-write validation only' {
        $record=[pscustomobject]@{DerId='DER-TEST-PREP';ObjectId='70707070-7070-4070-8070-707070707070';OwnershipClass='DER-Adopted';Metadata=[pscustomobject]@{
            ValidationUri='policies/example';ApiVersion='v1.0';ExpectedSubset=[pscustomobject]@{state='original'};
            RollbackPreparation=[pscustomobject]@{RunId='RUN-PREP';ActionId='A-PREP';Eligible=$true;ChangeMetadata=[pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='desired'}}}
        }}
        $effective=Resolve-DERValidationMetadata -StateRecord $record -ActionId 'A-PREP'
        $effective.ExpectedSubset.state | Should -Be 'desired'
        $record.Metadata.ExpectedSubset.state | Should -Be 'original'
    }

    It 'fails closed when another action encounters unresolved adopted preparation' {
        $record=[pscustomobject]@{DerId='DER-TEST-PREP';ObjectId='70707070-7070-4070-8070-707070707070';OwnershipClass='DER-Adopted';Metadata=[pscustomobject]@{
            ValidationUri='policies/example';ExpectedSubset=[pscustomobject]@{state='original'};
            RollbackPreparation=[pscustomobject]@{RunId='RUN-OLD';ActionId='A-OLD';Eligible=$true;ChangeMetadata=[pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='desired'}}}
        }}
        { Resolve-DERValidationMetadata -StateRecord $record -ActionId 'A-NEW' } | Should -Throw '*RECOVERY_REQUIRED*'
    }
}

Describe 'DER rollback proof behavior' {
    BeforeEach {
        $script:RollbackGetCount=0
        $script:RollbackRecord=[pscustomobject]@{
            DerId='DER-TEST-020';ObjectId='33333333-3333-4333-8333-333333333333';DisplayName='Synthetic';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';CreatedByRunId='RUN-CURRENT';Status='Managed';
            Metadata=[pscustomobject]@{Module='Synthetic';ValidationUri='groups/33333333-3333-4333-8333-333333333333';DeleteUri='groups/33333333-3333-4333-8333-333333333333';ApiVersion='v1.0';ExpectedSubset=[pscustomobject]@{displayName='Synthetic'}}
        }
        Mock -ModuleName DER.Rollback Get-DERCurrentState { [pscustomobject]@{Objects=@($script:RollbackRecord)} }
        Mock -ModuleName DER.Rollback Set-DERGraphRollbackWriteWindow {}
        Mock -ModuleName DER.Rollback Get-DERStateContext { $null }
        Mock -ModuleName DER.Rollback Register-DERTransaction {}
        Mock -ModuleName DER.Rollback Remove-DERStateObject {}
        Mock -ModuleName DER.Rollback Test-DERExpectedSubset { [pscustomobject]@{Success=$true;Differences=@()} }
        Mock -ModuleName DER.Rollback Invoke-DERGraphRequest {
            param($Method,$Uri)
            if($Method -eq 'DELETE'){return $null}
            if($Method -eq 'GET'){
                $script:RollbackGetCount++
                if($script:RollbackGetCount -eq 1){return [pscustomobject]@{id='33333333-3333-4333-8333-333333333333';displayName='Synthetic'}}
                throw '403 Forbidden synthetic rollback read-back'
            }
        }
    }

    It 'does not report a delete rollback as successful when read-back returns 403' {
        $report=Invoke-DERModuleRollback -Module 'Synthetic' -RunId 'RUN-CURRENT' -RuntimeRoot $TestDrive
        $report.Summary.RolledBack | Should -Be 0
        $report.Summary.Failed | Should -Be 1
        Assert-MockCalled -ModuleName DER.Rollback Remove-DERStateObject -Times 0
    }

    It 'discards transient adopted preparation after rollback without advancing committed expectations' {
        $metadata=[pscustomobject]@{
            Module='Synthetic';ValidationUri='policies/example';ApiVersion='v1.0';ExpectedSubset=[pscustomobject]@{state='original'};
            RollbackPreparation=[pscustomobject]@{RunId='RUN-CURRENT';ActionId='A-1';Eligible=$true;ChangeMetadata=[pscustomobject]@{
                ExpectedSubset=[pscustomobject]@{state='desired'};OriginalState=[pscustomobject]@{state='original'};OriginalExpectedSubset=[pscustomobject]@{state='original'};UpdateUri='policies/example';UpdateMethod='PATCH'
            }}
        }
        $restored=Get-DERAdoptedMetadataAfterRollback -Metadata $metadata
        $restored.ExpectedSubset.state | Should -Be 'original'
        $restored.PSObject.Properties.Name | Should -Not -Contain 'RollbackPreparation'
        $restored.PSObject.Properties.Name | Should -Not -Contain 'OriginalExpectedSubset'
    }


    It 'ignores historical DER-owned objects that the current run did not create' {
        $historical=[pscustomobject]@{
            DerId='DER-TEST-HIST';ObjectId='34343434-3434-4434-8434-343434343434';DisplayName='Historical';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';CreatedByRunId='RUN-OLD';Status='Validated';
            Metadata=[pscustomobject]@{Module='Synthetic';ValidationUri='groups/34343434-3434-4434-8434-343434343434';DeleteUri='groups/34343434-3434-4434-8434-343434343434';ApiVersion='v1.0';ExpectedSubset=[pscustomobject]@{displayName='Historical'}}
        }
        Mock -ModuleName DER.Rollback Get-DERCurrentState { [pscustomobject]@{Objects=@($historical)} }
        Mock -ModuleName DER.Rollback Invoke-DERGraphRequest { throw 'historical object must not be touched' }

        $report=Invoke-DERModuleRollback -Module 'Synthetic' -RunId 'RUN-CURRENT' -RuntimeRoot $TestDrive
        $report.Summary.ManualRequired | Should -Be 0
        $report.Summary.Failed | Should -Be 0
        $report.Results.Count | Should -Be 0
        Assert-MockCalled -ModuleName DER.Rollback Invoke-DERGraphRequest -Times 0
    }


    It 'does not throw under StrictMode when unrelated state metadata lacks Module or validation properties' {
        $partial=[pscustomobject]@{
            DerId='DER-TEST-PARTIAL';ObjectId='35353535-3535-4535-8535-353535353535';DisplayName='Partial';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';CreatedByRunId='RUN-CURRENT';Status='Validated';
            Metadata=[pscustomobject]@{Note='intentionally incomplete unrelated metadata'}
        }
        Mock -ModuleName DER.Rollback Get-DERCurrentState { [pscustomobject]@{Objects=@($partial)} }
        Mock -ModuleName DER.Rollback Invoke-DERGraphRequest { throw 'partial unrelated state must not be touched' }

        { $script:StrictRollbackReport=Invoke-DERModuleRollback -Module 'Synthetic' -RunId 'RUN-CURRENT' -RuntimeRoot $TestDrive } | Should -Not -Throw
        $script:StrictRollbackReport.Results.Count | Should -Be 0
        Assert-MockCalled -ModuleName DER.Rollback Invoke-DERGraphRequest -Times 0
    }
}

Describe 'DER state stabilization behavior' {
    It 'keeps newer local values during portable-state merge and only fills missing imported values' {
        $tenant='44444444-4444-4444-8444-444444444444'
        $local=[pscustomobject]@{TenantId=$tenant;TenantName='Local';BaselineVersion='1.0.0';BuildRecipe=[pscustomobject]@{Revision='new'};Questionnaire=$null;Objects=@([pscustomobject]@{DerId='DER-TEST-030';ObjectId='55555555-5555-4555-8555-555555555555';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';Metadata=[pscustomobject]@{Marker='local';OnlyLocal='keep'}})}
        $imported=[pscustomobject]@{TenantId=$tenant;TenantName='Imported';BaselineVersion='0.9.0';BuildRecipe=[pscustomobject]@{Revision='old';ImportedOnly='fill'};Questionnaire=[pscustomobject]@{Source='import'};Objects=@([pscustomobject]@{DerId='DER-TEST-030';ObjectId='55555555-5555-4555-8555-555555555555';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';Metadata=[pscustomobject]@{Marker='imported';ImportedOnly='fill'}})}
        $merged=Merge-DERTenantState -LocalState $local -ImportedState $imported
        $merged.TenantName | Should -Be 'Local'
        $merged.BaselineVersion | Should -Be '1.0.0'
        $merged.BuildRecipe.Revision | Should -Be 'new'
        $merged.BuildRecipe.ImportedOnly | Should -Be 'fill'
        $merged.Questionnaire.Source | Should -Be 'import'
        $merged.Objects[0].Metadata.Marker | Should -Be 'local'
        $merged.Objects[0].Metadata.OnlyLocal | Should -Be 'keep'
        $merged.Objects[0].Metadata.ImportedOnly | Should -Be 'fill'
    }

    It 'refuses rollback preparation for anything other than DER-Adopted state' {
        Mock -ModuleName DER.State Get-DERStateObject { [pscustomobject]@{DerId='DER-TEST-040';ObjectId='66666666-6666-4666-8666-666666666666';OwnershipClass='DER-Owned';Metadata=[pscustomobject]@{}} }
        Mock -ModuleName DER.State Update-DERStateObject {}
        { Set-DERAdoptedRollbackPreparation -ObjectId '66666666-6666-4666-8666-666666666666' -RunId 'RUN-CURRENT' -ActionId 'A-PREP' -RollbackMetadata @{OriginalState=@{state='old'}} } | Should -Throw '*not DER-Adopted*'
        Assert-MockCalled -ModuleName DER.State Update-DERStateObject -Times 0
    }


    It 'keeps committed adopted expectations unchanged while preparing a current-run change' {
        $script:PreparedRecord=[pscustomobject]@{DerId='DER-TEST-041';ObjectId='67676767-6767-4767-8767-676767676767';OwnershipClass='DER-Adopted';Metadata=[pscustomobject]@{Module='Synthetic';ValidationUri='policies/example';ExpectedSubset=[pscustomobject]@{state='original'}}}
        $script:PreparedMetadata=$null
        Mock -ModuleName DER.State Get-DERStateObject { $script:PreparedRecord }
        Mock -ModuleName DER.State Update-DERStateObject {
            param($ObjectId,$Metadata,$Status)
            $script:PreparedMetadata=$Metadata
            $script:PreparedRecord.Metadata=$Metadata
            return $script:PreparedRecord
        }
        Set-DERAdoptedRollbackPreparation -ObjectId $script:PreparedRecord.ObjectId -RunId 'RUN-CURRENT' -ActionId 'A-PREP' -RollbackMetadata ([pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='desired'};OriginalState=[pscustomobject]@{state='original'};UpdateUri='policies/example'}) | Out-Null
        $script:PreparedMetadata.ExpectedSubset.state | Should -Be 'original'
        $script:PreparedMetadata.RollbackPreparation.ActionId | Should -Be 'A-PREP'
        $script:PreparedMetadata.RollbackPreparation.ChangeMetadata.ExpectedSubset.state | Should -Be 'desired'
    }

    It 'promotes prepared desired expectations only after exact run/action finalization' {
        $script:FinalizeRecord=[pscustomobject]@{DerId='DER-TEST-042';ObjectId='68686868-6868-4868-8868-686868686868';OwnershipClass='DER-Adopted';Metadata=[pscustomobject]@{
            Module='Synthetic';ValidationUri='policies/example';ExpectedSubset=[pscustomobject]@{state='original'};
            RollbackPreparation=[pscustomobject]@{RunId='RUN-CURRENT';ActionId='A-FINAL';Eligible=$true;ChangeMetadata=[pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='desired'};OriginalState=[pscustomobject]@{state='original'};UpdateUri='policies/example';UpdateMethod='PATCH'}}
        }}
        $script:FinalizedMetadata=$null
        Mock -ModuleName DER.State Get-DERStateObject { $script:FinalizeRecord }
        Mock -ModuleName DER.State Update-DERStateObject {
            param($ObjectId,$Metadata,$Status)
            $script:FinalizedMetadata=$Metadata
            $script:FinalizeRecord.Metadata=$Metadata
            return $script:FinalizeRecord
        }
        Clear-DERAdoptedRollbackPreparation -ObjectId $script:FinalizeRecord.ObjectId -RunId 'RUN-CURRENT' -ActionId 'A-FINAL' | Out-Null
        $script:FinalizedMetadata.ExpectedSubset.state | Should -Be 'desired'
        $script:FinalizedMetadata.PSObject.Properties.Name | Should -Not -Contain 'RollbackPreparation'
        $script:FinalizedMetadata.PSObject.Properties.Name | Should -Not -Contain 'OriginalState'
        $script:FinalizedMetadata.PSObject.Properties.Name | Should -Not -Contain 'UpdateUri'
    }

    It 'refuses to overwrite unresolved adopted preparation from another run/action' {
        $script:PendingRecord=[pscustomobject]@{DerId='DER-TEST-043';ObjectId='69696969-6969-4969-8969-696969696969';OwnershipClass='DER-Adopted';Metadata=[pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='original'};RollbackPreparation=[pscustomobject]@{RunId='RUN-OLD';ActionId='A-OLD';Eligible=$true;ChangeMetadata=[pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='desired'}}}}}
        Mock -ModuleName DER.State Get-DERStateObject { $script:PendingRecord }
        Mock -ModuleName DER.State Update-DERStateObject {}
        { Set-DERAdoptedRollbackPreparation -ObjectId $script:PendingRecord.ObjectId -RunId 'RUN-NEW' -ActionId 'A-NEW' -RollbackMetadata ([pscustomobject]@{ExpectedSubset=[pscustomobject]@{state='new'}}) } | Should -Throw '*RECOVERY_REQUIRED*'
        Assert-MockCalled -ModuleName DER.State Update-DERStateObject -Times 0
    }

    It 'fails closed on corrupt CurrentState instead of restoring the previous copy' {
        $tenant='77777777-7777-4777-8777-777777777777'
        $runtime=Join-Path $TestDrive 'corrupt-state-runtime'
        $stateRoot=Join-Path (Join-Path $runtime 'State') $tenant
        New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
        '{not-json' | Set-Content -LiteralPath (Join-Path $stateRoot 'CurrentState.json') -Encoding UTF8
        '{"TenantId":"77777777-7777-4777-8777-777777777777","Objects":[]}' | Set-Content -LiteralPath (Join-Path $stateRoot 'CurrentState.previous.json') -Encoding UTF8
        function global:Get-DERAuthenticationContext { [pscustomobject]@{TenantId=$tenant;TenantName='Synthetic'} }
        try {
            { Initialize-DERState -RunId 'RUN-CORRUPT' -RuntimeRoot $runtime } | Should -Throw '*will NOT restore*'
            (Get-Content -LiteralPath (Join-Path $stateRoot 'CurrentState.json') -Raw) | Should -Match 'not-json'
            (Get-Content -LiteralPath (Join-Path $stateRoot 'CurrentState.previous.json') -Raw) | Should -Match '77777777-7777-4777-8777-777777777777'
        } finally {
            Remove-Item function:\global:Get-DERAuthenticationContext -ErrorAction SilentlyContinue
            Release-DERTenantStateLock -ErrorAction SilentlyContinue
        }
    }
}

Describe 'DER recovery correlation stabilization' {
    function New-StabilizationJournalEvent {
        param([int]$Sequence,[string]$ActionId,[string]$Phase,[string]$DerId,[string]$ObjectId,$Data=$null)
        [pscustomobject][ordered]@{journalVersion='1.1';sequence=$Sequence;timestamp=('2026-08-20T12:{0:D2}:00Z' -f $Sequence);runId='RUN-RECOVERY';tenantId='88888888-8888-4888-8888-888888888888';actionId=$ActionId;phase=$Phase;module='Synthetic';derId=$DerId;objectId=$ObjectId;message='synthetic';data=$Data}
    }

    It 'correlates a later validated rollback to the same DER identity even with a different ActionId' {
        $events=@(
            (New-StabilizationJournalEvent 1 'A-WRITE' EXECUTE 'DER-TEST-050' '99999999-9999-4999-8999-999999999999')
            (New-StabilizationJournalEvent 2 'A-WRITE' FAIL 'DER-TEST-050' '99999999-9999-4999-8999-999999999999' ([pscustomobject]@{writeOutcome='Uncertain'}))
            (New-StabilizationJournalEvent 3 'A-RB' ROLLBACK 'DER-TEST-050' '99999999-9999-4999-8999-999999999999')
            (New-StabilizationJournalEvent 4 'A-RB' ROLLBACK_VALIDATE 'DER-TEST-050' '99999999-9999-4999-8999-999999999999')
        )
        $timeline=Get-DERRecoveryActionTimelines -Events $events
        $write=@($timeline|Where-Object ActionId -eq 'A-WRITE')[0]
        $write.Disposition | Should -Be 'PreserveRolledBack'
        $write.RequiresExplicitReconcile | Should -BeFalse
        $write.CorrelatedRollbackActionId | Should -Be 'A-RB'
    }

    It 'does not correlate a shared Microsoft singleton rollback belonging to a different DER identity' {
        $events=@(
            (New-StabilizationJournalEvent 1 'A-ENTRA' EXECUTE 'DER-ENTRA-DEVICE' 'deviceRegistrationPolicy')
            (New-StabilizationJournalEvent 2 'A-ENTRA' FAIL 'DER-ENTRA-DEVICE' 'deviceRegistrationPolicy' ([pscustomobject]@{writeOutcome='Uncertain'}))
            (New-StabilizationJournalEvent 3 'A-LAPS-RB' ROLLBACK 'DER-LAPS-TENANT' 'deviceRegistrationPolicy')
            (New-StabilizationJournalEvent 4 'A-LAPS-RB' ROLLBACK_VALIDATE 'DER-LAPS-TENANT' 'deviceRegistrationPolicy')
        )
        $timeline=Get-DERRecoveryActionTimelines -Events $events
        $write=@($timeline|Where-Object ActionId -eq 'A-ENTRA')[0]
        $write.Disposition | Should -Be 'ReconcileFailed'
        $write.RequiresExplicitReconcile | Should -BeTrue
        $write.CorrelatedRollbackActionId | Should -BeNullOrEmpty
    }

    It 'enriches an unresolved action with an ObjectId preserved in RecoveryRequired run-state' {
        $tenant='88888888-8888-4888-8888-888888888888'
        $runtime=Join-Path $TestDrive 'receipt-recovery-runtime'
        $prior='RUN-RECEIPT'
        $runRoot=Join-Path (Join-Path (Join-Path $runtime 'Runs') $tenant) $prior
        New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
        [pscustomobject]@{
            SchemaVersion='1.0';RunId=$prior;TenantId=$tenant;Status='RecoveryRequired';Stage='UnhandledException';UpdatedAt='2026-08-20T12:00:00Z';ProcessId=0;
            Data=[pscustomobject]@{reason='later fatal handler updated ordinary run data'};
            RecoveryEvidence=[pscustomobject]@{actionId='A-RECEIPT';derId='DER-GRP-D-010';details=[pscustomobject]@{objectId='abababab-abab-4bab-8bab-abababababab'}}
        } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runRoot 'RunState.json') -Encoding UTF8
        @(
            (New-StabilizationJournalEvent 1 'A-RECEIPT' EXECUTE 'DER-GRP-D-010' $null)
        ) | ForEach-Object { $_.runId=$prior; ($_ | ConvertTo-Json -Depth 20 -Compress) } | Set-Content -LiteralPath (Join-Path $runRoot 'TransactionJournal.jsonl') -Encoding UTF8
        $runs=@(Get-DERIncompleteRuns -RuntimeRoot $runtime -TenantId $tenant -CurrentRunId 'RUN-CURRENT')
        $runs.Count | Should -Be 1
        $action=@($runs[0].Actions|Where-Object ActionId -eq 'A-RECEIPT')[0]
        $action.ObjectId | Should -Be 'abababab-abab-4bab-8bab-abababababab'
        $action.RequiresExplicitReconcile | Should -BeTrue
    }

    It 'keeps an uncertain create with no known Microsoft ObjectId unresolved' {
        $events=@(
            (New-StabilizationJournalEvent 1 'A-CREATE' EXECUTE 'DER-GRP-D-010' $null)
            (New-StabilizationJournalEvent 2 'A-CREATE' FAIL 'DER-GRP-D-010' $null ([pscustomobject]@{writeOutcome='Uncertain'}))
        )
        $timeline=Get-DERRecoveryActionTimelines -Events $events
        $timeline[0].Disposition | Should -Be 'ReconcileFailed'
        $timeline[0].RequiresExplicitReconcile | Should -BeTrue
        $timeline[0].CorrelatedRollbackActionId | Should -BeNullOrEmpty
    }
}


Describe 'DER LAPS transaction-domain isolation' {
    BeforeEach {
        $script:LapsPolicy=[pscustomobject]@{
            DerId='DER-LAPS-010';ObjectId='12121212-1212-4212-8212-121212121212';DisplayName='DER - Windows LAPS';ObjectType='SettingsCatalog';OwnershipClass='DER-Owned';Status='Validated';CreatedByRunId='RUN-OLD';
            Metadata=[pscustomobject]@{Module='LAPS';ValidationUri='deviceManagement/configurationPolicies/12121212-1212-4212-8212-121212121212';ApiVersion='beta';ExpectedSubset=[pscustomobject]@{name='DER - Windows LAPS'}}
        }
        $script:LapsPilot=[pscustomobject]@{
            DerId='DER-GRP-D-010';ObjectId='13131313-1313-4313-8313-131313131313';DisplayName='DER Pilot';ObjectType='SecurityGroup';OwnershipClass='DER-Owned';Status='Validated';CreatedByRunId='RUN-OLD';
            Metadata=[pscustomobject]@{Module='Groups';ValidationUri='groups/13131313-1313-4313-8313-131313131313';ApiVersion='v1.0';ExpectedSubset=[pscustomobject]@{displayName='DER Pilot'}}
        }
        Mock -ModuleName DER.LAPS New-DERActionId { param($Component) if($Component -eq 'LAPS-SWITCH'){'SWITCH-ACTION'}else{'POLICY-ACTION'} }
        Mock -ModuleName DER.LAPS Get-DERStateObject { param($DerId) if($DerId -eq 'DER-GRP-D-010'){$script:LapsPilot}elseif($DerId -eq 'DER-LAPS-010'){$script:LapsPolicy}else{$null} }
        Mock -ModuleName DER.LAPS Assert-DERManagedStateObject { [pscustomobject]@{Success=$true} }
        Mock -ModuleName DER.LAPS Register-DERTransaction {}
        Mock -ModuleName DER.LAPS Get-DERStateContext { $null }
        Mock -ModuleName DER.LAPS Test-DERExpectedSubset { [pscustomobject]@{Success=$true;Differences=@()} }
        Mock -ModuleName DER.LAPS Invoke-DERGraphRequest {
            param($Method,$Uri,$ApiVersion,$Body,$Component,$DerId,$ActionId)
            if($Method -eq 'GET' -and $Uri -eq 'policies/deviceRegistrationPolicy'){
                return [pscustomobject]@{id='deviceRegistrationPolicy';localAdminPassword=[pscustomobject]@{isEnabled=$false}}
            }
            if($Method -eq 'PUT' -and $Uri -eq 'policies/deviceRegistrationPolicy'){return [pscustomobject]@{id='deviceRegistrationPolicy'}}
            throw "Unexpected synthetic LAPS Graph request: $Method $Uri"
        }
    }

    It 'uses a distinct ActionId for the shared tenant switch so its rollback cannot terminate the policy action' {
        $build=[pscustomobject]@{
            TenantId='14141414-1414-4414-8414-141414141414';BaselineVersion='1.0.0';Profile='Standard';EnvironmentClassification='NewOrMostlyEmpty';
            Answers=[pscustomobject]@{Safety=[pscustomobject]@{AllowPreviewApis=$true;ChangeControl='Approved'};Security=[pscustomobject]@{LAPSRotationDays=30;LAPSPasswordLength=16;LAPSPostAuthRotation=$false}}
            Objects=@([pscustomobject]@{Enabled=$true;Module='LAPS';DerId='DER-LAPS-010';DisplayName='DER - Windows LAPS';ObjectType='SettingsCatalog'})
        }
        $result=Invoke-DERLAPSModule -BuildPlan $build -RunId 'RUN-CURRENT' -RuntimeRoot $TestDrive
        $result.Status | Should -Be 'Completed'
        Assert-MockCalled -ModuleName DER.LAPS Invoke-DERGraphRequest -Times 1 -ParameterFilter {$Method -eq 'PUT' -and $DerId -eq 'DER-LAPS-TENANT' -and $ActionId -eq 'SWITCH-ACTION'}
        Assert-MockCalled -ModuleName DER.LAPS Invoke-DERGraphRequest -Times 0 -ParameterFilter {$Method -eq 'PUT' -and $DerId -eq 'DER-LAPS-TENANT' -and $ActionId -eq 'POLICY-ACTION'}
    }
}

Describe 'DER immutable baseline coverage regression' {
    It 'contains every statically declared planner DER ID' {
        $planner=Get-Content (Join-Path $ProjectRoot 'Core\DER.Planner.psm1') -Raw
        $staticIds=@([regex]::Matches($planner,"'(?<id>DER-[A-Z0-9-]+)'")|ForEach-Object{$_.Groups['id'].Value}|Sort-Object -Unique)
        $baseline=Get-Content (Join-Path $ProjectRoot 'Definitions\Baselines\1.0.0\DER-Baseline.index.json') -Raw | ConvertFrom-Json -Depth 100
        $baselineIds=@($baseline.definitions.derId|Sort-Object -Unique)
        $staticIds.Count | Should -Be 73
        $baselineIds.Count | Should -Be $staticIds.Count
        foreach($id in $staticIds){$baselineIds | Should -Contain $id -Because "static planner DER ID $id must be immutable-baseline indexed"}
        foreach($id in $baselineIds){$staticIds | Should -Contain $id -Because "immutable-baseline entry $id must map to a literal planner DER ID"}
        $dynamic=@($baseline.metadata.dynamicDerIdPatterns)
        $dynamic.Count | Should -Be 2
        @($dynamic.id) | Should -Contain 'DepartmentUserGroups'
        @($dynamic.id) | Should -Contain 'SiteNamedLocations'
        @($dynamic.sourceExpression) | Should -Contain 'DER-GRP-U-{0}'
        @($dynamic.sourceExpression) | Should -Contain 'DER-LOC-SITE-{0:000}'
    }
}

Describe 'DER beta-write compatibility-catalog coupling' {
    It 'keeps every literal workload beta-write Component backed by a compatibility-catalog module entry' {
        $catalog=Get-Content (Join-Path $ProjectRoot 'Definitions\Compatibility\DER-CompatibilityCatalog.json') -Raw | ConvertFrom-Json -Depth 40
        $catalogModules=@($catalog.entries | Where-Object {$_.apiVersion -eq 'beta' -and [bool]$_.previewWriteAllowed} | ForEach-Object {[string]$_.module} | Sort-Object -Unique)
        $writeMethods=@('POST','PATCH','PUT','DELETE')
        $seen=New-Object System.Collections.Generic.HashSet[string]

        foreach($file in Get-ChildItem (Join-Path $ProjectRoot 'Workloads') -Filter '*.psm1' -File){
            $tokens=$null;$parseErrors=$null
            $ast=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because "$($file.Name) must parse before compatibility analysis"
            $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-DERGraphRequest'},$true))
            foreach($command in $commands){
                $parameters=@{}
                $elements=@($command.CommandElements)
                for($i=1;$i -lt $elements.Count;$i++){
                    if($elements[$i] -isnot [System.Management.Automation.Language.CommandParameterAst]){continue}
                    $name=[string]$elements[$i].ParameterName
                    if($i+1 -lt $elements.Count -and $elements[$i+1] -is [System.Management.Automation.Language.StringConstantExpressionAst]){
                        $parameters[$name]=[string]$elements[$i+1].Value
                    }
                }
                if([string]$parameters['ApiVersion'] -ne 'beta' -or [string]$parameters['Method'] -notin $writeMethods){continue}
                $component=[string]$parameters['Component']
                [string]::IsNullOrWhiteSpace($component) | Should -BeFalse -Because "$($file.Name) beta writes require a literal Component safety identity"
                if($component -notin @('Rollback','Recovery','Graph')){
                    $catalogModules | Should -Contain $component -Because "$($file.Name) beta write Component '$component' must match an enabled compatibility-catalog module"
                    $null=$seen.Add($component)
                }
            }
        }
        $seen.Count | Should -BeGreaterThan 0
    }
}

Describe 'DER Autopilot helper context contracts' {
    BeforeAll {
        $autopilotSource=Get-Content -LiteralPath (Join-Path $ProjectRoot 'Workloads\DER.Autopilot.psm1') -Raw
    }
    It 'passes DER ID explicitly into ESP assignment validation instead of relying on caller scope' {
        $match=[regex]::Match($autopilotSource,'(?s)function\s+Test-DERESPAssignment\s*\{(?<body>.*?)\n\}')
        $match.Success | Should -BeTrue
        $match.Groups['body'].Value | Should -Match '\[Parameter\(Mandatory\)\]\[string\]\$DerId'
        $match.Groups['body'].Value | Should -Match '-DerId\s+\$DerId'
        $match.Groups['body'].Value | Should -Not -Match '\$Planned\.DerId'
        $autopilotSource | Should -Match 'Test-DERESPAssignment .* -DerId \$Planned\.DerId'
    }
    It 'does not let the Autopilot log wrapper read an undeclared Planned variable' {
        $match=[regex]::Match($autopilotSource,'(?s)function\s+Write-DERAutopilotLog\s*\{(?<body>.*?)\n?\}')
        $match.Success | Should -BeTrue
        $match.Groups['body'].Value | Should -Match '\[string\]\$DerId'
        $match.Groups['body'].Value | Should -Not -Match '\$Planned'
    }
}

Describe 'DER PowerShell command-binding regressions' {
    It 'does not specify the same named parameter twice in one command invocation' {
        $findings=New-Object System.Collections.Generic.List[string]
        foreach($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1')}){
            $tokens=$null;$parseErrors=$null
            $ast=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because "$($file.FullName) must parse before command-binding analysis"
            $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]},$true))
            foreach($command in $commands){
                $parameterNames=@($command.CommandElements | Where-Object {$_ -is [System.Management.Automation.Language.CommandParameterAst]} | ForEach-Object {[string]$_.ParameterName})
                $duplicates=@($parameterNames | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
                if($duplicates.Count -gt 0){
                    $findings.Add(("{0}:{1}: {2} duplicates parameter(s): {3}" -f $file.FullName,$command.Extent.StartLineNumber,$command.GetCommandName(),($duplicates -join ', ')))
                }
            }
        }
        @($findings) | Should -BeNullOrEmpty -Because 'a duplicate named parameter is a runtime parameter-binding failure, not a stylistic issue'
    }

    It 'uses only the current New-DERActionId Component parameter contract' {
        $findings=New-Object System.Collections.Generic.List[string]
        foreach($file in Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1')}){
            $tokens=$null;$parseErrors=$null
            $ast=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
            @($parseErrors).Count | Should -Be 0 -Because "$($file.FullName) must parse before New-DERActionId contract analysis"
            $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-DERActionId'},$true))
            foreach($command in $commands){
                $names=@($command.CommandElements | Where-Object {$_ -is [System.Management.Automation.Language.CommandParameterAst]} | ForEach-Object {[string]$_.ParameterName})
                foreach($name in $names){
                    if($name -ne 'Component'){$findings.Add(("{0}:{1}: unsupported New-DERActionId parameter -{2}" -f $file.FullName,$command.Extent.StartLineNumber,$name))}
                }
            }
        }
        @($findings) | Should -BeNullOrEmpty -Because 'all callers must use the centralized v1 action-ID signature'
    }
}
