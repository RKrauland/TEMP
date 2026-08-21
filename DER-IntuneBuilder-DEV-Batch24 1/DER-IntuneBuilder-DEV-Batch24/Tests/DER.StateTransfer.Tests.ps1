# Requires -Version 7.4
# Pester 5.x
#
<#
.SYNOPSIS
    DER v1 Pester suite — Portable-state contract.

.DESCRIPTION
    Proves tenant binding, integrity, merge conservatism, replace semantics, and state isolation across tests.
.NOTES
    Pester must execute this suite for the result to count. Keep mocks below the
    behavior under test so they do not bypass the code being validated.
#>

# Test intent: Proves tenant binding, integrity, merge conservatism, replace semantics, and state isolation across tests.
# Failure significance: A failure here means portable state could remap ownership, rewind local authority, or contaminate another test/run.
# Static inspection of this file is not an executed Pester result.


BeforeAll {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
Describe 'DER portable state transfer' {
    BeforeEach {
        Remove-Module DER.State -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $ProjectRoot 'Core\DER.State.psm1') -Force
        $global:DERTestTenantId='11111111-2222-3333-4444-555555555555'
        function global:Get-DERAuthenticationContext { [pscustomobject]@{TenantId=$global:DERTestTenantId;TenantName='Test Tenant'} }
        $script:Runtime=Join-Path ([System.IO.Path]::GetTempPath()) ('DER-StateTest-'+[guid]::NewGuid().ToString('N'))
        Initialize-DERState -RunId 'TEST-RUN' -RuntimeRoot $script:Runtime | Out-Null
    }
    AfterEach {
        Release-DERTenantStateLock -ErrorAction SilentlyContinue
        Remove-Module DER.State -Force -ErrorAction SilentlyContinue
        Remove-Item function:\global:Get-DERAuthenticationContext -ErrorAction SilentlyContinue
        Remove-Variable DERTestTenantId -Scope Global -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:Runtime -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'round-trips a tenant-bound state envelope with SHA-256 integrity' {
        Add-DERStateObject -DerId 'DER.TEST.001' -ObjectId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' -ObjectType 'group' -DisplayName 'Test' -OwnershipClass 'DER-Owned' | Out-Null
        $export=Export-DERPortableState
        $validation=Test-DERPortableState -Path $export.Path -ExpectedTenantId $global:DERTestTenantId
        $validation.Valid | Should -BeTrue
        $validation.ActualPayloadSHA256 | Should -Be $export.PayloadSHA256
        @($validation.State.Objects).Count | Should -Be 1
    }
    It 'rejects a portable state bound to a different tenant' {
        $export=Export-DERPortableState
        $validation=Test-DERPortableState -Path $export.Path -ExpectedTenantId '99999999-9999-9999-9999-999999999999'
        $validation.Valid | Should -BeFalse
        ($validation.Errors -join ' ') | Should -Match 'does not match authenticated tenant'
    }
    It 'detects payload tampering' {
        $export=Export-DERPortableState
        $envelope=Get-Content $export.Path -Raw | ConvertFrom-Json -Depth 80
        $bytes=[Convert]::FromBase64String($envelope.PayloadBase64)
        $bytes[0]=($bytes[0] -bxor 1)
        $envelope.PayloadBase64=[Convert]::ToBase64String($bytes)
        $envelope | ConvertTo-Json -Depth 80 | Set-Content -LiteralPath $export.Path -Encoding UTF8
        (Test-DERPortableState -Path $export.Path -ExpectedTenantId $global:DERTestTenantId).Valid | Should -BeFalse
    }
    It 'refuses a merge that remaps a DerId to another Microsoft ObjectId' {
        $local=Get-DERCurrentState
        $local.Objects=@([pscustomobject]@{DerId='DER.TEST.001';ObjectId='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';ObjectType='group';OwnershipClass='DER-Owned'})
        $imported=($local | ConvertTo-Json -Depth 80 | ConvertFrom-Json -Depth 80)
        $imported.Objects[0].ObjectId='ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'
        { Merge-DERTenantState -LocalState $local -ImportedState $imported } | Should -Throw '*maps to local Microsoft ObjectId*'
    }
    It 'backs up state before replace import' {
        $export=Export-DERPortableState
        $result=Import-DERPortableState -Path $export.Path -Mode Replace
        Test-Path (Join-Path $result.BackupRoot 'CurrentState.before-import.json') | Should -BeTrue
        Test-Path $result.ReceiptPath | Should -BeTrue
    }

    It 'uses replacement semantics so CurrentState.previous.json is the exact prior committed state' {
        $state=Get-DERCurrentState
        $state | Add-Member -NotePropertyName TestRevision -NotePropertyValue 'old' -Force
        Save-DERCurrentState -State $state | Out-Null
        $state.TestRevision='new'
        Save-DERCurrentState -State $state | Out-Null

        $context=Get-DERStateContext
        $current=Get-Content -LiteralPath $context.CurrentStatePath -Raw | ConvertFrom-Json -Depth 80
        $previous=Get-Content -LiteralPath $context.PreviousStatePath -Raw | ConvertFrom-Json -Depth 80
        $current.TestRevision | Should -Be 'new'
        $previous.TestRevision | Should -Be 'old'
    }

    It 'fails closed if CurrentState disappears while prior DER tenant evidence exists' {
        $context=Get-DERStateContext
        Remove-Item -LiteralPath $context.CurrentStatePath -Force
        Release-DERTenantStateLock
        Remove-Module DER.State -Force
        Import-Module (Join-Path $ProjectRoot 'Core\DER.State.psm1') -Force
        { Initialize-DERState -RunId 'TEST-RECOVERY' -RuntimeRoot $script:Runtime } | Should -Throw '*RECOVERY_REQUIRED*'
    }
    It 'preserves the prior committed CurrentState when atomic replacement cannot acquire the destination' {
        $context=Get-DERStateContext
        $before=[System.IO.File]::ReadAllText($context.CurrentStatePath)
        $state=Get-DERCurrentState
        $state | Add-Member -NotePropertyName LockedWriteProbe -NotePropertyValue 'new-value' -Force
        $exclusive=[System.IO.File]::Open($context.CurrentStatePath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::None)
        try {
            { Save-DERCurrentState -State $state } | Should -Throw
        }
        finally {
            $exclusive.Dispose()
        }
        [System.IO.File]::ReadAllText($context.CurrentStatePath) | Should -BeExactly $before
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $context.CurrentStatePath) -Filter ('.{0}.*.tmp' -f [System.IO.Path]::GetFileName($context.CurrentStatePath)) -File -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

}
