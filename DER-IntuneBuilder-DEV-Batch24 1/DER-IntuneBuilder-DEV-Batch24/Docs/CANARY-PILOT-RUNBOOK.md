# DER v1 Controlled Canary Runbook

## Purpose

The canary proves DER can perform a tightly bounded tenant write and return a disposable test tenant to its pre-canary object state.

DER creates exactly one empty Microsoft Entra security group, validates it by Microsoft Object ID, soft-deletes it, validates the deleted object by the same Object ID, permanently purges that exact tombstone, and confirms it no longer resolves.

## Required order

1. Run `-TenantIntegrationTest` from the exact same package in a disposable/non-production tenant.
2. Keep the passing `DER-NoWriteEvidence.json`.
3. Run `-TenantCanaryTest -NoWriteEvidencePath <path>` from the same package.
4. Confirm the same tenant.
5. Type `CANARY-WRITE` exactly when DER displays the canary warning.
6. Complete delegated Graph consent/sign-in for the canary scope set.
7. Review the JSON/HTML evidence. PASS requires complete cleanup.

## Example

```powershell
.\Start-DERIntuneBuilder.ps1 -TenantCanaryTest -NoWriteEvidencePath 'C:\ProgramData\DER\IntuneBuilder\Evidence\<tenant>\<run>\DER-NoWriteEvidence.json'
```

## Tenant permissions

The canary requests delegated `Group.ReadWrite.All` plus read-only `Organization.Read.All` for tenant identity re-verification. Use an appropriately limited administrative role in the disposable tenant.

## Hard safety boundaries

- one new security group only
- no members or owners
- no dynamic membership
- no role-assignable group
- no assignment to any policy/app/resource
- no adoption or modification of existing objects
- no PATCH or PUT
- permanent purge only after the deleted item returns the exact Object ID/display name created by this run
- cleanup uncertainty = FAIL with preserved Object ID evidence

## Expected successful mutations

- POST: 1
- DELETE: 2
- PATCH: 0
- PUT: 0

The write window is deliberately limited to this lifecycle and closes afterward.
