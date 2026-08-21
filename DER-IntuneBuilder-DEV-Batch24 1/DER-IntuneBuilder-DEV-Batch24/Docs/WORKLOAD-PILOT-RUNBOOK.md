# DER v1 End-to-End Groups Workload Pilot Runbook

## Purpose

The pilot is the controlled bridge between no-write/canary validation and broader DER tenant testing. It invokes the **real Groups workload** for exactly one temporary DER-owned object and then removes it using the normal rollback engine.

## Preconditions

Use a disposable Microsoft 365 / Entra tenant. Do not run this pilot in production.

From the exact same package and tenant, first produce:

1. passing `DER-NoWriteEvidence.json` using `-TenantIntegrationTest`
2. passing `DER-CanaryEvidence.json` using `-TenantCanaryTest`

The evidence files must bind to the same tenant, stable v1 package identity, and exact internal build; the no-write evidence must bind to the current package-manifest SHA-256. Canary cleanup must be complete.

## Pilot command

```powershell
.\Start-DERIntuneBuilder.ps1 `
  -TenantPilotTest `
  -NoWriteEvidencePath 'C:\path\DER-NoWriteEvidence.json' `
  -CanaryEvidencePath 'C:\path\DER-CanaryEvidence.json'
```

DER begins with the Graph write guard at `DenyAll`. No pilot write occurs until all evidence checks pass and the engineer types exactly:

`PILOT-WRITE`

## Allowed lifecycle

1. Invoke real `Invoke-DERGroupsModule` with a one-object pilot build plan.
2. Create one empty assigned security group named `DER Pilot - DELETE ME - <run>`.
3. Read the exact Object ID back and verify DER state.
4. Invoke normal `Invoke-DERModuleRollback` with both the exact DER ID and Microsoft Object ID.
5. Verify the active group no longer resolves and the DER state record is gone.
6. Verify the soft-deleted tombstone has the exact Object ID/display name.
7. Permanently purge only that tombstone.
8. Verify the deleted item no longer resolves.

Expected mutation contract:

- POST: 1
- PATCH: 0
- PUT: 0
- DELETE: 2
- write sessions opened: 1

No members, assignments, dynamic rules, role assignments, or existing customer objects are touched.

## Evidence

- `DER-PilotEvidence.json`
- `DER-PilotEvidence.html`
- `DER-PilotSteps.csv`

PASS requires successful workload execution, exact read-back/state validation, normal rollback success, state removal, and exact tombstone purge.

If cleanup cannot be proven, stop and account for the Object ID before any broader DER test.
