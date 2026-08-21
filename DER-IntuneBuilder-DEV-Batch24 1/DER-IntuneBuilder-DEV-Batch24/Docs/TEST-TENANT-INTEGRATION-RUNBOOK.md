# DER Test-Tenant Integration Runbook

## Purpose

This path performs real Microsoft tenant integration while remaining deliberately **read-only**. It is intended only for a disposable/non-production Microsoft 365 test tenant.

The integration path exercises:

1. Package/preflight validation
2. Discovery-only Microsoft Graph authentication
3. Tenant identity confirmation
4. Explicit `TEST-TENANT` operator attestation
5. Tenant discovery
6. Pre-build snapshot
7. Tenant analysis
8. Discovery-driven questionnaire
9. Build-plan generation
10. Minimum write-permission calculation **without requesting those permissions**
11. Full dry run in integration no-write mode
12. Cryptographic no-write evidence generation

It does **not** perform adoption, write authentication, workload execution, or post-build validation.

## Before the first tenant run

Run the Windows-only package tests first:

```powershell
.\Start-DERIntuneBuilder.ps1 -PreflightOnly
.\Start-DERIntuneBuilder.ps1 -SmokeTestOnly -InstallTestDependencies
```

Both must pass before using a Microsoft tenant.

## Run the disposable test-tenant integration

```powershell
.\Start-DERIntuneBuilder.ps1 -TenantIntegrationTest
```

DER will:

- enable the central Graph `DenyAll` mutation guard **before authentication**;
- authenticate only with discovery/read scopes;
- show the tenant identity and require the normal `YES` scan confirmation;
- then require the literal token `TEST-TENANT` to attest that the connected tenant is disposable/non-production;
- run discovery, analysis, questionnaire, planning, permission calculation and dry run;
- never open the second/write Graph session;
- never ask for `BUILD` approval;
- exit before any workload module can execute.

## What counts as PASS

The no-write evidence must show all of the following:

- Graph write guard = `DenyAll`
- active authentication session = `Discovery`
- write-authentication attempts = `0` and write-authenticated sessions opened = `0`
- granted ReadWrite/Write scopes = `0`
- Graph mutation transport count = `0`
- blocked mutation attempts = `0`
- forensic Graph-log mutation transport events = `0`
- direct Graph transport bypass findings = `0`
- workload/write transaction phases = `0`
- final build approval = `false`
- disposable test-tenant attestation = confirmed
- frozen Graph + technical log snapshots exist and have SHA-256 hashes

A blocked POST/PATCH/PUT/DELETE still protects the tenant, but **fails the integration test** because DER code attempted a write where none should have been attempted.

## Evidence files

DER writes the proof bundle under:

```text
%ProgramData%\DER\IntuneBuilder\Evidence\<TenantId>\<RunId>\
```

or the normal DER LOCALAPPDATA fallback if ProgramData is unavailable.

Files:

- `DER-NoWriteEvidence.json` — machine-readable attestation
- `DER-NoWriteEvidence.html` — human-readable summary
- `DER-NoWriteChecks.csv` — check-by-check result list

The console also prints the SHA-256 of `DER-NoWriteEvidence.json`.

The evidence references SHA-256 hashes for the package manifest and the frozen Graph/technical log snapshots. The frozen copies prevent later logging from changing the files being used as proof.

## Important interpretation

`ReadyToBuild = false` does **not** automatically mean the integration harness failed. A questionnaire choice, missing prerequisite, or preview-API policy can legitimately create dry-run blocking items.

The integration result answers a different question:

> Did DER safely execute the real discovery-to-dry-run path while proving that zero Microsoft Graph writes occurred?

The dry-run report should be reviewed separately to decide what must be corrected before any future pilot-write phase.

## Stop conditions

Do not move to a pilot-write phase if any no-write evidence check fails, if the evidence file is missing, or if the Graph log shows any mutation transport event.
