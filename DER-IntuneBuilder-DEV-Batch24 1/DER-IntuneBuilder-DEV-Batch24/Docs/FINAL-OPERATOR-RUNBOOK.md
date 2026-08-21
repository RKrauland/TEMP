# DER v1 Final Development Operator Runbook

DER v1 is a Development-channel package and is not yet a production release. Do not use it for customer-tenant writes until the exact package has passed the complete validation sequence below.

## Primary operating rule

Use one clean, unmodified package folder for the entire evidence chain. Evidence is package-bound by SHA-256. If a protected file changes, reseal the package and restart the evidence chain.

Use one write-capable Windows workstation per tenant. DER's mutex and authoritative state store are local to the workstation, not distributed between engineers.

## Stage 1 — Windows smoke

From the package root in PowerShell 7 on Windows x64:

```powershell
.\Start-DERIntuneBuilder.ps1 -SmokeTestOnly -InstallTestDependencies
```

Required result: `DER SMOKE-TEST-ONLY RESULT: PASS`.

This stage is tenant-blind. It validates package integrity, workstation/runtime readiness, PowerShell AST parsing, JSON/schema validation, module imports/entry points, PSScriptAnalyzer, and the full pinned Pester suite. It performs no Graph authentication or Graph API request.

Stop if any parser/import/PSScriptAnalyzer Error/Pester failure occurs.

## Stage 2 — Disposable-tenant no-write integration

Use a disposable/non-production Microsoft 365 tenant:

```powershell
.\Start-DERIntuneBuilder.ps1 -TenantIntegrationTest
```

Type `TEST-TENANT` only after verifying the displayed tenant is disposable/non-production.

Required evidence: `DER-NoWriteEvidence.json` = PASS with zero Graph mutations and zero write-authentication attempts.

## Stage 3 — Controlled canary

Use the exact no-write evidence from Stage 2:

```powershell
.\Start-DERIntuneBuilder.ps1 `
  -TenantCanaryTest `
  -NoWriteEvidencePath 'C:\path\DER-NoWriteEvidence.json'
```

Type `CANARY-WRITE` only in the same disposable tenant.

Required evidence: `DER-CanaryEvidence.json` = PASS, cleanup complete, exact mutation delta `POST=1, PATCH=0, PUT=0, DELETE=2`.

## Stage 4 — Groups workload pilot

Use the exact no-write and canary evidence files:

```powershell
.\Start-DERIntuneBuilder.ps1 `
  -TenantPilotTest `
  -NoWriteEvidencePath 'C:\path\DER-NoWriteEvidence.json' `
  -CanaryEvidencePath 'C:\path\DER-CanaryEvidence.json'
```

Type `PILOT-WRITE` only in the same disposable tenant.

Required evidence: `DER-PilotEvidence.json` = PASS, normal rollback/cleanup proven, DER state removed, exact mutation delta `POST=1, PATCH=0, PUT=0, DELETE=2`.

## Stage 5 — Controlled interruption/recovery exercise

Before broad tenant testing, repeat a controlled disposable-tenant write scenario and intentionally terminate DER after Graph transport is entered but before the complete action lifecycle finishes.

On restart:

1. Preserve the interrupted run directory.
2. Run DER recovery analysis.
3. Confirm the interrupted action is not silently replayed.
4. Confirm unresolved/uncertain state becomes `RecoveryRequired` when appropriate.
5. Confirm exact Object ID / DER ID / Action ID / Incident ID evidence is sufficient to identify what occurred.
6. Reconcile/clean up the disposable object before proceeding.

This test exists specifically to prove the write-uncertainty/recovery design under real interruption.

## Stage 6 — Development certification

```powershell
.\Tools\Invoke-DERDevCertification.ps1 `
  -InstallTestDependencies `
  -NoWriteEvidencePath 'C:\path\DER-NoWriteEvidence.json' `
  -CanaryEvidencePath 'C:\path\DER-CanaryEvidence.json' `
  -PilotEvidencePath 'C:\path\DER-PilotEvidence.json'
```

Required result: `DER DEVELOPMENT CERTIFICATION: FULL-PASS`.

FULL-PASS means the required Development gates passed. It does **not** mean the package is an approved signed production release.

## Failure triage

Preserve the entire run folder. Start with `Docs\LOGGING-REFERENCE.md`.

- `DER-EngineErrors.jsonl`: DER/PowerShell/runtime failures.
- `DER-ActionErrors.jsonl`: Microsoft/tenant/action/safety/read-back failures.
- `DER-Errors.jsonl`: combined structured error stream.
- `DER-Actions.jsonl`: Action-ID timeline.
- `DER-Engine.jsonl`: engine timeline.
- `DER-Graph.jsonl`: transport/write-outcome evidence.
- `DER-Validation.jsonl`: read-back validation.
- `DER-Rollback.jsonl`: rollback evidence.

Do not rerun a write-capable flow while `WRITE_UNCERTAIN`, `RECOVERY_REQUIRED`, state corruption, journal corruption, or unproven rollback remains unresolved.

## Production boundary

DER v1 remains Development-channel with `productionReady=false` until the release policy is satisfied. Passing Development gates is necessary evidence; it is not authorization to bypass the signed Release packaging requirements.
