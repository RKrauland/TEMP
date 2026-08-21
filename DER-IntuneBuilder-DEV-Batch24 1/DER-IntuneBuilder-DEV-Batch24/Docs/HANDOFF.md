# DER Intune / Entra Environment Builder — v1 Handoff

## Current package

- Product version: **v1**
- Engine: `1.0.0-dev`
- Baseline: `1.0.0`
- Development package: `1.0.0-dev`
- Build metadata: `24`
- Runtime: one parent orchestrator, 19 Core modules, 25 Workload modules
- Application deployment: intentionally outside the v1 baseline scope

## What another engineer must understand first

DER is a stateful tenant-build engine. The execution model is:

`discover -> snapshot -> analyze -> questionnaire -> plan -> adoption review -> permission resolution -> dry run -> explicit approval -> limited writes -> immediate journal/state evidence -> Microsoft read-back -> validation -> reporting`

When something fails, the preferred response is STOP + evidence + reconciliation, not an optimistic replay.

Ownership is based on Microsoft Object IDs. Names are collision/discovery aids only. DER state must be revalidated against Microsoft before an existing tracked object is trusted.

## Failure triage

Start with `Docs/LOGGING-REFERENCE.md`.

- `DER-LogIndex.json` is the front door: exact v1/internal-build identity, counts, classification contract, and every diagnostic stream path.
- `DER-EngineErrors.jsonl` answers: **Did DER/PowerShell/runtime itself fail?**
- `DER-ActionErrors.jsonl` answers: **Did DER run correctly but the requested Microsoft/tenant action fail or become unsafe?**
- `DER-Actions.jsonl` reconstructs one Action ID end to end.
- `DER-Engine.jsonl` reconstructs engine-level activity that is not tied to a tenant action.
- `DER-Errors.jsonl` is the combined structured error stream.
- `DER-Graph.jsonl`, `DER-Validation.jsonl`, and `DER-Rollback.jsonl` provide forensic detail.
- `PowerShell-Transcript.txt` is the final raw execution fallback.

The same underlying exception carries an Incident ID so a Graph/workload/orchestrator re-log can be recognized as one incident rather than three independent failures.

## Required next gates

1. On Windows, run:
   `./Start-DERIntuneBuilder.ps1 -SmokeTestOnly -InstallTestDependencies`
2. Do not proceed until AST parsing, module import, PSScriptAnalyzer Error findings, and full Pester are green.
3. Use a disposable Microsoft 365 tenant for `-TenantIntegrationTest`.
4. Run the controlled canary using the same-package no-write evidence.
5. Run the Groups workload pilot using same-package no-write + canary evidence.
6. Perform a controlled interruption/recovery exercise before broad write testing.

## Hard stop rules

Do not continue after:

- `WRITE_UNCERTAIN`
- `RECOVERY_REQUIRED`
- corrupt/missing authoritative state with prior evidence
- malformed transaction journal
- Object-ID ownership mismatch
- unproven rollback
- failed package trust-chain validation
- any Windows smoke/Pester failure

## Development boundary

This is a Development package, not a production release. Static validation does not substitute for Windows PowerShell/Pester execution. A signed Release package is a separate gate.
