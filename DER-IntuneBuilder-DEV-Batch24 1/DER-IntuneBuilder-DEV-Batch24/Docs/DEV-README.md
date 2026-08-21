# DER Intune / Entra Builder — v1 Development Operating Guide

## Purpose and scope

DER v1 is an operator-attended Intune/Entra tenant-baseline engine. It discovers the tenant, creates a deterministic plan, requires explicit safety decisions, writes only through one Graph transport, validates Microsoft state after writes, persists ownership/recovery evidence, and produces engineer-readable handoff reports.

The v1 baseline focuses on tenant policy/configuration. **Application deployment is intentionally not part of the v1 baseline.** There is no assumption that a single application set is appropriate for most businesses.

The runtime consists of one parent orchestrator, 19 Core modules, and 25 Workload modules.

## Version contract

- Product: **v1**
- Engine: `1.0.0-dev`
- Package: `1.0.0-dev`
- Build metadata: `24`
- Baseline: `1.0.0`
- Definition schema: `1.0`
- Portable state: `1.0`
- Compatibility catalog: `1.0.0`
- Minimum PowerShell: `7.4`
- Tested/bootstrap PowerShell target: `7.6.4`
- `Microsoft.Graph.Authentication`: `2.36.1`
- Smoke-test PSScriptAnalyzer: `1.24.0`
- Smoke-test Pester: `5.9.0`

The product stays at v1 until the project owner explicitly authorizes a version change. Build metadata does not imply a product-version increment.

## Runtime flow

The normal build flow is intentionally staged:

1. Package trust validation.
2. Windows/runtime preflight.
3. Core-module import.
4. Authentication for discovery reads.
5. Tenant discovery.
6. Pre-build snapshot.
7. Analysis/findings.
8. Per-tenant state initialization and lock acquisition.
9. Questionnaire/preset resolution.
10. Deterministic build plan.
11. Collision/adoption review.
12. Required-permission resolution.
13. Dry-run safety gate.
14. Explicit final build approval.
15. Write-capable authentication and write-guard opening.
16. Ordered workload execution.
17. Immediate transaction/state evidence around writes.
18. Microsoft read-back validation.
19. Failure latch/rollback/recovery when required.
20. Final reports and portable-state export.

The order is a safety boundary. Do not casually move tenant writes earlier in the lifecycle.

## Non-negotiable safety model

1. **Object ID is authority.** A display name is never ownership proof.
2. **Ownership classes remain separate.** DER-Owned, DER-Adopted, and Customer-Owned are not interchangeable.
3. **Customer-Owned means hands off.** A collision is skipped until an explicit adoption decision exists.
4. **State is not proof.** DER rereads Microsoft before trusting an existing tracked object.
5. **One Graph transport.** Workloads do not call Microsoft.Graph directly.
6. **DER owns retry policy.** Microsoft.Graph automatic retry is disabled.
7. **Reads may retry.** Definite write-side 429 may honor `Retry-After`.
8. **Ambiguous writes are not replayed.** Network/408/5xx ambiguity becomes recovery/reconciliation work.
9. **Write failure latches the run.** No later normal write is allowed after a failed/uncertain write.
10. **Rollback is scoped.** Only proven current-run/current-action work or concurrency-safe adopted-state restoration is eligible.
11. **Conditional Access stays Report-only** in the baseline.
12. **Preview writes are double-gated.** The operator must allow preview APIs and the compatibility catalog must explicitly allow the component/path.
13. **Recovery fails closed.** Corrupt state, corrupt journal, sequence gaps, unresolved write outcomes, stale adoption preparation, or unproven rollback stop execution.
14. **One write-capable workstation per tenant.** The mutex/state authority is local; it is not a distributed lock.

## Graph response and transport contract

`Invoke-DERGraphRequest` is the sole production SDK boundary. It explicitly requests PSObject output from `Invoke-MgGraphRequest`, while DER's response helpers also support dictionary/Hashtable responses defensively. Collection paging follows `value` and `@odata.nextLink` through that central wrapper.

A write must include a DER ID and Action ID. Before Graph transport is entered, DER records the transaction execution checkpoint. When Microsoft returns an object ID, DER records it as early as possible before later state/report work. If transport is known not to have started, a failure is definite-no-write; if transport was entered and the result is unknown, DER treats the outcome as uncertain and does not replay it.

## State and ownership

Authoritative local state is stored outside the package under the DER runtime root. Existing `CurrentState.json` is replaced using `System.IO.File.Replace`, with a previous-state backup captured by the same filesystem operation. A bounded retry handles transient sharing/AV interference; persistent replacement failure stops the run.

If `CurrentState.json` is missing while prior DER state/history evidence exists, DER does not initialize a blank tenant. It requires recovery/reconciliation.

Portable `.derstate` files are tenant-bound integrity envelopes. Merge is local-authoritative: existing local bindings win and imported data fills missing information. Replace is the explicit import-wins mode. Object-ID remaps, DER-ID remaps, ownership changes, and incompatible object-type changes are refused.

The portable-state SHA-256 protects integrity, not sender authenticity. Use a trusted transport process.

Example:

```powershell
# Explicit export path.
.\Start-DERIntuneBuilder.ps1 -ExportStatePath 'D:\Handoff\Customer.derstate'

# Same-tenant workstation handoff; Merge is the conservative mode.
.\Start-DERIntuneBuilder.ps1 -ImportStatePath 'D:\Handoff\Customer.derstate' -StateImportMode Merge
```

## Adoption contract

Adoption never occurs because names match. The adoption workflow performs read-only discovery, creates sanitized evidence, records desired-vs-existing differences, binds the proposed decision to the exact DER ID + Microsoft Object ID, and requires explicit acknowledgment.

For DER-Adopted objects, committed state describes the last proven Microsoft state. Current-run desired state lives in transient rollback-preparation metadata until the write is validated and committed. A crash before the write therefore does not advance the committed expectation. Rollback eligibility is tied to the current Run ID/Action ID.

## Rollback and recovery contract

Rollback does not assume a DELETE succeeded because a later GET threw. Only a genuine not-found result proves absence. Authentication, permission, throttling, transport, and other read failures are rollback-validation failures.

Historical DER-owned objects that the current run did not change are outside rollback scope, not rollback failures.

Recovery analyzes the journal chronologically. A later validated rollback may resolve an earlier failed action when DER ID/Object ID correlation proves they refer to the same change. An uncertain write with no usable identity remains unresolved.

## Failure taxonomy

DER uses two failure classes:

### ENGINE

DER, PowerShell, local runtime, or internal code did not execute correctly. Examples:

- command/function missing
- parameter-binding error
- undefined variable/property under StrictMode
- unexpected exception
- serialization/state persistence problem
- local filesystem/runtime failure
- internal invariant/catalog mismatch

Unknown/unclassified failures default to ENGINE.

### ACTION

DER executed the intended path, but the requested tenant operation could not complete safely. Examples:

- Microsoft Graph rejects the request
- exact-name customer collision
- expected target group is unavailable
- read-back/assignment/settings validation fails
- drift or reconciliation requirement
- explicit safety/precondition refusal
- rollback cannot be proven

Action ID is correlation only. It does not decide failure provenance.

See `LOGGING-REFERENCE.md` for the complete logging model.

## Runtime logging

Every run produces multiple complementary evidence streams rather than one giant ambiguous log:

- human-readable progress
- structured technical timeline
- engine timeline
- action timeline
- combined structured error stream
- ENGINE-only errors
- ACTION-only errors
- Graph forensic events
- validation events
- rollback events
- PowerShell transcript

Events include run/action/DER correlation, event sequence, UTC/local timestamps, component, package/baseline/engine identity, process/thread identity, elapsed time, and Incident ID where applicable. Secrets are redacted before structured serialization.

## Test harness

The offline test system contains synthetic Graph fixtures, workload contract tests, workload mock tests, state/recovery/rollback tests, safety tests, logging tests, package tests, and behavioral stabilization regressions.

The important distinction is:

- static scans/hashes/schema checks prove package/source properties;
- AST parsing proves PowerShell syntax;
- imports prove module load contracts;
- PSScriptAnalyzer adds static PowerShell diagnostics;
- Pester proves encoded unit/behavior contracts;
- disposable-tenant gates prove real Graph/runtime behavior.

Do not describe one gate as another.

## Windows smoke gate

Preferred command:

```powershell
.\Start-DERIntuneBuilder.ps1 -SmokeTestOnly -InstallTestDependencies
```

This is intentionally no-tenant/no-Graph-authentication. It runs Windows preflight, PowerShell AST parsing, JSON/schema validation, module import/entry-point checks, PSScriptAnalyzer, and the complete pinned Pester suite.

Direct Pester remains available:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

PSScriptAnalyzer **Error** findings block the smoke gate. Warnings are preserved for engineering review but are not automatically treated as runtime defects.

## Disposable-tenant gates

After Windows smoke is green:

### 1. No-write integration

```powershell
.\Start-DERIntuneBuilder.ps1 -TenantIntegrationTest
```

This performs real tenant discovery/planning/dry-run behind the central DenyAll write guard and produces no-write evidence.

### 2. Controlled canary

Use the same-package no-write evidence with `-TenantCanaryTest`. The canary owns exactly one temporary security group lifecycle and verifies cleanup.

### 3. Groups workload pilot

Use same-package no-write + canary evidence with `-TenantPilotTest`. The pilot invokes the real Groups workload for one temporary assigned security group, validates state, invokes normal rollback, verifies deletion/state removal, and purges only the matching deleted-item tombstone.

### 4. Interruption/recovery exercise

Before broad tenant testing, deliberately interrupt a controlled disposable-tenant write flow and confirm that restart/recovery classifies the interrupted action correctly. Preserve all run evidence.

## Package trust model

The parent launcher pins the SHA-256 of the package manifest. The package manifest hashes protected child content. `SHA256SUMS.txt` provides whole-package checksum inventory. Development permits unsigned DER source, but an invalid signature is always fatal. Release posture is defined separately in `DER-SigningPolicy.json`.

The Graph authentication dependency is isolated/pinned rather than accepting an arbitrary global module. The tested dependency is `Microsoft.Graph.Authentication 2.36.1` with the expected module GUID/publisher contract.

The PowerShell bootstrap target is 7.6.4 and automatic Microsoft Update is disabled for the pinned bootstrap install. A dependency-version decision should be deliberate and separately tested.

## Manual-action reporting

`Definitions\Portal\DER-PortalPathCatalog.json` is the source of truth for exact admin-center navigation guidance. Do not hard-code new portal paths in reporting code. Portal paths can change independently of the underlying Graph/configuration object and must be periodically reverified.

## Runtime storage

Runtime state normally lives under:

`C:\ProgramData\DER\IntuneBuilder`

A fallback runtime root is allowed only when DER can verify it is on a local fixed drive. Network/remote/removable storage is rejected for authoritative state because atomic replacement and local-lock assumptions depend on local filesystem semantics.

## Development freeze

The v1 tenant-feature scope is frozen. Continue only with defect, security, compatibility, test, observability, and documentation work until the project owner explicitly reopens feature scope.

The correct next engineering step is execution, not speculative feature work: Windows smoke -> disposable no-write -> canary -> Groups pilot -> interruption/recovery exercise.
