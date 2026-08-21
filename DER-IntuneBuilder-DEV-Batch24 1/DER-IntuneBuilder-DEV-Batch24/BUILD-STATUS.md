# DER Intune / Entra Environment Builder — v1 Build Status

## Product identity

DER is held at **v1**. The current development package identifies itself as engine `1.0.0-dev`, baseline `1.0.0`, package `1.0.0-dev`, build `24`. The build number is packaging/build metadata; it is not a product-version increment.

The executable tenant runtime contains one parent orchestrator, 19 Core modules, and 25 Workload modules. Application deployment is intentionally outside the v1 baseline scope.

## Development posture

The v1 tenant-feature scope is frozen. Source work is limited to defect, security, compatibility, test, observability, and documentation corrections unless the project owner explicitly reopens feature scope.

This package is a **Development** package. `productionReady` remains false until the required Windows and disposable-tenant gates pass and an approved Release package is produced under the signing policy.

## Safety contract

DER is designed to fail closed. The non-negotiable runtime rules are:

1. Microsoft Object ID is the ownership authority. A display name is never proof of ownership.
2. DER-Owned, DER-Adopted, and Customer-Owned objects remain distinct.
3. Customer-Owned objects are not automatically modified or deleted.
4. Existing state records are revalidated against Microsoft; state is evidence, not proof.
5. All workload Graph traffic passes through the central Graph transport.
6. The Microsoft.Graph SDK retry layer is disabled; DER owns retry behavior.
7. GET operations may retry transient failures. A definite write-side 429 may follow Retry-After. An ambiguous write outcome is never automatically replayed.
8. A failed or uncertain write closes the normal write latch. Rollback uses an explicitly limited rollback-only write window.
9. Every write is transaction-correlated with DER ID and Action ID and is read-back validated where the API permits it.
10. Conditional Access remains Report-only in the v1 baseline.
11. Rollback is limited to work DER can prove belongs to the current run/action or to concurrency-safe adopted-state restoration.
12. Corrupt state, journal ambiguity, interrupted ownership preparation, and unresolved writes stop for recovery/reconciliation.
13. The per-tenant mutex and authoritative state store are local to one workstation. Only one workstation may perform write-capable DER work against a tenant at a time.

## Failure and logging contract

DER distinguishes **ENGINE** from **ACTION** failures.

- **ENGINE**: DER/PowerShell/runtime did not execute correctly. Examples include a missing command, parameter-binding defect, unexpected null/property failure, serialization failure, local state persistence failure, or another unclassified code/runtime exception.
- **ACTION**: DER executed the intended path, but the requested tenant operation could not complete safely. Examples include Microsoft Graph denial, collision, read-back mismatch, drift, reconciliation requirement, or an explicit safety/precondition refusal.

An Action ID is correlation only; it does not prove failure provenance. Unknown/unclassified failures default to ENGINE.

Every run maintains human, technical, engine-timeline, action-timeline, combined structured-error, engine-error, action-error, Graph, validation, rollback, and PowerShell transcript evidence. See `Docs/LOGGING-REFERENCE.md`.

## Required external gates

Run these gates in order. Stop at the first failure.

1. **Windows smoke** — parser, JSON/schema validation, imports/entry points, PSScriptAnalyzer, full Pester. No Graph authentication or tenant mutation.
2. **Disposable tenant no-write integration** — real discovery/planning/dry-run under a central DenyAll write guard.
3. **Controlled canary** — one temporary security-group lifecycle with exact-object validation and cleanup.
4. **Groups workload pilot** — real Groups workload for one temporary object, normal rollback, tombstone verification, and purge.
5. **Crash/recovery exercise** — interrupt a controlled disposable-tenant write flow and prove recovery classification before broader tenant testing.

No real customer tenant should be used for write-capable validation until the disposable-tenant gates are green.

## Current validation boundary

The source/package can be statically inspected in the build environment, but the authoritative runtime gate is PowerShell 7 on Windows. Do not describe static lexical/grep/schema/hash checks as a successful Pester or runtime execution. A green Windows smoke result is required before tenant testing.

## Static package evidence

The current source tree contains 69 PowerShell source/test/helper files, 66 JSON documents, 22 JSON schemas, 17 Pester suites, 19 Core modules, and 25 Workload modules.

The pre-seal static gate verifies all 69 PowerShell files with an independent lexical/delimiter scan; all 66 JSON documents parse; all 21 schema-bound documents validate; the two immutable-baseline files match `DER-Baseline.manifest.json`; all 44 parent module-catalog entry points exist; all 73 fixed planner DER IDs match the immutable baseline index; both generated DER-ID families are explicitly modeled; all detected Core/Workload Graph writes carry DER-ID correlation; Workloads contain no direct Graph SDK/REST transport; no empty catch blocks are present; and every PowerShell source/test/helper file carries maintenance notes describing its responsibility and safety boundaries.

These checks are **static evidence**. The 17 Pester suites have not been executed in this build environment. PowerShell 7 AST parsing on Windows, module imports, PSScriptAnalyzer, and Pester remain the authoritative next gate.
