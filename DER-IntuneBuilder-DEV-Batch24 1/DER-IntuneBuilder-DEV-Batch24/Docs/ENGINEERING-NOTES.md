# DER v1 Engineering Notes

This document describes **current behavior and maintainer invariants** for DER v1.

## 1. The five authorities

The following responsibilities have a single owner:

1. **Graph authority:** `Core/DER.Graph.psm1` is the production Graph transport/retry/write-latch authority.
2. **State authority:** `Core/DER.State.psm1` owns persistent per-tenant DER state and transaction-journal persistence.
3. **Ownership authority:** Microsoft Object ID is the only authoritative Microsoft-object identity. DER ID is DER's logical identity; display name is never ownership proof.
4. **Rollback authority:** `Core/DER.Rollback.psm1` is the primary rollback engine; special singleton rollback exists only where a shared Microsoft singleton makes a second ownership record unsafe.
5. **Recovery authority:** `Core/DER.Recovery.psm1` interprets interrupted/failed run evidence chronologically. Parent fatal handling should consume the same interpretation rather than inventing a second recovery theory.

Do not introduce parallel retry, state, ownership, rollback, or recovery authorities. Extend the existing owner instead.

## 2. Data-flow model

The normal runtime pipeline is:

`package trust -> preflight -> discovery auth -> discovery -> snapshot -> analysis -> state lock -> questionnaire -> plan -> adoption -> permissions -> dry run -> explicit approval -> write auth -> workload -> read-back -> commit/rollback -> reporting`

Each stage exists to narrow uncertainty before the next stage becomes more consequential.

## 3. Graph write state machine

A write-capable request has four relevant stages:

1. **Pre-transport:** required state/journal infrastructure is initialized, write guard permits the operation, failure latch is clear, DER ID and Action ID exist.
2. **Execute checkpoint:** transaction evidence records that DER is about to enter Graph transport.
3. **Transport entered:** once `Invoke-MgGraphRequest` is invoked, a lost response can no longer be assumed to mean no write.
4. **Outcome evidence:** success/error classification is journaled, returned Object ID is captured where available, then Microsoft is reread/validated before commit.

Retry policy:

- GET: bounded transient retry is allowed.
- Write + definite 429: Retry-After may be honored.
- Write + 408/5xx/network ambiguity after transport entry: do not replay; latch and require recovery/reconciliation.
- Failure before transport entry: definite no-write; latch normal writes for the run, but do not invent tenant uncertainty.

The Microsoft.Graph SDK's own retry middleware must remain disabled so only DER owns this decision.

## 4. State lifecycle

`CurrentState.json` represents committed/proven DER knowledge, not optimistic intent.

For DER-Owned creates, Microsoft success and returned Object ID must be recorded in transaction evidence before later state persistence can fail silently.

For DER-Adopted mutation, desired state is transient preparation until Microsoft read-back validates. The committed record continues describing the old/proven Microsoft state during preparation. Commit promotes the desired expectation. Rollback restores Microsoft and state expectations together.

A missing authoritative state file with historical DER evidence is a recovery condition, not a fresh tenant.

## 5. Ownership rules

- **DER-Owned:** DER created/owns the specific Microsoft Object ID and may manage it according to state and current-run safety rules.
- **DER-Adopted:** an existing customer object was explicitly adopted with recorded original state and constrained rollback semantics.
- **Customer-Owned:** DER may discover/report/collide with it but does not automatically modify/delete it.

Never infer ownership from a name, group tag, policy description, or naming convention.

## 6. Existing-object validation

A state record is a pointer to evidence, not final truth. Before using a tracked object as an assignment target or declaring it Existing, DER should:

1. GET the exact tracked Object ID.
2. Treat genuine 404 as reconciliation required.
3. Propagate 403/429/auth/network/read failures; do not interpret them as absence.
4. Verify Microsoft identity/Object ID where applicable.
5. Verify recorded expected subset.
6. Verify required assignment.
7. Verify minimum Settings Catalog count where the workload records one.
8. Mark validation only after proof succeeds.

## 7. Failure taxonomy

### ENGINE

Use ENGINE when DER itself did not execute correctly or when provenance is unknown. Examples: missing command, parameter binding, unexpected StrictMode property error, invalid internal catalog mapping, serialization/local persistence failure, or another unclassified exception.

### ACTION

Use ACTION when DER executed the intended path and positively knows the requested tenant operation was denied, invalid, unsafe, drifted, unreconciled, or failed read-back.

**Action ID is correlation, not causation.** An engine defect can happen during an action and should appear on the action timeline while still being ENGINE.

Authored workload safety throws should use the workload failure factory. Internal “DER should know this” invariant failures must explicitly select ENGINE.

## 8. Logging model

Logs are separated by diagnostic purpose:

- `DER-LogIndex.json`: start here; exact v1/internal-build identity, classification definitions, current counters, and every focused stream path/purpose.
- `DER-Human.log`: operator progress/status.
- `DER-Technical.jsonl`: full structured event stream.
- `DER-Engine.jsonl`: engine/system timeline.
- `DER-Actions.jsonl`: all events correlated to Action IDs, including ENGINE failures that happened during an action.
- `DER-Errors.jsonl`: combined structured error stream.
- `DER-EngineErrors.jsonl`: DER/runtime/code failures only.
- `DER-ActionErrors.jsonl`: tenant/request/read-back/safety failures only.
- `DER-Errors.log`: concise human-readable combined error stream.
- `DER-Graph.jsonl`: request/response/retry/write-outcome forensic events.
- `DER-Validation.jsonl`: validation evidence.
- `DER-Rollback.jsonl`: rollback decisions/results.
- `PowerShell-Transcript.txt`: raw shell transcript fallback.

Use Run ID to join a run, Action ID to join one logical action, DER ID to join a logical managed object, Microsoft Object ID to join the actual tenant object, and Incident ID to recognize the same exception when multiple layers log it.

Never place secrets into log Data and assume redaction will rescue poor design. Redaction is a safety net, not permission to log credentials.

## 9. Rollback rules

Rollback requires positive eligibility evidence; proximity or naming similarity is not sufficient.

For current-run DER-Owned creates, rollback requires current-run creation evidence and exact Object ID.

For DER-Adopted work, rollback requires current Run ID/Action ID preparation evidence and concurrency-safe comparison against the current Microsoft state before restoration.

For DELETE validation, only genuine not-found proves deletion. Any other GET failure is unknown/failure.

Historical untouched objects are out of scope, not rollback failures.

## 10. Shared singletons

A Microsoft singleton must not receive duplicate DER ownership records just because two workload concepts touch it. Shared singleton handling must preserve one ownership authority and separate transaction identities for logically independent writes so one rollback marker cannot resolve another action accidentally.

## 11. Recovery rules

Recovery is chronological. It evaluates transaction sequence, action terminal outcomes, rollback validation, current state, transient adopted preparation, and run liveness.

Never treat a corrupt/unparseable journal line as ignorable. If DER cannot prove whether a write happened, assume recovery is required.

A rollback action with a different Action ID may resolve an earlier failure only when identity correlation is safe. Shared singleton Object IDs require DER-ID-aware correlation.

## 12. Controlled test modes

- **Windows smoke:** zero Graph authentication and zero tenant writes.
- **Tenant no-write integration:** real Graph reads under DenyAll write guard.
- **Canary:** one narrowly bounded temporary-object lifecycle.
- **Pilot:** real Groups workload for exactly one temporary object using normal state/rollback.

Each write-capable test must pass recovery gating before the write window opens.

## 13. Concurrency

The per-tenant mutex is machine-local. The state authority is workstation-local. This is intentional for v1. Operationally enforce one write-capable workstation per tenant. Do not imply distributed safety that does not exist.

## 14. Package integrity

The parent launcher anchors the package manifest hash. The package manifest protects child content. `SHA256SUMS.txt` inventories the package. Regenerate integrity metadata from the final source bytes only.

Do not edit a sealed package in place. Any source correction creates a new build package, even while the product version remains v1.

## 15. Maintainer pre-change checklist

Before modifying code, check:

- Does this add a second authority for something DER already centralizes?
- Could a read failure become “missing” and cause a duplicate create?
- Could a write be replayed after an ambiguous result?
- Could Microsoft succeed while DER loses the Object ID?
- Could state advance before Microsoft is proven to match?
- Could rollback touch an object from a prior run?
- Could rollback report success on 403/429/network failure?
- Could a shared singleton transaction resolve the wrong action?
- Could an exception be mislabeled ACTION when DER itself broke?
- Is the Action ID/DER ID/Object ID/Incident ID sufficient to reconstruct what happened?
- Does a test exercise actual behavior at the boundary being changed, or only search source text?

## 16. Before sealing a build

- Parse all JSON.
- Validate every schema-bound document.
- AST-parse all PowerShell on Windows.
- Import every advertised module and validate entry points.
- Run PSScriptAnalyzer and review diagnostics.
- Run the full pinned Pester suite.
- Scan for Graph bypasses and write calls missing DER ID.
- Verify baseline/planner ID coverage.
- Verify no empty/swallowed safety-critical catches.
- Regenerate package manifest/trust anchor/SHA256SUMS from final bytes.
- Create the ZIP.
- Extract to a clean directory.
- Validate the extracted package independently.
- Compare frozen source and extracted package byte-for-byte.
