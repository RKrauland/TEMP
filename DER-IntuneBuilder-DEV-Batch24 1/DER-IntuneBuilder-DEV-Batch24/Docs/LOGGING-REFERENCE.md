# DER v1 Logging and Failure Classification Reference

## Goal

DER logging is designed for two different troubleshooting questions that must never be confused:

1. **Did DER/PowerShell/runtime itself fail?** -> ENGINE
2. **Did DER run correctly, but the requested Microsoft/tenant action fail or become unsafe?** -> ACTION

The logs also preserve a chronological action timeline, a separate engine timeline, and deep Graph/validation/rollback forensics so an engineer can reconstruct the event without reading the source first.

## Failure taxonomy

### ACTION failure

ACTION is used only when DER positively knows that its intended code path ran and the requested tenant operation could not complete safely. Common examples:

- Microsoft Graph rejects a request.
- A required customer/DER target does not exist or cannot be safely resolved.
- A customer-owned exact-name collision requires adoption.
- Microsoft read-back does not match the expected state.
- Required assignment/settings evidence is absent.
- Drift/reconciliation conditions block a safe operation.
- Rollback identity or validation cannot be proven.
- A deliberate workload safety/precondition rule refuses the requested action.

ACTION does **not** mean the situation is harmless. `WRITE_UNCERTAIN`, unresolved rollback, or reconciliation-required conditions may be ACTION failures with serious operator follow-up.

### ENGINE failure

ENGINE means DER, PowerShell, the local runtime, or internal code did not execute correctly, or the failure origin could not be positively established as ACTION. Examples:

- command/function cannot be invoked
- parameter-binding failure
- undefined property/variable under StrictMode
- unexpected exception
- internal invariant/catalog mismatch
- JSON/serialization problem
- local state/journal/filesystem persistence failure
- logging/runtime failure
- SDK configuration failure before Graph transport

**Unclassified failures default to ENGINE.** This is intentional. DER must not blame Microsoft or tenant state when the origin is unknown.

### Action ID is not failure provenance

An ENGINE error can occur while DER is processing a specific Action ID. That event belongs on the action timeline for correlation, but its `failureKind` remains `Engine`.

This allows an engineer to say:

> Action `ABC` failed because DER itself broke at step X.

rather than incorrectly reporting:

> Microsoft rejected action `ABC`.

## Per-run files

### `DER-LogIndex.json`

Start here. This is the per-run map of DER diagnostics. It records the v1 package identity, internal build number, run ID, ENGINE/ACTION classification rules, current counts, and the purpose/path of every focused log stream. It is written when logging starts and refreshed when logging stops. It is diagnostic metadata only and is never used as tenant ownership or write-safety authority.


### `DER-Human.log`

Concise operator-readable progress, warnings, stops, and major outcomes.

### `DER-Technical.jsonl`

Complete structured event stream. This is the broadest machine-readable timeline.

### `DER-Engine.jsonl`

Engine/system events that are not inherently tenant-action events. ENGINE failures tied to an Action ID are also represented on the action timeline.

### `DER-Actions.jsonl`

All events carrying an Action ID, regardless of failure class. Use this to reconstruct one logical action from precheck through Graph/validation/commit/failure/rollback.

### `DER-Errors.jsonl`

Combined structured error stream containing both ENGINE and ACTION error events. Use when you want every structured failure in one file while retaining `failureKind`.

### `DER-EngineErrors.jsonl`

Only ENGINE failures. Start here when the script/tool/runtime itself appears broken.

### `DER-ActionErrors.jsonl`

Only ACTION failures. Start here when DER ran but Microsoft, tenant state, read-back validation, collision policy, or a safety rule prevented completion.

### `DER-Errors.log`

Human-readable combined error stream. This is convenient for rapid reading; use the structured JSONL files for detailed correlation.

### `DER-Graph.jsonl`

Graph transport/retry/write-outcome evidence. It is the first forensic source for:

- request method/path/API version
- Action ID / DER ID
- retry decision
- transport-entered status
- status code
- returned Object ID when available
- definite-no-write vs uncertain write outcome

### `DER-Validation.jsonl`

Read-back validation evidence and validation outcomes.

### `DER-Rollback.jsonl`

Rollback eligibility, decisions, write attempts, validation, and manual/recovery requirements.

### `PowerShell-Transcript.txt`

Raw PowerShell transcript. Treat this as the final fallback when structured logging itself fails or when shell-level output is needed.

## Correlation fields

Structured events may include:

- `timestamp` — local offset-aware timestamp
- `timestampUtc` — normalized UTC timestamp
- `sequence` — monotonically increasing run event sequence
- `eventId` — stable run + sequence identifier such as `RUNID:00000042`
- `runId` — one DER execution
- `actionId` — one logical action/transaction
- `derId` — DER logical object identity
- `objectId` — Microsoft object identity when applicable
- `incidentId` — one underlying exception/failure incident across multiple logging layers
- `component` — source module/component
- `eventDomain` — Engine or Action timeline domain
- `failureKind` — Engine or Action
- `engineVersion`
- `packageVersion`
- `buildNumber` — internal package build; product/public version remains v1
- `baselineVersion`
- `elapsedMs` — time since logging initialization
- `processId`
- `threadId`
- `hostName`

### Incident ID

The same exception can be observed and logged by Graph, a workload, and the parent orchestrator. DER stamps an Incident ID into exception metadata so those records can be recognized as one underlying incident.

Do not count three records with the same Incident ID as three independent failures.

## Error diagnostics

When available, structured error detail includes:

- exception type
- message
- HResult
- inner-exception chain
- exception Data entries
- PowerShell category
- FullyQualifiedErrorId
- script stack trace
- script/file name
- line number
- column/offset
- failing statement text

These fields are intended to answer **where did DER actually fail?** without relying only on a friendly summary message.

## Secret handling

Structured objects pass through DER's redaction layer before serialization. Known secret-like keys and credential/token material are suppressed.

Redaction is a safety net, not permission to log credentials. New code should avoid placing secrets into logging data at all.

## Operator triage order

When a run stops unexpectedly:

1. Preserve the entire run directory before rerunning anything.
2. Open `DER-LogIndex.json` to confirm the exact internal build, failure counts, and diagnostic stream paths.
3. Read the human summary/report to identify stage and stop reason.
4. Inspect `DER-EngineErrors.jsonl`.
   - If populated, fix/understand DER/runtime issues before blaming tenant state.
5. Inspect `DER-ActionErrors.jsonl`.
   - Look for Graph denial, drift, validation, reconciliation, or rollback evidence.
6. Use `incidentId` to group duplicate observations of the same underlying failure.
7. Use `actionId` in `DER-Actions.jsonl` to reconstruct the complete logical action.
8. Use `derId` and Microsoft `objectId` to identify the managed logical/tenant object.
9. Inspect `DER-Graph.jsonl` for transport entry, status code, retry, and write-outcome evidence.
10. Inspect `DER-Validation.jsonl` and `DER-Rollback.jsonl` when the failure happened after a write.
11. Inspect `DER-Engine.jsonl` for engine activity not tied to a tenant action.
12. Use `DER-Technical.jsonl` for the complete structured sequence.
13. Use the PowerShell transcript when structured evidence is insufficient.

## Write-uncertainty interpretation

Do not infer “no write happened” from a network/408/5xx failure after Graph transport was entered. DER intentionally classifies that situation as uncertain and refuses automatic replay.

If DER can prove transport was never entered, the failure is definite-no-write. The run still latches normal writes closed, but tenant reconciliation is not invented unnecessarily.

## Logging failure behavior

Logging and state/journal persistence are part of DER's safety system. A failure to persist safety-critical transaction/state evidence is not silently ignored. DER stops or escalates recovery rather than continuing with an incomplete forensic record.

The PowerShell transcript provides a lower-level fallback when structured logging itself cannot persist normally.

## Reporting counters

Run summaries distinguish:

- warning count
- total structured error count
- ENGINE error count
- ACTION error count
- unique Incident ID count
- unique ENGINE incident count
- unique ACTION incident count

Use incident counts when estimating distinct underlying failures; use record counts when reconstructing how many layers observed/logged them.

## Validation limitation

A logging contract can be statically reviewed, but only the Windows PowerShell/Pester gate proves that parameter binding, module scope, filesystem behavior, and the Pester logging expectations execute successfully in the supported runtime.
