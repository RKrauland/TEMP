# DER v1 Configuration and Contract Reference

This document describes the current configuration authorities shipped with DER v1. JSON documents do not support comments, so maintainers should use this reference together with the matching JSON Schema when deciding what a field means or whether it is safe to edit.

## Identity model

- **Product/public version:** `v1` until the project owner explicitly authorizes another version.
- **Package version:** `1.0.0-dev` while the package remains Development-channel.
- **Internal build number:** an integer used to bind package policies and evidence to exact source bytes without presenting a product-version increment.
- **Engine version:** `1.0.0-dev`.
- **Baseline version:** `1.0.0`.
- Package integrity is ultimately bound by `DER-PackageManifest.json`, the parent trust-anchor SHA-256, and `SHA256SUMS.txt`. Version strings are never a substitute for hashes.

## Package contracts

### `Definitions/Package/DER-UpdateManifest.json`
Authoritative runtime/package compatibility declaration. It carries package/build identity, runtime minimums, the pinned bootstrap PowerShell version/hash, dependency-lock identity, and compatible policy versions. The word "Update" is the contract name for package/runtime compatibility and does not imply a product-version increment.

### `Definitions/Package/DER-PackageManifest.json`
Generated only from frozen bytes. It inventories protected files with role, byte count, and SHA-256. Do not hand-edit it. Regenerate it after all source/document/config edits are complete.

### `Definitions/Package/DER-DependencyLock.json`
Pins the Microsoft Graph authentication dependency identity, acquisition rules, publisher requirement, and runtime content-lock expectations. Dependency convenience must never bypass this contract.

### `Definitions/Package/DER-SigningPolicy.json`
Defines Development versus Release signature posture. Development may be unsigned according to policy; Release signing remains fail-closed and explicitly trusted.

## Validation and evidence contracts

### `Definitions/Validation/DER-WindowsValidationPolicy.json`
Defines the tenant-blind Windows preflight/smoke gate: supported PowerShell, local runtime requirements, endpoint checks, Pester, PSScriptAnalyzer, required stages, and result formats. `generatedForPackage` plus `generatedForBuild` bind the policy to the exact internal v1 build.

### `Definitions/Validation/DER-SchemaBindings.json`
Maps persistent package JSON documents to their schemas and identifies runtime-only evidence schemas. The Windows smoke gate uses this catalog to validate documents against the intended schema rather than merely parsing JSON.

### Integration / Canary / Pilot policies
- `Definitions/Integration/DER-TestTenantIntegrationPolicy.json`: zero-write disposable-tenant proof contract.
- `Definitions/Canary/DER-CanaryPolicy.json`: one controlled create/read-back/delete/purge contract.
- `Definitions/Pilot/DER-PilotPolicy.json`: real Groups workload create/state/read-back/central-rollback/purge contract.

Each policy is bound to both the stable v1 package version and the internal build number. Evidence additionally carries/checks the package-manifest SHA-256 where appropriate. Evidence from another build must not be accepted merely because both builds are called v1.

## Release/freeze contract

`Definitions/Release/DER-DevFreezePolicy.json` is the authoritative v1 feature-scope and required-test-gate policy. Application deployment remains outside the v1 baseline. New tenant features remain frozen unless the project owner explicitly reopens scope.

## Baseline authorities

`Definitions/Baselines/1.0.0/` contains the baseline, immutable index, and baseline manifest. Static planner DER IDs must have exact baseline-index coverage. Generated DER-ID families are represented as explicit patterns. A baseline file hash proves immutability; planner/index coverage tests prove semantic completeness.

## Compatibility catalog

`Definitions/Compatibility/DER-CompatibilityCatalog.json` is the allow-list for Graph compatibility decisions, especially preview/beta write surfaces. A workload cannot make an allowed beta write merely by choosing a beta URL; the component must match a catalog entry and the normal central transport safety checks still apply.

## Ownership/adoption/recovery contracts

- `Definitions/Adoption/DER-AdoptionCatalog.json`: adoption-supported object types and comparison/ownership semantics.
- `Definitions/Recovery/DER-RecoveryPolicy.json`: recovery classification rules and supported evidence expectations.
- Portable state schema: defines the transferable DER state envelope; import `Merge` remains local-authoritative and `Replace` remains an explicit destructive state choice.

## Editing rules

1. Edit source/configuration only in an unsealed working tree.
2. Keep product identity at v1 unless the project owner explicitly says otherwise.
3. Increment only the internal build when creating a new sealed package from corrected source.
4. If a package-bound policy changes, keep `generatedForPackage` and `generatedForBuild` aligned with the launcher/update manifest.
5. If a JSON structure changes, update the matching schema and behavioral test at the same time.
6. Never weaken package/evidence binding just to avoid regenerating hashes.
7. Document the current contract, rationale, authority, and safety invariant directly where maintainers need it.
8. After final edits: run Windows AST/import/analyzer/Pester gates, then regenerate manifest → parent trust anchor → SHA256SUMS from final bytes.
