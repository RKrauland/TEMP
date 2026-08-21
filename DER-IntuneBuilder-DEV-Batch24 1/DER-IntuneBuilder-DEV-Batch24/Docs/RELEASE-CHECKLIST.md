# DER v1 Development / Release Checklist

## v1 feature scope

- [ ] Product version remains **v1** unless the project owner explicitly authorizes a version change.
- [ ] No new tenant feature is added while the v1 feature scope is frozen.
- [ ] Source work is limited to defect, security, compatibility, test, observability, and documentation corrections.
- [ ] Application deployment remains outside the v1 baseline scope.

## Required validation gates

- [ ] Package integrity/trust-chain validation passes from final bytes.
- [ ] Windows preflight passes.
- [ ] PowerShell AST parsing passes for every `.ps1`/`.psm1` file.
- [ ] Every advertised module imports and exposes its required entry point.
- [ ] JSON and schema-bound documents validate.
- [ ] PSScriptAnalyzer reports zero Error-severity findings. Warnings are reviewed and recorded.
- [ ] Full pinned Pester suite passes.
- [ ] Disposable-tenant no-write integration passes.
- [ ] Controlled canary passes and cleans up the exact object it created.
- [ ] Groups workload pilot passes, rollback is proven, and deleted-item cleanup is proven.
- [ ] Controlled interruption/recovery behavior is exercised and reviewed.

## If any gate fails

- [ ] Stop at that gate.
- [ ] Preserve the complete run folder.
- [ ] Classify failures using ENGINE vs ACTION evidence.
- [ ] Resolve `WRITE_UNCERTAIN` / `RECOVERY_REQUIRED` before attempting another write-capable flow.
- [ ] Correct the actual defect only; do not add unrelated tenant functionality.
- [ ] Rebuild package integrity metadata from final bytes and repeat the failed gate.

## Signed release packaging

- [ ] Signing-policy release requirements are satisfied.
- [ ] Approved certificate thumbprint is explicitly allowlisted.
- [ ] Required DER source files are Authenticode signed.
- [ ] Package manifest is regenerated after child signing.
- [ ] Parent trust-anchor hash is embedded before parent signing.
- [ ] Timestamping is configured.
- [ ] Strict package validation passes after signing.
- [ ] Release artifact is independently extracted and verified.

## Customer use

- [ ] Development-channel package is not represented as production-ready.
- [ ] One write-capable workstation per tenant is enforced operationally.
- [ ] Portable state transfer is validated against the exact tenant before use.
- [ ] Customer-Owned collisions remain untouched unless an explicit adoption workflow is completed.
