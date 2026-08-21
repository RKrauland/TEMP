# DER Windows Validation Runbook

This Windows-only validation path deliberately stops before Microsoft Graph authentication. Use it before pointing a DER development package at any tenant.

## Safety boundary

The preflight and smoke-test modes do **not** call `Connect-MgGraph`, do not issue authenticated Graph requests, and do not write tenant configuration. They are workstation/package tests only.

Runtime reports are written under `C:\ProgramData\DER\IntuneBuilder` (or the existing LOCALAPPDATA fallback).

## Recommended first test — one command

Open an elevated Windows PowerShell or PowerShell window in the DER package root and run:

```powershell
.\Start-DERIntuneBuilder.ps1 -SmokeTestOnly -InstallTestDependencies
```

What that command does:

1. Finds a supported PowerShell 7 installation or offers to install the pinned Microsoft build.
2. Relaunches itself under PowerShell 7 when required.
3. Verifies the package trust-anchor/hash inventory.
4. Runs the tenant-blind Windows preflight.
5. Parses every `.ps1`, `.psm1`, and `.psd1` with the native PowerShell AST parser.
6. Parses every JSON file.
7. Validates all static JSON contracts in `DER-SchemaBindings.json` with `Test-Json -SchemaFile`.
8. Imports all parent-advertised Core/Workload modules and verifies their exported entry points without invoking those entry points.
9. Loads pinned PSScriptAnalyzer 1.24.0 and runs recursive Error/Warning analysis, writing `PSScriptAnalyzer-Results.json`. Analyzer Errors fail the smoke gate; warnings are retained as WARN evidence.
10. Loads the pinned Pester 5.9.0 test framework and runs the complete `Tests` folder.
10. Writes JSON and NUnitXml results and exits without Graph authentication.

`-InstallTestDependencies` is optional. It allows the smoke harness to save the exact PSScriptAnalyzer 1.24.0 and Pester 5.9.0 validation dependencies into DER's isolated validation cache when those exact versions are not already available. These validation dependencies are not used during a normal DER tenant run.

## Faster preflight only

For host/package/network readiness without running Pester:

```powershell
.\Start-DERIntuneBuilder.ps1 -PreflightOnly
```

This checks the supported Windows/PowerShell host, language mode, required PowerShell commands, package integrity, runtime/temp write access, free disk space, Mark-of-the-Web warning state, and HTTPS reachability to Microsoft identity and PowerShell Gallery, plus a raw TCP/TLS handshake to Microsoft Graph with no Graph HTTP/API request. It exits before Graph dependency loading or authentication.

## Standalone tools

Once already running PowerShell 7.4 or later:

```powershell
.\Tools\Invoke-DERWindowsPreflight.ps1
```

```powershell
.\Tools\Invoke-DERWindowsSmokeTest.ps1 -InstallTestDependencies
```

The standalone smoke tool also runs package integrity and preflight unless explicitly told those stages were already completed by the parent launcher.

## Expected PASS artifacts

A parent-launched validation run creates a run-specific directory under `Logs` and writes:

- `DER-PackageSelfCheck.json`
- `DER-WindowsPreflight.json`
- `SmokeTest\DER-WindowsSmokeTest.json` for smoke mode
- `SmokeTest\PSScriptAnalyzer-Results.json` for static analyzer diagnostics
- `SmokeTest\Pester-Summary.json` for smoke mode
- `SmokeTest\Pester-TestResults.xml` for smoke mode

A PASS means the local package/test contracts executed cleanly. It does **not** certify tenant permissions, licensing, Graph API behavior, or a production rollout.

## If it fails

Read the JSON report first. The failed check/stage includes the local reason and, where appropriate, a remediation hint. Do not bypass a failed package-integrity, parser, schema, or module-import stage just to reach tenant testing.

The next integration stage after a clean smoke result is a controlled disposable Microsoft test-tenant Discovery/Dry Run validation with writes still disabled.
