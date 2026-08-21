# Sanitized Graph fixtures

These files are **test data only**. They are intentionally synthetic and must never be copied from a customer tenant.

Rules:

- GUID-shaped values use the reserved DER test namespace beginning `00000000-0000-4000-8000-...`.
- Email/web examples use `example.invalid`.
- Public IP examples use documentation ranges such as `203.0.113.0/24` (RFC 5737).
- No access tokens, refresh tokens, passwords, client secrets, real UPNs, tenant IDs, device IDs, or customer names are permitted.
- `DER-GraphFixtureCatalog.json` is the contract tying workload modules to their mocked Graph interaction families.
- Add a fixture only when it represents a response/body shape needed by an offline test. Do not grow this into a tenant dump.
