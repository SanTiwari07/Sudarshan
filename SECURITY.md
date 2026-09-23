# Security Policy

SUDARSHAN is a cybersecurity research and security platform. Due to the nature of dynamic analysis and malware execution, strict safety expectations apply.

## Reporting a Vulnerability

If you discover a vulnerability in the platform or sandbox containment:

1. **Do not disclose sensitive vulnerabilities publicly** before coordination.
2. Use GitHub's private vulnerability reporting mechanism to submit a report directly to the repository maintainers.
3. Wait for an acknowledgment before discussing the vulnerability on public trackers.

## Development and Testing Rules

- **Never commit credentials.** All credentials must be managed via `.env`.
- **Never commit private APKs or sensitive banking data.** Use `tests/apks/` as a local-only staging area or utilize the dedicated baselines repository.
- **Sandbox Safety:** The dynamic analysis engine executes untrusted code. Maintain the intended network isolation and execution boundaries.
- **Responsible Testing:** Ensure that you have authorization before testing the platform against live services.

## Scope

Security issues relating to:
- Authentication and RBAC bypass
- Sandbox escapes or containment failure
- Evidence tampering or log spoofing
- Prompt injection against the AI Investigation Engine
- Deterministic Risk Engine evasion

are considered in scope for security reports.
