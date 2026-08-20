# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability or include production network
data in a report. Use GitHub's private security-advisory flow for this
repository. Include the affected version, impact, reproduction steps and a
minimal sanitized example.

## Repository data policy

The repository must not contain:

- `.env` files, passwords, API tokens, webhook URLs or secret-manager exports
- JWT or Ed25519 signing material, SSH private keys or device certificates
- approval-ledger anchors or database snapshots
- packet captures or unredacted device output
- commercial network OS images, VM disks or firmware

`.gitignore` and `.dockerignore` reduce accidental inclusion; they are not a
substitute for reviewing staged changes. Before publishing:

```bash
git status --short --ignored
git diff --cached
```

If sensitive data has entered Git history, rotate it first. Removing the file
or adding an ignore rule does not revoke the exposed credential.

## Safe defaults

- Authentication, approver MFA and strict dependency checks are enabled.
- Execution is disabled until both `EXECUTION_ENABLED=true` and an explicit
  `EXECUTION_DEVICES` allowlist are configured.
- Real device credentials should use `env:`, `file:`, `vault:` or `exec:`
  references; inline credentials are refused by default.
- Session cookies must use `COOKIE_SECURE=true` behind production TLS.
- The approval ledger needs a persistent signing key and an anchor stored
  outside PostgreSQL.

The included NetBox and fake-device credentials are local lab placeholders.
Generate new values in `.env`; never reuse them outside an isolated lab.
