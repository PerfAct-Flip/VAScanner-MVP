# Vulnerable Test Target

A deliberately misconfigured container for testing the scanner's Nuclei and
SSH-audit ("openvas") engines end-to-end with real findings — not a
demonstration of "here's what a finding looks like," an actual vulnerable
target that gets actually detected.

**Never expose this beyond an isolated local test network.** Every setting
here is intentionally weak (root SSH login, password auth, weak crypto, an
account with no password, an exposed `.git/config`).

## What it triggers

**Nuclei** (confirmed against the real templates in this repo's local
`nuclei-templates` cache):
- `git-config` (medium) — exposed `/.git/config`
- `http-missing-security-headers` (info, several matches) — no security
  headers set at all
- `ssh-sha1-hmac-algo` (info) — weak SSH MAC algorithm

**SSH audit** (`ssh_audit.py`):
- High — `PermitRootLogin yes`
- Medium — `PasswordAuthentication yes`
- Medium — weak ciphers (`3des-cbc`, `aes128-cbc`)
- Medium — weak MACs (`hmac-md5`, `hmac-sha1`, ...)
- Medium — weak key exchange (`diffie-hellman-group1-sha1`)
- Critical — an account with no password set (`nopassuser`)
- High — the scan's own account has unrestricted passwordless sudo
  (`vulnadmin`, `NOPASSWD: ALL`)
- Informational — listening ports, system banner

## Usage

```bash
docker build -t vulnerable-test-target:local .
docker run -d --name vulnerable-test-target -p 80:80 -p 2222:22 vulnerable-test-target:local
```

Port 80 (not some other port) matters — Nuclei probes a bare IP/hostname on
the default HTTP port, so this makes it reachable without any extra
configuration once Discover finds the host it's running on. Port 2222 is
used because 22 is likely already taken by the host's own real SSH server;
enter it as the credential's `port` field when creating the scan.

When creating the internal scan, add a credential:
- Type: SSH
- Username: `vulnadmin`
- Password: `vulnpass123`
- Port: `2222`

## Cleanup

```bash
docker stop vulnerable-test-target && docker rm vulnerable-test-target
```
