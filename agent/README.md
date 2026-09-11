# Presence Agent

Runs on a machine already inside a customer's internal network (wired or
Wi-Fi — whichever interfaces happen to be up) and executes internal scans on
the backend's behalf: it pairs once with the backend, then polls for jobs,
runs them, and reports results back.

It never accepts inbound connections — everything is outbound polling, so it
works from behind a normal firewall/NAT with no port-forwarding needed.

## What it does today

- **`discover`**: ping-sweeps (`nmap -sn`) every active local subnet to find
  live hosts, reports them back — the backend turns each into an `Asset`.
- **`nuclei`**: runs Nuclei against whatever assets the scan has (discovered
  and/or pre-seeded), reports findings back.
- **`openvas`**: *not* real OpenVAS/GVM (that would need its own scanner
  engine with network access to the targets — the same reachability problem
  this whole agent exists to solve, meaning a full GVM stack per customer
  site). Instead, this is a lightweight authenticated SSH audit: for each
  target, it tries every SSH credential attached to the scan, and on a
  successful login checks for a handful of concrete, high-signal issues —
  `PermitRootLogin`/`PasswordAuthentication` in `sshd_config`, and pending
  package updates (`apt`/`dnf`/`yum`). Not a CVE-database scanner, but real
  credentialed checks against real hosts. If no SSH credential is attached
  to the scan, this job fails immediately with a clear message instead of
  hanging.

## Requirements

- Python 3.10+
- [`nmap`](https://nmap.org/) on `PATH` (for discovery)
- [`nuclei`](https://github.com/projectdiscovery/nuclei) on `PATH` (for scanning)
- Network access to the backend's `BACKEND_URL`
- Network access to whatever host(s) you attach an SSH credential for (for
  the authenticated audit) — no extra binary needed, this uses `paramiko`

For the most accurate discovery, run as root/administrator — `nmap -sn` uses
ARP for local subnets when it can, which is faster and more reliable than the
ICMP/TCP fallback used otherwise.

## Setup (Docker — recommended for customers)

Everything (Python, nmap, nuclei) is baked into a single image — no manual dependency
installation needed.

```bash
docker build -t presence-agent:local .
```

Then open `setup.html` in a browser (just double-click it, no server needed) — fill in
the backend URL and a site name, and it generates the exact `docker run` command to use,
including the flags that matter (`--network host` so the container sees the real
network, `--cap-add` for accurate ARP-based discovery).

## Setup (without Docker)

```bash
cd agent
cp .env.example .env
# edit .env: set BACKEND_URL and a unique AGENT_NAME for this site

uv sync
uv run presence-agent
```

On first run it registers itself with the backend (`POST /agents/register`)
and saves the one-time pairing key it gets back to `STATE_PATH` (default
`~/.presence-agent/credentials.json`, `chmod 600`). **Back this file up** —
the backend only ever shows that key once; if it's lost, you register a new
identity under a different `AGENT_NAME` rather than recovering the old one.

## Creating an internal scan against this agent

1. Find this agent's id: `GET /api/v1/agents` on the backend (or read
   `agent_id` out of the saved credentials file).
2. `POST /api/v1/scans` with:
   ```json
   {
     "type": "internal",
     "agent_id": <that id>,
     "credentials": [
       {"type": "ssh", "username": "someuser", "secret": "somepassword", "port": 22}
     ]
   }
   ```
   `asset_ids` can be omitted entirely — discovery populates targets. Any
   pre-seeded `asset_ids` are scanned in addition to whatever gets discovered.
   `credentials` is only used by the `openvas` (SSH audit) engine — omit it
   (or pass `[]`) if you only want discovery + Nuclei.

## Running it as a persistent service

Any process supervisor works — e.g. a systemd unit running
`uv run --directory /path/to/agent presence-agent`, restarting on failure.
