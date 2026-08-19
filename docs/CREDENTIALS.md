# Credentials

Every credential Network Defender uses, what it can do, and how to change it.

The three are deliberately unequal in blast radius, and that difference is the
whole of the least-privilege story here: the threat intel key can be abused to
spend someone's quota, the API key exposes what the sensor has seen, and the
database URL is the sensor's entire memory.

## What exists

| Credential | Env var | Grants | If leaked |
|---|---|---|---|
| Threat intel API key | `ABUSEIPDB_API_KEY` | Reputation lookups on the owner's quota | Someone else spends the daily budget; enrichment degrades. No access to this system. |
| Dashboard/API key | `API_KEY` | Read every alert, packet and statistic; trigger enrichment; toggle rules | Full visibility of what the sensor has seen, which is a map of the monitored network |
| Database URL | `DATABASE_URL` | Direct read/write of every stored alert and packet | Everything above, plus the ability to delete the audit trail |

None has a default. None appears in `config/*.json` — those files are
committed, so a secret in one is a secret in the repository. They are read
only through `shared/secrets.py`, which `tests/unit/security/` enforces.

## Least privilege

**Threat intel.** Use a read-only lookup key, never an account-management
token. The provider is asked about *public* addresses only —
`services/threat_intel/eligibility.py` refuses RFC 1918 space before the
request is built, so a compromised provider learns nothing about internal
topology. Set `threat_intel.enrich_private_ips` to `true` only if you
genuinely intend to send internal addresses to a third party.

**Database.** The sensor writes; the API only reads. Give each its own
account:

```sql
-- Sensor: writes alerts and evidence, prunes what has aged out.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nd_sensor;

-- API: reads. It cannot alter the audit trail even if the process is taken.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nd_api;
GRANT UPDATE (status) ON alerts TO nd_api;  -- triage is the one write it needs
```

Neither account needs `CREATE`. Migrations are a deploy-time step run under a
third, higher-privilege account — a running process that can alter its own
schema is a running process that can be made to.

On SQLite these grants do not exist; the equivalent is filesystem
permissions, and the API should hold the database file read-only.

**API key.** There is one, and it is all-or-nothing. Anyone holding it can
read everything the sensor has recorded, so treat it as a credential for the
monitored network, not just for a dashboard. When authentication is not
configured the API is open; `/config` reports `secrets_configured` so that is
visible rather than silent.

## Rotation

Rotate on a schedule and immediately on any suspicion. Quarterly is a
reasonable default; the API key deserves shorter, because it is the one an
attacker gains most from.

Nothing caches a credential. `get_secret()` reads the environment on every
call, so a value can change without a code change — but the process
environment is fixed at start, so a rotation still means a restart of anything
already running.

**Threat intel key.** Issue the new key, set `ABUSEIPDB_API_KEY`, restart the
sensor, revoke the old key. Enrichment degrades gracefully in the gap: a
provider that fails is skipped, the circuit breaker opens, and alerts are
still raised — unenriched. Nothing is lost, so this rotation needs no window.

**API key.** Set `API_KEY`, restart the API, update the dashboard. There is no
overlap period — a single configured value means old and new cannot both be
valid — so rotate this one during a quiet period, or accept a few seconds of
401s. Failed authentication is not rate-limited, so if the key may have been
brute-forced rather than leaked, check the audit log for a burst of 401s
before assuming the rotation is sufficient.

**Database URL.** Create the new account, grant it as above, set
`DATABASE_URL`, restart both the sensor and the API, then drop the old
account. The sensor buffers nothing across a restart, so anything on the wire
during the switch is not captured — schedule it accordingly.

## After a leak

Rotating is necessary and not sufficient.

1. Revoke first, rotate second. A key that is still valid while you generate
   its replacement is a key an attacker is still using.
2. If the leak was a commit, the value is in every clone and rewriting history
   does not recall them. Treat it as public.
3. Check the audit log (`network_defender.audit`) for outbound calls you did
   not make, and the access log for reads you cannot account for.
4. If `DATABASE_URL` leaked, assume the alert history was read, and consider
   what that discloses about the monitored network — hosts, services, and
   which of them are noisy enough to have raised alerts.
