# CrossPatch deployment runbook

This runbook separates reproducible local verification from hosted verification.
Do not claim a hosted deployment from a successful local Compose run. Hosted
acceptance requires credentials, DNS, a reachable URL, TLS, authenticated Judge
MCP readback, uptime monitoring, persistent token behavior, and GitHub license
metadata.

## Availability requirement

The hosted demo, Judge MCP endpoint, judge token, DNS, TLS certificate, database,
backups, and uptime monitor must remain operational through the inclusive service
deadline **`2026-08-13T07:00:00Z`**. That UTC time covers the end of August 12 in
Pacific time. CrossPatch defaults judge-token expiry to `2026-09-01T07:00:00Z`
for operational margin and refuses any configured expiry before the required
deadline.

Do not schedule teardown, token revocation, DNS removal, certificate expiry,
credit exhaustion, or hosting suspension before that time.

## Required authority and inputs

- A Linux host or managed container VM with Docker Engine and Compose v2.
- A public DNS name controlled by the project owner.
- Inbound TCP 80/443 to Caddy; no other service port is public.
- Persistent encrypted volumes/snapshots for PostgreSQL, generated secrets,
  sanitized/raw artifacts, and Caddy state.
- `OPENAI_API_KEY` with the required GPT-5.6 access and enough credits for the
  ten-run readiness gate plus the live demo.
- Strong random values for database/operator/session/signing configuration.
- A monitoring destination that remains active through the service deadline.

Set independent 32-byte-or-longer values for
`CROSSPATCH_EVIDENCE_MCP_SIGNING_SECRET`,
`CROSSPATCH_BROKER_MCP_SIGNING_SECRET`, and
`CROSSPATCH_JUDGE_MCP_SIGNING_SECRET`. The API and the named MCP zone receive
the same value; no MCP service receives another zone's key. The API and Broker
MCP must also share `CROSSPATCH_APPROVAL_MAC_KEY`. The read-only Evidence and
Judge MCP services receive neither the OpenAI key nor operator, approver,
victim, runner, or approval credentials. Raw and sanitized artifact roots are
fixed below the persistent `/var/lib/crosspatch/artifacts` volume.

If any hosting credential or DNS authority is unavailable, generate the canonical
`HOSTED_DEPLOYMENT_BLOCKED` artifact with `scripts/verify-hosted.sh`; never claim
hosted completion.

## Initial hosted deployment

1. Provision the host, encrypted storage, DNS record, firewall, and backup target.
2. Clone the exact public repository commit and verify its Git SHA.
3. Copy `.env.example` to `.env` and set production values. Do not commit `.env`.
4. Set `CROSSPATCH_RELEASE_MODE=1`. Every service must fail startup if a
   checked-in local default or low-entropy runtime credential remains.
   Set an independent `CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD` for bootstrap
   and independent values for `CROSSPATCH_VICTIM_APP_PASSWORD`,
   `CROSSPATCH_VICTIM_CANDIDATE_PASSWORD`, `CROSSPATCH_VICTIM_WORKER_PASSWORD`,
   `CROSSPATCH_VICTIM_ORACLE_PASSWORD`, and
   `CROSSPATCH_VICTIM_SCOPE_PASSWORD`. The running victim, candidate, worker,
   and trusted verifier receive only their named least-privilege roles; none
   receives the bootstrap credential. Also set independent
   `CROSSPATCH_API_POSTGRES_PASSWORD`, `CROSSPATCH_BROKER_POSTGRES_PASSWORD`,
   `CROSSPATCH_EVIDENCE_POSTGRES_PASSWORD`, and
   `CROSSPATCH_JUDGE_POSTGRES_PASSWORD` values for the control database roles.
5. Set `CROSSPATCH_PUBLIC_URL=https://your-host.example` and exact allowed origin.
6. Set `CROSSPATCH_JUDGE_TOKEN_EXPIRES_AT` no earlier than
   `2026-08-13T07:00:00Z`; the recommended value is `2026-09-01T07:00:00Z`.
7. Configure the DNS name in `CROSSPATCH_SITE_ADDRESS` so Caddy obtains a trusted
   certificate. The local default remains self-signed.
8. Build the pinned images, derive the exact warrant-bound identities, export
   them into the current shell, and only then start release-mode services:

   ```bash
   docker compose pull --ignore-buildable
   docker compose build --pull
   uv run --frozen --extra dev python scripts/derive_release_identity.py \
     > .env.release-identity
   set -a
   . ./.env.release-identity
   set +a
   docker compose up -d --wait
   rm -f .env.release-identity
   ```

9. Record `docker compose images --format json` and
   `python scripts/derive_release_identity.py --format json` alongside the
   deployed commit. The generator binds the Git SHA, Compose SHA-256, and all
   three local image IDs into `CROSSPATCH_ENVIRONMENT_DIGEST`; it binds the
   runner image ID into `CROSSPATCH_RUNNER_DIGEST`. Release mode rejects
   zero/development placeholders. Verify deployed image IDs match the values
   bound into every warrant.
10. Open a real incident through `scripts/setup-sample-incident.sh`; do not load a
   database fixture or authored timeline.
11. Run local verification, then hosted verification:

   ```bash
   ./scripts/verify-release.sh --strict
   CROSSPATCH_PUBLIC_URL=https://your-host.example \
   CROSSPATCH_JUDGE_TOKEN='plaintext-token-issued-once' \
   ./scripts/verify-hosted.sh
   ```

12. Read the generated artifacts and confirm their aggregate status, timestamps,
    commit, hashes, and service deadline before making a claim.

The current release supports a fresh PostgreSQL volume created from the shipped
schema. It does not claim an in-place schema upgrade from pre-schema-lock
development volumes: `create_all` is not a migration engine. Back up any older
development data, start the final judge deployment on a fresh volume, and never
describe a restart of an older schema as a verified upgrade path.

## Judge token lifecycle

Judge credentials use persistent, hashed judge token records. Plaintext is
returned only once when issued and must be delivered over a separate secure
channel. The hosted default is `CROSSPATCH_JUDGE_INCIDENT_SCOPED=0`: issue one
publication-bounded token with `crosspatch judge-token rotate`. It can list and
read every explicitly published sanitized case, while the Judge database reader
rejects all unpublished/in-flight projections. Publication occurs only for an
operator incident at terminal `VERIFIED`; live trials stay unpublished after
successful sandbox verification. Set
`CROSSPATCH_JUDGE_INCIDENT_SCOPED=1` only for an optional private mode, then issue
with `crosspatch judge-token rotate INCIDENT_ID`. The API issuer and Judge MCP
must receive the same setting. Hash, audience, issue/expiry times, JTI/replay
state, optional incident grant, revocation time, and token version remain in
PostgreSQL across restart. Secret/bootstrap and database volumes must persist.

The registered Judge bearer may establish replacement MCP sessions after a
normal disconnect, idle cleanup, lost initialize response, or service restart.
Each live session is still bound to the bearer digest, JTI, subject, and origin,
and registry revocation is checked on every request. Evidence and Broker bearer
tokens remain single-session and retain strict replay tombstones; reusable
session establishment is limited to the read-only, registry-backed Judge zone.

## Live-trial credential and global spend cap

Configure `CROSSPATCH_LIVE_TRIAL_GLOBAL_BUDGET_USD` (default `20`),
`CROSSPATCH_LIVE_TRIAL_RUN_RESERVATION_USD` (default `4`),
`CROSSPATCH_LIVE_TRIAL_REQUESTS_PER_WINDOW` (default `3`), and
`CROSSPATCH_LIVE_TRIAL_WINDOW_SECONDS` (default `3600`) on the API service.
The spend cap is one cumulative database record shared across every issued
credential; never describe it as a per-token allowance. Conservative admission
reserves spend before a run or revision and reconciles it from recorded model
metrics afterward.

Issue and revoke live-trial bearers only through the approver-authenticated API
rotation endpoints. Plaintext is returned once and only its digest persists.
The bearer can operate only its own bundled trial incidents. It cannot decide a
published/sealed/operator/foreign case, and the runner/broker topology is not
expanded. A trial stays unpublished after sandbox `VERIFIED`, so it is absent
from the shared Judge MCP view.

### Overlapping rotation

Use an overlapping rotation so access is never shortened accidentally:

1. Authenticate as an approver/operator with step-up.
2. Issue a new token with expiry at or after `2026-08-13T07:00:00Z`.
3. Store its plaintext in the intended secret manager and deliver it to judges.
4. Test an authenticated `tools/list` and `get_case_file` through public
   `/mcp/judge` using the new token.
5. Keep the previous token active during the overlap.
6. After readback and monitoring succeed, perform immediate revocation of the old
   token by ID. Do not shorten the new token or service window.
7. Verify the old token fails and the new one still succeeds; preserve the audit
   events.

On suspected theft, use immediate revocation first, issue a replacement, test it,
and notify recipients. Do not rely on container restart to revoke a credential.

## Restart and upgrade procedure

Compose uses `restart: unless-stopped` for long-running services and health-based
dependencies. Before a planned restart:

1. Stop new approvals and allow an executing warrant to finish or fail closed.
2. Run `./scripts/backup.sh` and verify the archive hash.
3. Record current Git SHA, image IDs, database migration head, token expiry, and
   public MCP readback.
4. Build/pull pinned images and inspect the rendered Compose configuration.
5. Run `docker compose up -d --wait --remove-orphans`.
6. Confirm database migrations, API health, UI, SSE, private services, victim,
   runner, and Caddy health.
7. Confirm the existing judge token remains valid after restart and its hash/ID
   has not changed.
8. Run local verification and hosted verification again.

If any readback changes unexpectedly, keep approval disabled and restore the prior
commit/images/database. Never synthesize a success event.

### Deterministic database-preservation digests

PostgreSQL 16 and later emit per-invocation `\restrict` and `\unrestrict`
guard tokens in plain-text `pg_dump` output. Those psql meta-command lines are
intentionally random, so a digest of the raw stream is not preservation
evidence. Every pre/post deployment database digest must remove all lines whose
first byte is `\` before hashing. For example:

```bash
docker compose exec -T postgres sh -lc \
  'LC_ALL=C pg_dump --data-only --inserts --no-owner --no-privileges \
  --exclude-table-data=public.api_principals \
  -U "$POSTGRES_USER" "$POSTGRES_DB"' < /dev/null \
  | sed '/^\\/d' | sha256sum
```

Use the same `sed '/^\\/d'` normalization for the full victim-database dump
and the `public.judge_tokens` table dump. Take two back-to-back normalized
post-deployment measurements and require them to match before accepting either
one. The only permitted control-database exclusion is the whole
`public.api_principals` table: it is the sole unconditional startup writer and
is deterministically provisioned from the separately hashed `.env`. Do not add
another exclusion to make a mismatch pass.

Preservation acceptance also requires an unchanged `judge_tokens` row count,
`.env` hash, canonical mount digest, Docker volume inventory and count, and
exact PostgreSQL, victim-PostgreSQL, and Caddy container identities. Never use
a raw `pg_dump` digest as preservation proof.

## TLS renewal and DNS

Caddy owns certificates, redirects HTTP to HTTPS, and redirects the `www` host to
the canonical apex in hosted mode. Persist its data/config volumes. Verify TLS
renewal is scheduled well before expiry and that the DNS A/AAAA records still point to the active host. Monitor certificate expiry,
issuer, hostname, redirect behavior, and HTTP/2 or HTTP/3 availability. A valid
local self-signed certificate does not satisfy hosted TLS acceptance.

Test renewal without deleting the live certificate or Caddy data. After any DNS
or TLS change, run `scripts/verify-hosted.sh` from an external network.

## Uptime monitor

Schedule an external uptime monitor at least every five minutes through
`2026-08-13T07:00:00Z`. It should check:

- public HTTPS health and certificate validity;
- web page rendering;
- an authenticated read-only Judge MCP request using a dedicated revocable token;
- DNS resolution from outside the host;
- alert delivery and remaining OpenAI/hosting credit.

The monitor must not call approval, broker, runner, or mutation paths. Configure
alerts to the project owner and a secondary channel. Record the monitor identifier
and active-through date in the hosted acceptance artifact; do not store its secret.

## Backup

`scripts/backup.sh` creates a timestamped bundle containing a consistent
PostgreSQL dump and approved persistent non-secret/sanitized operational data,
then writes a SHA-256 manifest authenticated with a host-held HMAC key. Raw evidence and secret material require a
separately controlled encrypted backup policy; do not copy them into a public
artifact.

Example:

```bash
install -d -m 700 /secure/crosspatch-backups
openssl rand -base64 48 > /secure/crosspatch-backup-auth.key
chmod 600 /secure/crosspatch-backup-auth.key
CROSSPATCH_BACKUP_AUTH_KEY_FILE=/secure/crosspatch-backup-auth.key \
CROSSPATCH_BACKUP_DIR=/secure/crosspatch-backups ./scripts/backup.sh
```

Requirements:

- encrypt at rest and restrict access;
- retain at least one restore point beyond the required service deadline;
- copy off-host;
- verify hashes after transfer;
- never commit backup output.
- keep `CROSSPATCH_BACKUP_AUTH_KEY_FILE` off-host in the same protected secret
  system used for restore credentials; the key is never included in the bundle;
- use the same owner-only key file for restore, and rotate it only after all
  backups signed by the prior key have passed their retention deadline.

## Restore

Test restore into an isolated Compose project before relying on a backup:

```bash
CROSSPATCH_RELEASE_MODE=0 \
COMPOSE_PROJECT_NAME=crosspatch-restore-a1b2c3d4e5f6 \
CROSSPATCH_RESTORE_PROJECT=crosspatch-restore-a1b2c3d4e5f6 \
CROSSPATCH_RESTORE_TARGET=isolated-nonproduction \
CROSSPATCH_RESTORE_CONFIRM=RESTORE \
CROSSPATCH_BACKUP_AUTH_KEY_FILE=/secure/crosspatch-backup-auth.key \
./scripts/restore.sh /secure/crosspatch-backups/crosspatch-TIMESTAMP.tar.gz
```

The restore script authenticates the manifest before parsing or import and refuses the default
project, every release-mode project, a mismatched Compose identity, or any name
outside the reserved `crosspatch-restore-<12 lowercase hex>` namespace. Create
that disposable project with fresh volumes and no public DNS before the command;
never point the restore variables at the live stack. After restore, validate event
hash chains, published projections, warrant/nonce state, token hashes/expiry,
artifact manifests, and migration head. Then perform local verification. Only
after that should DNS be moved or hosted verification run.

A restore must not reactivate revoked tokens or consumed approvals. If validation
fails, stop with approval disabled and preserve both source and failed restore for
analysis.

## Local verification

Local verification establishes source, test, policy, and one-command sandbox
behavior on the current machine:

```bash
docker compose config
docker compose build
docker compose up -d --wait
./scripts/setup-sample-incident.sh
./scripts/verify-release.sh --strict
docker compose down
```

It checks backend/security/integration contracts, UI tests/build/browser flow,
Compose policy, real webhook reproduction, broker negative controls, MCP
allowlists, exports, and claim hashes. It does not establish public reachability,
DNS, trusted TLS, uptime monitoring, hosted persistence, or GitHub metadata.

### Isolated strict release proof

`./scripts/verify-release.sh --strict` proves release-mode startup in a new,
per-run Compose project rather than reusing either the normal local project or a
hosted deployment. The verifier creates fresh disposable volumes, generates
independent high-entropy runtime and database secrets in memory, and passes them
to Compose through the child-process environment. It does not write those
secrets to `.env`, command arguments, logs, or verification artifacts.

Caddy is the only service with host bindings. For this isolated project the
verifier overrides `CROSSPATCH_BIND_ADDRESS` with `127.0.0.1` and sets
`CROSSPATCH_HTTP_PORT` plus `CROSSPATCH_HTTPS_PORT` to `0`, asking Docker to
allocate loopback-only ephemeral host ports. This lets a strict proof coexist
with the normal `80`/`443` local stack and prevents the proof services from
becoming remotely reachable. The
`CROSSPATCH_VERIFICATION_POSTGRES_PASSWORD` belongs only to the disposable
verification profile database and must not be reused for a hosted role.

Cleanup is guarded by the verifier's unique project identity: it may stop and
remove only that per-run project and its fresh volumes. It must never run a
generic `docker compose down --volumes` against the normal local or hosted
project. If identity validation fails, cleanup stops and reports the retained
project for operator inspection.

Image and export-public-key evidence is point-in-time provenance captured from
the healthy isolated stack before guarded cleanup. It binds the inspected
containers, images, immutable build context, Git SHA, release-mode public key,
and verification timestamp. It does not claim that those disposable containers
remain running afterward, and it does not establish hosted persistence or
availability.

### Supply-chain evidence

The release verifier creates five narrowly scoped machine artifacts. It runs the
SBOM and secret scan as a preflight before any Compose build, then captures image
and public-key provenance only after its isolated release-mode stack is running
and before guarded cleanup. A failed preflight prevents both the image build and
the provenance stage:

- `artifacts/verification/sbom.cdx.json` is a deterministic CycloneDX 1.5 SBOM
  covering every non-editable Python package in `uv.lock` and every npm package
  version in `package-lock.json`. It binds both lockfiles by SHA-256.
- `artifacts/verification/build-context-secret-scan.json` records the exact
  `.dockerignore`-included file manifest and fails on high-confidence credential
  formats or high-entropy secret assignments. Findings contain only a hash of
  the detected value, never the value itself.
- `artifacts/verification/immutable-build.json` records the SHA-256 of one
  deterministic tar snapshot whose file manifest must equal the passed secret
  scan. Strict release supplies those same immutable bytes to all three local
  image builds and labels each image with both hashes.
- `artifacts/verification/image-provenance.json` is strict-mode readback from
  `docker inspect` and `docker image inspect`. It binds every deployed Compose
  service to its container ID, exact `sha256:` image ID, available registry
  digests, state, Compose-file hash, Git SHA, and the exact passed build-context
  manifest/tar SHA-256 labels read from every local image. It also repeats the
  secret scan after the build, binds the immutable-build artifact by SHA-256,
  and rejects any context drift before reading Docker state. A locally built
  image can honestly have no repository digest; its image ID and both context
  labels remain mandatory.
- `artifacts/verification/export-public-key.json` contains the raw Ed25519 public
  key in base64, its SHA-256 fingerprint, Git SHA, and a verified signature over
  a fixed public challenge read back from the running API container. It never
  reads, contains, or hashes the private seed on the host.

Generate the offline artifacts directly when needed:

```bash
uv run --frozen --extra dev python scripts/generate_sbom.py
uv run --frozen --extra dev python scripts/scan_build_context.py
```

The secret scanner permits a provider-shaped test value only under an explicit
`tests/fixtures/` tree and only when its source line carries
`# secret-scan: allow=test-fixture`. The generated artifact records the file,
line, rule, reason, and value hash. The same marker anywhere else is ignored;
never annotate an operational credential or use the marker to bypass a finding.

Strict verification never builds local images from the mutable workspace. It
creates one deterministic tar snapshot after the preflight, checks that its
manifest is identical, streams the same tar bytes to the app, runner, and web
Docker builds, and embeds the manifest and tar hashes as image labels. After the
Compose stack starts, readback requires those exact labels on every local image.

It then asks the running `api` service to return only its Ed25519
public key plus a signature over a fixed public challenge. The host verifies
that signature before publishing the key. This proof requires the running API to
be in release mode, so a development-placeholder key cannot produce a PASS. The
private seed remains inside the runtime process boundary and is never printed,
passed on a command line, or copied into release evidence. A failed preflight,
failed Compose stage, context drift, unhealthy deployment, or invalid runtime
proof overwrites prior evidence with `BLOCKED`/`FAIL` instead of accepting stale
output.

Distribute `export-public-key.json` independently from case archives and pin its
`public_key_sha256`. Preserve the prior public-key artifact when rotating the
private seed so previously exported cases remain verifiable, generate and
distribute the replacement before using the new seed, and never publish or copy
the private seed into verification artifacts.

### Published export-verification keys

The web release adds two immutable public proofs and one provenance manifest:

- `/verification/production-export-public-key.json` verifies exports produced by
  the hosted production signing identity. Pin fingerprint
  `9fc05d3c32c1b276a3e59f699ad73b8f9f332cc608ece3c8f5fd2cb2b665bc7d`.
  Its bytes come from the machine-generated running-API runtime proof at
  `artifacts/verification/operator-session-20260717T074450Z/production-export-public-key.json`.
- `/verification/sealed-cohort-export-public-key.json` preserves verification of
  the historical paced cohort. Pin fingerprint
  `949bed254068654a5d5c125079c4631055709fafcac92e097b02a08cd87f9875`.
  Its bytes remain identical to the sealed cohort proof; that artifact is never
  rewritten during release.
- `/verification/export-public-keys.json` binds both URLs to their source
  artifact SHA-256, runtime Git SHA, public-key fingerprint, and proof status.

`scripts/publish_export_public_keys.py` verifies each Ed25519 challenge
signature before copying the public proof bytes. This additive distribution does
not rotate a signing secret, does not replace `artifacts/verification/export-public-key.json`,
and never publishes a private seed. Choose the key by recorded archive lineage;
do not guess a key or accept a key solely because the archive download succeeded.

These artifacts prove only the inspected source and Compose deployment. A local
SBOM, secret scan, immutable build, image readback, or public key **does not establish hosted**
reachability, TLS, persistence, monitoring, or Judge MCP acceptance; those remain
independently `BLOCKED` until `scripts/verify-hosted.sh` verifies them.

## Hosted verification

Hosted verification is external and credentialed:

```bash
CROSSPATCH_PUBLIC_URL=https://your-host.example \
CROSSPATCH_JUDGE_TOKEN='issued-judge-token' \
CROSSPATCH_UPTIME_MONITOR_ID='provider-monitor-id' \
CROSSPATCH_UPTIME_MONITOR_ACTIVE_THROUGH=2026-09-01T07:00:00Z \
CROSSPATCH_GITHUB_ABOUT_VISUAL_EVIDENCE=/secure/evidence/github-about-visual.json \
./scripts/verify-hosted.sh --capture-operational \
  --compose-project crosspatch \
  --output artifacts/verification/hosted-acceptance.json
```

The verifier checks public health, reachable URL, DNS, TLS, authenticated Judge
MCP, actively proves that direct ports 8000/8011/8012/8013 are unreachable,
checks token persistence across a controlled restart, uptime monitor metadata,
deadline, backup/restore evidence, authenticated GitHub API license readback,
and a separate authenticated-browser screenshot proving the About panel visibly
shows MIT. The four operational artifacts are accepted only when captured and
SHA-bound by that same verifier process. External JSON is never operational
proof, even when it matches the exact
`crosspatch.hosted-evidence.v1` check schema, deployment URL, Git SHA, freshness,
check-specific observations, checked-in executable generator, and generator
action; a generic `machine_generated: true` assertion is rejected. A missing
credential, DNS record, reachable URL, monitor, visual artifact, or
owner-authorized restart produces `BLOCKED`, never `VERIFIED`.

The capture reads restart policy and health from live container inspection,
authenticates the same Judge bearer before and after a controlled Caddy/Judge
MCP restart, validates the running Caddy command/storage and observes live
certificate-maintenance activity plus the served certificate, and restores an
authenticated backup into a randomly named disposable Compose project before
comparing database snapshots. The restore project is removed with its volumes.
Any missing observation, failed restart, failed cleanup, snapshot mismatch, or
untrusted TLS result is `BLOCKED`; no partial capture is accepted. The
`--allow-insecure-localhost` option exists only to prove the mechanism against
the local Caddy CA and is rejected for non-loopback hostnames; never use it for
hosted acceptance.

The strict local verifier runs PostgreSQL checks through the one-shot
`verification` Compose profile and its own disposable `verification-postgres`
database. That pinned PostgreSQL 16 service uses a `tmpfs`, has no published or
exposed port, uses dedicated local-only verifier credentials, and joins only the
internal `verification` network. `postgres-verifier` runs the event-store and
broker concurrency checks; `victim-postgres-verifier` runs the real race
reproduction. Neither verifier joins a production data network, receives a
production database credential, or can persist verification data after the
profile is removed.

## Rollback

CrossPatch does not automatically deploy or merge a proposed patch. For an
application-stack release rollback, stop approvals, pin the previous verified Git
SHA/image set, restore only if the database migration is incompatible, start with
health waits, validate hash chains and token state, and repeat both verification
layers. Preserve the failed release artifacts and logs as untrusted evidence.

## Teardown after the judging window

Only after `2026-08-13T07:00:00Z` and confirmation that judging no longer needs
access: export final machine-generated evidence, revoke judge/operator tokens,
take and verify the final encrypted backup, remove DNS, stop the stack, destroy
secrets, and document the teardown timestamp. Keep the public repository/private
judge-sharing state consistent with the submission rules.
