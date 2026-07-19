# Codex collaboration dossier

CrossPatch was planned, implemented, challenged, and verified through real Codex
tasks. The privacy-minimized machine-readable index is
[`codex-sessions.json`](codex-sessions.json). It records task IDs, task lineage,
observed UTC date ranges, roles, and safe `session_meta` fingerprints. It does
not publish transcript bodies, local filesystem paths, credentials, or prompts.
Task IDs, lineage, and timestamps come directly from `session_meta`; the three
role labels are conservative classifications from each recorded task path and
bounded brief because role is not a native `session_meta` field. Independent
verification/matrix tasks are classified as adversarial review.

The public dossier deliberately excludes private build-history commit IDs. Its
two named review receipts instead bind the finding task to the exact surviving
regression-test path, test name, and current source SHA-256. This makes the
receipt independently checkable from the clean public snapshot without
publishing the archived development object database.

## Ownership and planning provenance

The owner set the product thesis, safety boundaries, exact five seats, models,
verdict vocabulary, approval semantics, evidence rules, and release gates.

The planning task was `019f5c65-f787-7e63-b523-b8f4065a7819`. It used the
curated Superpowers plugin to turn those decisions into the design and execution
plans. Those private plans are Codex planning output, not independent execution evidence,
and are intentionally absent from this public release. Current
regression tests, generated verification artifacts, the implementation task,
and the privacy-minimized dossier provide the public execution receipts.

The continuous majority-build task was
`019f5cdf-55ad-74f3-9a6c-af64f2478847`. That task integrated the repository,
owned the critical warrant/candidate boundary, reconciled parallel slices, ran
the release gates, and produced the commits judges can inspect. Focused Codex
subtasks implemented or adversarially reviewed bounded slices; their presence in
the dossier does not imply that a subtask independently owned the final commit.

## Repository-slice map

The JSON dossier is authoritative for dates and full task lineage. This table is
the human-readable index.

| Slice | Plan task | Implementation task(s) | Adversarial review task(s) |
|---|---|---|---|
| `domain-state-machine` | `019f5c65-f787-7e63-b523-b8f4065a7819` | `019f5cdf-55ad-74f3-9a6c-af64f2478847` | `019f5e6e-0d0e-7aa2-b870-27861cb65cee` |
| `hostile-evidence-sanitizer` | `019f5c9e-1d1c-73e2-8228-2c236dce5765` | `019f5cdf-55ad-74f3-9a6c-af64f2478847`, `019f5d17-7d99-7520-9686-fb54e941697e` | `019f6086-b240-7f22-9dc7-fa4dd68d2d2f` |
| `warrant-broker` | `019f5c65-f787-7e63-b523-b8f4065a7819` | `019f5cdf-55ad-74f3-9a6c-af64f2478847` | `019f5d4e-1010-7580-a06b-d53593c1c29b` |
| `candidate-isolation` | `019f5c65-f787-7e63-b523-b8f4065a7819` | `019f5cdf-55ad-74f3-9a6c-af64f2478847` | `019f5d4e-1010-7580-a06b-d53593c1c29b`, `019f5dc7-845a-7602-9a97-a6cf900e8e63` |
| `agents-sdk` | `019f5cfc-e4ae-7c41-80f1-3f03afea6cdf` | `019f5cdf-55ad-74f3-9a6c-af64f2478847`, `019f5d3d-42e6-7b22-ade6-e7cb591cf014`, `019f5dbc-bd9a-7972-8079-b9258d785749` | `019f6084-7ed4-73e1-be83-1aa00e36f847` |
| `mcp-zones` | `019f5ce1-fe00-7113-93f1-4a694f9ebce7` | `019f5cdf-55ad-74f3-9a6c-af64f2478847`, `019f5d3d-42e6-7b22-ade6-e7cb591cf014` | `019f5dd6-2066-7301-ab0b-6e0b534f0cb2` |
| `web-ui` | `019f5c65-f787-7e63-b523-b8f4065a7819` | `019f5cdf-55ad-74f3-9a6c-af64f2478847`, `019f5d3d-bd16-7b21-a7ec-8eeadff38954`, `019f5d69-b112-7492-88bf-a9649615e307` | `019f6723-50f6-7e91-8408-36e0808bbe62` |
| `release-verification` | `019f5e30-c4b4-76f2-b849-364079e312d2` | `019f5cdf-55ad-74f3-9a6c-af64f2478847` | `019f5e48-18ce-7ab3-9e5d-200af2a9b08b`, `019f6748-ef03-7913-ae8e-1191475e2324`, `019f6749-2c0c-7e22-b83c-afabf5f61c74`, `019f6749-632a-7ab0-b09f-cee5b9afedd0` |

## Named review receipts

### `warrant-status-ui`

Task `019f5d69-b112-7492-88bf-a9649615e307` found that the real API returned
`PENDING_APPROVAL` while the web fixture and decoder recognized only `pending`.
The finding became these surviving regressions:

- `web/tests/components/api.test.ts` — “discovers and decodes the exact pending
  warrant bindings.”
- `web/tests/components/incident-room.test.tsx` — “refetches the room after
  approval and displays the authoritative warrant status.”

The machine-readable receipt records each test file's current SHA-256 so a
fresh clone can verify the evidence without access to private build history.

### `candidate-exit-code-spoof`

Adversarial review task `019f5d4e-1010-7580-a06b-d53593c1c29b` demonstrated
that candidate-controlled import-time exit zero could not be treated as trusted
proof. The surviving regression
`backend/tests/security/test_candidate_spoof.py::test_import_time_zero_exit_and_forged_stdout_cannot_spoof_success`.

The named receipt binds that finding to the current regression source hash; the
trusted supervisor/oracle and production sidecar code remain directly
inspectable in this public snapshot.

## Verification and claim binding

Offline verification checks schema, slice coverage, repository paths, exact
test names, and current regression-source hashes:

```bash
uv run --frozen --extra dev python scripts/verify_codex_collaboration.py --check
```

The originating private archive retains the complete build history and local
metadata needed for owner-side provenance audits; neither is required or
published for judge installation. Every positive public release-verifier run
performs the offline check above and wraps it in the machine-generated
`artifacts/verification/codex-collaboration.json` artifact. Claim ID
`collaboration.codex-provenance` is registered against that artifact; the
release claim map includes it only after a clean verifier run regenerates all
source-bound evidence on the same release head.
