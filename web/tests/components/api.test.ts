import { createHash } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  approveWarrant,
  decodeIncidentRoom,
  decodeTimelineEvent,
  fetchPublishedCase,
  fetchPublishedCases,
  getIncidentRoom,
  incidentEventsUrl,
  openIncident,
  rejectWarrant,
  requestWarrantRevision,
} from "@/lib/api";
import { DEFAULT_SEATS } from "@/lib/tokens";
import {
  canonicalFixtureWithPythonNumberVectors,
  publicCaseEnvelope,
  publicPayloadEquivalenceEnvelope,
  publicCaseSummary,
  publicCaseWithWarrantEnvelope,
  sealPublicCaseEnvelope,
} from "../fixtures/public-cases";

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const canonicalWarrant = JSON.stringify({
  incident_id: "inc-1",
  patch_sha256: "c".repeat(64),
  base_sha: "b".repeat(40),
  allowed_paths: ["victim/src/victim/db.py"],
  execution_plans: [{ plan_id: "victim.candidate-race" }],
  expires_at: "2099-07-14T04:00:00Z",
});
const canonicalWarrantHash = createHash("sha256").update(canonicalWarrant).digest("hex");

function warrantResponse(status = "PENDING_APPROVAL") {
  return {
    id: "war-1",
    incident_id: "inc-1",
    status,
    warrant_sha256: canonicalWarrantHash,
    expires_at: "2099-07-14T04:00:00Z",
    canonical_document: canonicalWarrant,
  };
}

describe("control API adapter", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("preserves published event provenance and the complete public JSON envelope", () => {
    const published = {
      id: "evt-provenance",
      incident_id: "inc-1",
      sequence: 7,
      type: "VERDICT",
      actor: "Magistrate",
      summary: "Verdict",
      details: { verdict: "REMAND", remand_target: "Counsel" },
      event_hash: "e".repeat(64),
      created_at: "2026-07-14T00:00:07Z",
      published: true,
    };

    const event = decodeTimelineEvent(published);

    expect(event.eventHash).toBe(published.event_hash);
    expect(JSON.parse(event.rawPublicJson)).toEqual(published);
  });

  it("preserves the published specialist artifact envelope behind its output hash", () => {
    const specialist = {
      kind: "INSPECTOR",
      seat: "Inspector",
      run_id: "run-inspector",
      model: "gpt-5.6-terra",
      effort: "medium",
      escalation_count: 0,
      phase: "analysis",
      output_sha256: "a".repeat(64),
      semantic_sha256: "b".repeat(64),
      created_at: "2026-07-14T00:00:05Z",
      mechanism: "The receipt check and insert are not atomic.",
      evidence_ids: ["ev-baseline"],
      falsifiers: ["A uniqueness constraint prevents the duplicate."],
    };

    const room = decodeIncidentRoom({
      incident: { id: "inc-1", title: "Receipt race", state: "ANALYZING" },
      specialist_summaries: [specialist],
      artifacts: {},
    });

    expect(room.specialistSummaries[0]?.rawPublicJson).toBe(JSON.stringify(specialist, null, 2));
  });

  it.each([
    ["ABSTAIN", "failed"],
    ["BLOCK", "failed"],
    ["REMAND", "warning"],
    ["CLEAR", "verified"],
  ] as const)("maps the %s verdict from event details to %s", (verdict, state) => {
    expect(
      decodeTimelineEvent({
        id: `evt-${verdict}`,
        sequence: 7,
        type: "VERDICT",
        actor: "Magistrate",
        summary: `Magistrate returned ${verdict}`,
        details: { verdict },
        created_at: "2026-07-14T00:00:00Z",
      }).state,
    ).toBe(state);
  });

  it.each([
    [
      "classified structured projection",
      { classification: "UNTRUSTED_EVIDENCE", text: "@@ -1 +1 @@\n-racy\n+atomic" },
    ],
    ["legacy string projection", "@@ -1 +1 @@\n-racy\n+atomic"],
  ])("decodes the %s diff as display text", (_shape, diff) => {
    const room = decodeIncidentRoom({
      incident: { id: "inc-1", title: "Receipt race", state: "PATCHING" },
      artifacts: { diff },
    });

    expect(room.artifacts.diff).toBe("@@ -1 +1 @@\n-racy\n+atomic");
  });

  it.each([
    { classification: "INTERNAL", text: "secret" },
    { classification: "UNTRUSTED_EVIDENCE", text: 42 },
    { text: "unclassified" },
  ])("rejects a malformed structured diff envelope %#", (diff) => {
    const room = decodeIncidentRoom({
      incident: { id: "inc-1", title: "Receipt race", state: "PATCHING" },
      artifacts: { diff },
    });

    expect(room.artifacts.diff).toBeNull();
  });

  it("loads the complete authoritative room projection without fabricating fallbacks", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      json({
        incident: {
          id: "inc-1",
          title: "Receipt race",
          scenario: "victim-race",
          state: "EVIDENCE_READY",
          severity: "SEV-2",
          base_sha: "b".repeat(40),
          created_at: "2026-07-14T00:00:00Z",
          updated_at: "2026-07-14T00:01:00Z",
        },
        seats: DEFAULT_SEATS.map((seat) => ({
          name: seat.name,
          role: seat.name === "Inspector" ? "Live role" : seat.role,
          model: seat.name === "Inspector" ? "untrusted-model-id" : seat.model,
          tier_rationale:
            seat.name === "Inspector" ? "Live tier rationale" : seat.tierRationale,
          effort:
            seat.name === "Inspector" ? "high" : seat.name === "Bailiff" ? "minimal" : seat.effort,
          escalation_count:
            seat.name === "Inspector" ? 1 : seat.name === "Bailiff" ? 99 : seat.escalationCount,
          state:
            seat.name === "Inspector" ? "working" : seat.name === "Bailiff" ? "spoofed" : seat.state,
        })),
        events: [
          {
            id: "evt-1",
            incident_id: "inc-1",
            sequence: 1,
            type: "EVIDENCE_READY",
            actor: "system",
            summary: "Evidence published",
            details: { evidence_count: 1, evidence_ids: ["ev-1"] },
            event_hash: "b".repeat(64),
            created_at: "2026-07-14T00:00:00Z",
            published: true,
          },
        ],
        artifacts: {
          evidence: [
            {
              classification: "UNTRUSTED_EVIDENCE",
              id: "ev-1",
              incident_id: "inc-1",
              kind: "log",
              provenance: "worker.log",
              text: "sanitized line",
              sanitized_sha256: "a".repeat(64),
              captured_at: "2026-07-14T00:00:00Z",
              tags: [],
            },
          ],
          diff: {
            classification: "UNTRUSTED_EVIDENCE",
            incident_id: "inc-1",
            candidate_id: "candidate-1",
            patch_sha256: "c".repeat(64),
            text: "@@ -1 +1 @@\n-racy\n+atomic",
            sanitized_sha256: "d".repeat(64),
            tags: [],
            created_at: "2026-07-14T00:00:01Z",
          },
          tests: [
            {
              id: "victim.candidate-race",
              label: "Candidate race",
              state: "failed",
              duration_ms: 412,
              detail: "duplicate delivery remained",
              receipt_sha256: "e".repeat(64),
            },
          ],
          warrant: null,
        },
        pending_warrant: null,
      }),
    );
    vi.stubGlobal("fetch", fetcher);

    const room = await getIncidentRoom("inc-1");

    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([
      "/api/incidents/inc-1/room",
    ]);
    expect(fetcher.mock.calls.every(([, init]) => init?.credentials === undefined)).toBe(true);
    expect(room.artifacts.evidence[0]).toMatchObject({
      classification: "UNTRUSTED_EVIDENCE",
      content: "sanitized line",
      sha256: "a".repeat(64),
    });
    expect(room.events[0]).toMatchObject({
      kind: "EVIDENCE_READY",
      details: { evidence_count: 1, evidence_ids: ["ev-1"] },
    });
    expect(room.seats).toHaveLength(5);
    expect(room.seats.find((seat) => seat.name === "Inspector")).toMatchObject({
      name: "Inspector",
      role: "Builds the evidence-backed failure mechanism",
      model: "gpt-5.6-terra",
      tierRationale: "Balanced analysis across incident evidence",
      effort: "high",
      escalationCount: 1,
      state: "working",
    });

    const bailiff = room.seats.find((seat) => seat.name === "Bailiff");
    expect(bailiff).toMatchObject({
      effort: "none",
      escalationCount: 0,
      state: "idle",
    });
    expect(room.artifacts.diff).toContain("+atomic");
    expect(room.artifacts.tests[0]).toMatchObject({
      id: "victim.candidate-race",
      state: "failed",
      durationMs: 412,
      receiptSha256: "e".repeat(64),
    });
  });

  it.each([
    ["webhook-race", "Duplicate order-paid delivery"],
    ["webhook-payload-equivalence", "Equivalent webhook retry rejected"],
  ] as const)("opens the closed %s scenario with the session bearer token", async (scenario, title) => {
    sessionStorage.setItem("crosspatch_access_token", "operator-token");
    const fetcher = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "inc-opened",
          title,
          scenario,
          state: "OPEN",
          timeline_head: null,
          pending_warrant_id: null,
        }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetcher);

    const opened = await openIncident(scenario, title);

    expect(opened).toEqual({
      id: "inc-opened",
      title,
      scenario,
      state: "OPEN",
    });
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("/api/incidents");
    expect(init.method).toBe("POST");
    expect(headers.get("Authorization")).toBe("Bearer operator-token");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(init.body).toBe(JSON.stringify({
      scenario,
      title,
      evidence_profile: "standard",
    }));
  });

  it("sends the closed instruction-log profile without changing the scenario", async () => {
    sessionStorage.setItem("crosspatch_access_token", "operator-token");
    const title = "Poisoned webhook logs — due process held";
    const fetcher = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "inc-c2",
          title,
          scenario: "webhook-race",
          state: "OPEN",
        }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetcher);

    await openIncident("webhook-race", title, "instruction-like-log");

    const [, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBe(JSON.stringify({
      scenario: "webhook-race",
      title,
      evidence_profile: "instruction-like-log",
    }));
  });

  it("preserves typed trusted receipt observations from a sealed public case", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(publicPayloadEquivalenceEnvelope())));

    const published = await fetchPublishedCase("inc-public-1");
    expect(published.snapshot.artifacts.tests[0]?.trustedObservation).toEqual({
      counts: { receipts: 1, jobs: 1, deliveries: 1 },
      responseStatuses: [202, 200, 409],
    });
    expect(published.snapshot.artifacts.tests[0]?.label)
      .toBe("victim.payload-equivalence.candidate");
  });

  it("preserves an unknown recorded plan label for neutral presentation", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      json(publicPayloadEquivalenceEnvelope("victim.unknown.candidate")),
    ));

    const published = await fetchPublishedCase("inc-public-1");

    expect(published.snapshot.artifacts.tests[0]?.label).toBe("victim.unknown.candidate");
  });

  it("uses the exact authenticated approval contract", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    const fetcher = vi.fn().mockResolvedValue(json(warrantResponse("APPROVED")));
    vi.stubGlobal("fetch", fetcher);

    const decided = await approveWarrant("war-1", canonicalWarrantHash);

    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("/api/warrants/war-1/approve");
    expect(init.method).toBe("POST");
    expect(headers.get("Authorization")).toBe("Bearer approver-token");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(headers.get("X-CrossPatch-Step-Up")).toBe("step-up-token");
    expect(init.credentials).toBeUndefined();
    expect(init.body).toBe(
      JSON.stringify({ confirmation: "APPROVE", warrant_sha256: canonicalWarrantHash }),
    );
    expect(decided).toMatchObject({ id: "war-1", approvalState: "approved" });
  });

  it("binds rejection to the exact reviewed warrant hash", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    const fetcher = vi.fn().mockResolvedValue(json(warrantResponse("REJECTED")));
    vi.stubGlobal("fetch", fetcher);

    await rejectWarrant("war-1", canonicalWarrantHash);

    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(url).toBe("/api/warrants/war-1/reject");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(headers.get("X-CrossPatch-Step-Up")).toBe("step-up-token");
    expect(init.credentials).toBeUndefined();
    expect(init.body).toBe(
      JSON.stringify({ confirmation: "REJECT", warrant_sha256: canonicalWarrantHash }),
    );
  });

  it("uses bearer-only controls for live-trial decisions and revision", async () => {
    sessionStorage.setItem("crosspatch_access_token", "live-trial-token");
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(json(warrantResponse("REJECTED")))
      .mockResolvedValueOnce(json({ id: "inc-1", state: "PATCHING" }));
    vi.stubGlobal("fetch", fetcher);

    await rejectWarrant(
      "war-1",
      canonicalWarrantHash,
      "The evidence does not justify this scope.",
      true,
    );
    await requestWarrantRevision(
      "war-1",
      canonicalWarrantHash,
      "Narrow the patch using the cited evidence.",
    );

    const rejectHeaders = new Headers((fetcher.mock.calls[0]?.[1] as RequestInit).headers);
    expect(rejectHeaders.get("Authorization")).toBe("Bearer live-trial-token");
    expect(rejectHeaders.get("X-CSRF-Token")).toBeNull();
    expect((fetcher.mock.calls[0]?.[1] as RequestInit).body).toBe(JSON.stringify({
      confirmation: "REJECT",
      warrant_sha256: canonicalWarrantHash,
      reason: "The evidence does not justify this scope.",
    }));
    expect(fetcher.mock.calls[1]?.[0]).toBe("/api/warrants/war-1/request-revision");
    expect((fetcher.mock.calls[1]?.[1] as RequestInit).body).toBe(JSON.stringify({
      confirmation: "REQUEST_REVISION",
      warrant_sha256: canonicalWarrantHash,
      comment: "Narrow the patch using the cited evidence.",
    }));
  });

  it("fails closed before an approval request when session approval credentials are absent", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    await expect(approveWarrant("war-1", "c".repeat(64))).rejects.toThrow(
      "CSRF and step-up tokens are required for approval controls",
    );
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("discovers and decodes the exact pending warrant bindings", async () => {
    const warrant = warrantResponse();
    const fetcher = vi.fn().mockResolvedValue(json({
      incident: {
        id: "inc-1",
        title: "Receipt race",
        scenario: "victim-race",
        state: "APPROVAL_PENDING",
      },
      seats: [],
      events: [],
      artifacts: { evidence: [], diff: null, tests: [], warrant },
      pending_warrant: warrant,
    }));
    vi.stubGlobal("fetch", fetcher);

    const room = await getIncidentRoom("inc-1");

    expect(room.pendingWarrant).toMatchObject({
      id: "war-1",
      warrantHash: canonicalWarrantHash,
      canonicalDocument: canonicalWarrant,
      patchHash: "c".repeat(64),
      baseSha: "b".repeat(40),
      paths: ["victim/src/victim/db.py"],
      commands: ["victim.candidate-race"],
      approvalState: "pending",
    });
  });

  it("points the browser stream at the authenticated SSE endpoint", () => {
    expect(incidentEventsUrl("inc/unsafe")).toBe(
      "/api/incidents/inc%2Funsafe/events/stream?limit=500",
    );
  });

  it("loads the public case index without attaching the tab bearer", async () => {
    sessionStorage.setItem("crosspatch_access_token", "operator-token-must-not-leak");
    const fetcher = vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary()] }));
    vi.stubGlobal("fetch", fetcher);

    const cases = await fetchPublishedCases();

    expect(cases).toEqual([{
      incidentId: "inc-public-1",
      title: "Webhook receipt race",
      state: "VERIFIED",
      scenario: "webhook-race",
      createdAt: "2026-07-14T10:50:00Z",
      updatedAt: "2026-07-14T10:54:28Z",
      revision: 3,
      manifestSha256: "a".repeat(64),
      verdictPath: ["REMAND", "CLEAR"],
      recordedCostUsd: 0.0168,
      durationSeconds: 268,
      evidenceToVerifiedSeconds: 255,
      humanGateDwellSeconds: 60,
      executionVerificationSeconds: 20,
      seatSpend: [
        {
          seat: "Inspector",
          effort: "medium",
          escalationCount: 0,
          costUsd: 0.0123,
        },
        {
          seat: "Magistrate",
          effort: "high",
          escalationCount: 1,
          costUsd: 0.0045,
        },
      ],
    }]);
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/public/cases");
    expect(new Headers(init.headers).get("Authorization")).toBeNull();
    expect(init.credentials).toBeUndefined();
  });

  it("loads one encoded public case as a forced read-only snapshot without bearer auth", async () => {
    sessionStorage.setItem("crosspatch_access_token", "operator-token-must-not-leak");
    let envelope = publicCaseEnvelope({ incident_id: "inc/public" });
    const projection = envelope.projection as Record<string, unknown>;
    projection.incident = {
      ...(projection.incident as Record<string, unknown>),
      id: "inc/public",
    };
    for (const event of projection.events as Array<Record<string, unknown>>) {
      event.incident_id = "inc/public";
    }
    for (const verdict of projection.verdicts as Array<Record<string, unknown>>) {
      verdict.incident_id = "inc/public";
    }
    envelope = sealPublicCaseEnvelope(envelope);
    const fetcher = vi.fn().mockResolvedValue(json(envelope));
    vi.stubGlobal("fetch", fetcher);

    const published = await fetchPublishedCase("inc/public");

    expect(published.incidentId).toBe("inc/public");
    expect(published.snapshot.viewerRole).toBe("read_only");
    expect(published.snapshot.pendingWarrant).toBeNull();
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/public/cases/inc%2Fpublic");
    expect(new Headers(init.headers).get("Authorization")).toBeNull();
  });

  it("validates and decodes the nonce-safe canonical public warrant anatomy", async () => {
    const envelope = publicCaseWithWarrantEnvelope();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(envelope)));

    const published = await fetchPublishedCase("inc-public-1");

    expect(published.snapshot.warrants).toHaveLength(1);
    expect(published.snapshot.warrants[0]).toMatchObject({
      warrantId: "war-public-1",
      canonicalSha256: "1".repeat(64),
      publicWarrantBytes: envelope.projection.warrants[0].public_warrant_bytes,
      publicWarrantSha256: envelope.projection.warrants[0].public_warrant_sha256,
      nonceSha256: "2".repeat(64),
      publicWarrant: {
        format: "crosspatch-public-warrant-anatomy-v1",
        approverIdentity: "approver-public-1",
        allowedPaths: ["victim/src/victim/db.py"],
        planIds: ["victim.duplicate-race.candidate"],
      },
    });
  });

  it("fails a resealed published case closed when its nested warrant anatomy hash is false", async () => {
    const envelope = structuredClone(publicCaseWithWarrantEnvelope());
    envelope.projection.warrants[0].public_warrant_sha256 = "f".repeat(64);
    const resealed = sealPublicCaseEnvelope(envelope);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(resealed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });

  it("pins the fixture to the backend canonical projection digest", () => {
    expect(publicCaseEnvelope().manifest_sha256).toBe(
      "84638146e1df84306d6c3a125e44c4196b8a3a7202d815dd083f7d5d81dff680",
    );
  });

  it("hashes backend canonical numeric lexemes without reconstructing them in JavaScript", async () => {
    let envelope = structuredClone(publicCaseEnvelope());
    const metrics = envelope.projection.events[4];
    metrics.details.canonical_number_vectors = {
      zero: 0.0,
      one: 1.0,
      negative_zero: -0.0,
      small_exponent: 1e-7,
      large_exponent: 1e20,
    };
    const canonical = canonicalFixtureWithPythonNumberVectors(envelope.projection);
    envelope = sealPublicCaseEnvelope(envelope, canonical);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(envelope)));

    const published = await fetchPublishedCase("inc-public-1");

    expect(published.incidentId).toBe("inc-public-1");
    expect(published.displayTitle).toBe("Webhook receipt race");
    expect(envelope.canonical_projection_json).toContain('"zero":0.0');
    expect(envelope.canonical_projection_json).toContain('"one":1.0');
    expect(envelope.canonical_projection_json).toContain('"negative_zero":-0.0');
    expect(envelope.canonical_projection_json).toContain('"small_exponent":1e-07');
    expect(envelope.canonical_projection_json).toContain('"large_exponent":1e+20');
  });

  it("uses the safe display title while retaining exact legacy canonical projection bytes", async () => {
    const envelope = structuredClone(publicCaseEnvelope());
    envelope.display_title = "Duplicate order-paid delivery";
    envelope.projection.incident.title = "Genuine fresh-output release evaluation 10";
    const resealed = sealPublicCaseEnvelope(envelope);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(resealed)));

    const published = await fetchPublishedCase("inc-public-1");

    expect(published.displayTitle).toBe("Duplicate order-paid delivery");
    expect(published.snapshot.incident.title).toBe("Duplicate order-paid delivery");
    expect(resealed.canonical_projection_json).toContain(
      "Genuine fresh-output release evaluation 10",
    );
  });

  it("fails the public index closed when required publication metadata is malformed", async () => {
    const malformed = publicCaseSummary({ manifest_sha256: "not-a-sha" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [malformed] })));

    await expect(fetchPublishedCases()).rejects.toThrow("Published case index failed validation");
  });

  it.each([
    ["unknown verdict", { verdict_path: ["INVENTED", "CLEAR"] }],
    ["empty verdict path", { verdict_path: [] }],
    ["non-CLEAR terminal verdict", { verdict_path: ["CLEAR", "REMAND"] }],
    ["negative recorded cost", { recorded_cost_usd: -0.01 }],
    ["string recorded cost", { recorded_cost_usd: "0.01" }],
    ["negative duration", { duration_seconds: -1 }],
    ["string duration", { duration_seconds: "2.5" }],
    ["negative evidence-to-verified", { evidence_to_verified_seconds: -1 }],
    ["unknown spend seat", { seat_spend: [{ seat: "Root", effort: "high", escalation_count: 0, cost_usd: 1 }] }],
    ["unknown spend effort", { seat_spend: [{ seat: "Inspector", effort: "ultra", escalation_count: 0, cost_usd: 1 }] }],
    ["invalid escalation count", { seat_spend: [{ seat: "Inspector", effort: "high", escalation_count: 3, cost_usd: 1 }] }],
    ["negative seat spend", { seat_spend: [{ seat: "Inspector", effort: "high", escalation_count: 0, cost_usd: -1 }] }],
  ])("fails the public index closed for %s", async (_label, overrides) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({
      cases: [publicCaseSummary(overrides)],
    })));

    await expect(fetchPublishedCases()).rejects.toThrow("Published case index failed validation");
  });

  it("preserves the backend's millisecond-precision duration", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      duration_seconds: 268.661,
    })] })));

    const [publishedCase] = await fetchPublishedCases();

    expect(publishedCase.durationSeconds).toBe(268.661);
  });

  it("preserves explicitly unavailable recorded metrics as null", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      recorded_cost_usd: null,
      duration_seconds: null,
    })] })));

    const [publishedCase] = await fetchPublishedCases();

    expect(publishedCase.recordedCostUsd).toBeNull();
    expect(publishedCase.durationSeconds).toBeNull();
  });

  it("fails a published case closed when the envelope and projection identities differ", async () => {
    const malformed = publicCaseEnvelope();
    (malformed.projection.incident as Record<string, unknown>).id = "inc-other";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });

  it("fails a published case closed when canonical and readable projections disagree", async () => {
    const malformed = publicCaseEnvelope();
    (malformed.projection.incident as Record<string, unknown>).title = "Changed after publish";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });

  it("fails a published case closed when the exact canonical bytes do not match the manifest", async () => {
    const malformed = publicCaseEnvelope();
    malformed.canonical_projection_json += " ";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });

  it("fails a published case closed when hash-matching canonical bytes are malformed JSON", async () => {
    const malformed = publicCaseEnvelope();
    malformed.canonical_projection_json = "{";
    malformed.manifest_sha256 = createHash("sha256").update("{").digest("hex");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });

  it.each([
    "noncontiguous events",
    "out-of-order events",
    "verdict/event mismatch",
    "failure after terminal CLEAR",
    "missing recorded metrics",
    "invalid recorded metrics",
  ])("fails a recomputed published case closed for %s", async (failure) => {
    let malformed = structuredClone(publicCaseEnvelope());
    const projection = malformed.projection;
    const events = projection.events as Array<Record<string, unknown>>;
    const verdicts = projection.verdicts as Array<Record<string, unknown>>;

    if (failure === "noncontiguous events") {
      events[1].sequence = 9;
    } else if (failure === "out-of-order events") {
      [events[1], events[2]] = [events[2], events[1]];
    } else if (failure === "verdict/event mismatch") {
      verdicts[0].verdict = "CLEAR";
    } else if (failure === "failure after terminal CLEAR") {
      events.splice(4, 0, {
        id: "evt-public-failed-after-clear",
        incident_id: "inc-public-1",
        sequence: 5,
        type: "TEST_FAILED",
        actor: "runner",
        summary: "Candidate failed",
        details: {},
        event_hash: "c".repeat(64),
        created_at: "2026-07-14T10:52:10Z",
        published: true,
      });
      events.forEach((event, index) => { event.sequence = index + 1; });
    } else if (failure === "missing recorded metrics") {
      for (let index = events.length - 1; index >= 0; index -= 1) {
        if (events[index].type === "MODEL_METRICS_RECORDED") events.splice(index, 1);
      }
      events.forEach((event, index) => {
        event.sequence = index + 1;
      });
    } else {
      (events[4].details as Record<string, unknown>).cost_usd = "0.0123";
    }
    malformed = sealPublicCaseEnvelope(malformed);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    await expect(fetchPublishedCase("inc-public-1")).rejects.toThrow(
      "Published case failed validation",
    );
  });
});
