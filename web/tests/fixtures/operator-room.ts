import { createHash } from "node:crypto";

import type { Page } from "@playwright/test";

export const operatorIncident = {
  id: "inc-e2e",
  title: "Webhook receipt race",
  scenario: "webhook-worker",
  state: "APPROVAL_PENDING",
  severity: "UNSET",
  base_sha: "b".repeat(40),
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:03:00Z",
};

export const operatorEvents = [
  {
    id: "evt-1",
    incident_id: "inc-e2e",
    sequence: 1,
    type: "TEST_FAILED",
    actor: "runner",
    created_at: "2026-07-14T00:01:00Z",
    summary: "Candidate test failed",
    details: {},
    event_hash: "1".repeat(64),
    published: true,
  },
  {
    id: "evt-2",
    incident_id: "inc-e2e",
    sequence: 2,
    type: "RETRY_STARTED",
    actor: "Inspector",
    created_at: "2026-07-14T00:02:00Z",
    summary: "Retry started",
    details: {},
    event_hash: "2".repeat(64),
    published: true,
  },
];

export const operatorCanonicalDocument = JSON.stringify({
  incident_id: "inc-e2e",
  patch_sha256: "a".repeat(64),
  base_sha: "b".repeat(40),
  allowed_paths: ["victim/src/victim/db.py"],
  execution_plans: [{ plan_id: "victim.candidate-race" }],
  expires_at: "2099-07-14T04:00:00Z",
});

export const operatorWarrant = {
  id: "war-e2e",
  incident_id: "inc-e2e",
  status: "PENDING_APPROVAL",
  warrant_sha256: createHash("sha256").update(operatorCanonicalDocument).digest("hex"),
  expires_at: "2099-07-14T04:00:00Z",
  canonical_document: operatorCanonicalDocument,
};

export const operatorSeats = [
  ["Prosecutor", "Challenges the leading incident hypothesis", "gpt-5.6-luna", "Fast rival-hypothesis pressure testing", "low"],
  ["Inspector", "Builds the evidence-backed failure mechanism", "gpt-5.6-terra", "Balanced analysis across incident evidence", "medium"],
  ["Counsel", "Proposes the smallest testable repair", "gpt-5.6-terra", "Controlled patch and test-intent synthesis", "medium"],
  ["Magistrate", "Returns the fail-closed incident verdict", "gpt-5.6-sol", "Highest scrutiny at the approval boundary", "medium"],
  ["Bailiff", "Presents one approved warrant for execution", "gpt-5.6-luna", "No reasoning; single broker tool only", "none"],
].map(([name, role, model, tier_rationale, effort]) => ({
  name,
  role,
  model,
  tier_rationale,
  effort,
  escalation_count: 0,
  state: "idle",
}));

export const operatorRoomProjection = {
  incident: operatorIncident,
  seats: operatorSeats,
  events: operatorEvents,
  specialist_summaries: [],
  warrants: [],
  artifacts: {
    evidence: [],
    diff: null,
    tests: [],
    warrant: operatorWarrant,
  },
  pending_warrant: operatorWarrant,
};

export async function installOperatorRoom(page: Page): Promise<void> {
  await page.addInitScript(() => {
    window.sessionStorage.setItem("crosspatch_access_token", "operator-access-token");
    window.sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    window.sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    window.sessionStorage.setItem("crosspatch_incident_id", "inc-e2e");
  });
  await page.route(/\/api\/incidents\/inc-e2e\/room(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(operatorRoomProjection),
    });
  });
  await page.route(/\/api\/incidents\/inc-e2e\/events\/stream(?:\?.*)?$/, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: ": connected\n\n",
    });
  });
}
