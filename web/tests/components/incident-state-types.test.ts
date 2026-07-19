import { expect, it } from "vitest";

import type { IncidentState } from "@/lib/types";

it("accepts every backend incident state while preserving compatible legacy projections", () => {
  const backendStates = [
    "OPEN",
    "REPRODUCING",
    "EVIDENCE_READY",
    "ANALYZING",
    "PATCHING",
    "REVIEWING",
    "APPROVAL_PENDING",
    "APPROVED",
    "EXECUTING",
    "TEST_FAILED",
    "VERIFIED",
    "BLOCKED",
    "HUMAN_ESCALATION",
  ] as const satisfies readonly IncidentState[];
  const compatibleProjectionStates = ["REMANDED", "ABSTAINED"] as const satisfies readonly IncidentState[];

  expect([...backendStates, ...compatibleProjectionStates]).toHaveLength(15);
});
