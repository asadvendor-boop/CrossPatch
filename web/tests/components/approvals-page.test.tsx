import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApprovalsPage } from "@/components/pages/ApprovalsPage";
import { recordedRoomSnapshot } from "@/tests/fixtures/recorded-room";
import type { IncidentRoomSnapshot, PendingWarrant } from "@/lib/types";

const api = vi.hoisted(() => ({
  approveWarrant: vi.fn(),
  getIncidentRoom: vi.fn(),
  rejectWarrant: vi.fn(),
  requestWarrantRevision: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/api")>(),
  ...api,
}));

const PENDING_WARRANT: PendingWarrant = {
  id: "war-review",
  incidentId: "inc-review",
  warrantHash: "a".repeat(64),
  canonicalDocument: "{\"incident_id\":\"inc-review\",\"paths\":[\"victim/src/victim/db.py\"]}\n",
  patchHash: "b".repeat(64),
  baseSha: "c".repeat(40),
  paths: ["victim/src/victim/db.py"],
  commands: ["victim.duplicate-race.candidate"],
  expiresAt: "2099-07-15T12:00:00Z",
  approvalState: "pending",
};

function pendingSnapshot(): IncidentRoomSnapshot {
  const recorded = recordedRoomSnapshot();
  return {
    ...recorded,
    viewerRole: "approver",
    incident: {
      ...recorded.incident,
      id: "inc-review",
      title: "Webhook receipt race under review",
      state: "APPROVAL_PENDING",
    },
    artifacts: { ...recorded.artifacts, warrant: PENDING_WARRANT },
    pendingWarrant: PENDING_WARRANT,
  };
}

describe("ApprovalsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("starts with an explicit incident selection instead of implying a global queue", async () => {
    render(<ApprovalsPage />);

    expect(await screen.findByRole("heading", { name: "Select one incident" })).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Incident ID" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Load approval review" })).toBeDisabled();
    expect(await screen.findByText(/no incident is selected in this browser tab/i)).toBeVisible();
    expect(api.getIncidentRoom).not.toHaveBeenCalled();
    expect(screen.queryByText(/bulk approval/i)).not.toBeInTheDocument();
  });

  it("loads the remembered incident, preserves canonical bytes, and renders one pending gate", async () => {
    sessionStorage.setItem("crosspatch_incident_id", "inc-review");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-review");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-review");
    api.getIncidentRoom.mockResolvedValue(pendingSnapshot());

    render(<ApprovalsPage />);

    expect(await screen.findByText("Webhook receipt race under review")).toBeVisible();
    const review = screen.getByTestId("incident-approval-review");
    expect(within(review).getAllByTestId("approval-gate")).toHaveLength(1);
    expect(within(review).getByTestId("canonical-warrant-document").textContent)
      .toBe(PENDING_WARRANT.canonicalDocument);
    expect(within(review).getByRole("heading", { name: "Warrant anatomy" })).toBeVisible();
    expect(within(review).getByText("Full broker-bound SHA-256")).toBeVisible();
    expect(api.getIncidentRoom).toHaveBeenCalledWith("inc-review", expect.any(AbortSignal));
  });

  it("records a decision through the warrant binding and refreshes the same incident", async () => {
    const afterApproval = {
      ...pendingSnapshot(),
      incident: { ...pendingSnapshot().incident, state: "APPROVED" as const },
      pendingWarrant: null,
    };
    sessionStorage.setItem("crosspatch_incident_id", "inc-review");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-review");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-review");
    api.getIncidentRoom
      .mockResolvedValueOnce(pendingSnapshot())
      .mockResolvedValueOnce(afterApproval);
    api.approveWarrant.mockResolvedValue({ ...PENDING_WARRANT, approvalState: "approved" });

    render(<ApprovalsPage />);
    await screen.findByText("Webhook receipt race under review");
    await userEvent.click(screen.getByRole("checkbox", {
      name: /i reviewed the exact canonical warrant/i,
    }));
    await userEvent.click(screen.getByRole("button", { name: "Approve warrant" }));

    await waitFor(() => {
      expect(api.approveWarrant).toHaveBeenCalledWith(
        PENDING_WARRANT.id,
        PENDING_WARRANT.warrantHash,
        false,
      );
      expect(api.getIncidentRoom).toHaveBeenCalledTimes(2);
    });
    expect(await screen.findByText(/no pending warrant for this incident/i)).toBeVisible();
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc-review");
  });

  it("lets the operator replace an inaccessible remembered incident", async () => {
    sessionStorage.setItem("crosspatch_incident_id", "inc-denied");
    api.getIncidentRoom
      .mockRejectedValueOnce(new Error("Incident access denied"))
      .mockResolvedValueOnce(pendingSnapshot());

    render(<ApprovalsPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Incident access denied");
    const input = screen.getByRole("textbox", { name: "Incident ID" });
    await userEvent.clear(input);
    await userEvent.type(input, "inc-review");
    await userEvent.click(screen.getByRole("button", { name: "Load approval review" }));

    expect(await screen.findByText("Webhook receipt race under review")).toBeVisible();
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc-review");
  });
});
