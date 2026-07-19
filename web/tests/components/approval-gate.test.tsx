import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApprovalGate } from "@/components/ApprovalGate";
import type { PendingWarrant } from "@/lib/types";

const warrant: PendingWarrant = {
  id: "war-1",
  incidentId: "inc-1",
  warrantHash: "d".repeat(64),
  canonicalDocument: '{"base_sha":"bbbb","incident_id":"inc-1"}',
  patchHash: "a".repeat(64),
  baseSha: "b".repeat(40),
  paths: ["victim/src/victim/db.py"],
  commands: ["victim.candidate-race"],
  expiresAt: "2099-07-14T02:00:00Z",
  approvalState: "pending",
};

describe("ApprovalGate", () => {
  it("is disabled unless a pending warrant is present", () => {
    render(<ApprovalGate warrant={null} incidentState="ABSTAINED" />);

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "No pending warrant is available",
    );
  });

  it("fails closed with an explicit reason when the warrant has expired", () => {
    render(
      <ApprovalGate
        warrant={{ ...warrant, approvalState: "expired" }}
        incidentState="APPROVAL_PENDING"
      />,
    );

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "This warrant has expired",
    );
  });

  it("fails closed with an explicit reason for a malformed canonical binding", () => {
    render(
      <ApprovalGate
        warrant={{ ...warrant, warrantHash: "not-a-sha256" }}
        incidentState="APPROVAL_PENDING"
      />,
    );

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "The canonical warrant SHA-256 is malformed",
    );
  });

  it("fails closed with an explicit reason when the incident state cannot approve", () => {
    render(<ApprovalGate warrant={warrant} incidentState="ABSTAINED" />);

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "Incident state ABSTAINED does not permit approval",
    );
  });

  it("fails closed with an explicit reason when the warrant is no longer pending", () => {
    render(
      <ApprovalGate
        warrant={{ ...warrant, approvalState: "rejected" }}
        incidentState="APPROVAL_PENDING"
      />,
    );

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "This warrant is rejected",
    );
  });

  it("requires an explicit confirmation before approval", async () => {
    const approve = vi.fn().mockResolvedValue(undefined);
    render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
        onApprove={approve}
      />,
    );

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    await userEvent.click(
      screen.getByRole("checkbox", { name: /reviewed the exact canonical warrant/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Approve warrant" }));

    expect(approve).toHaveBeenCalledWith("war-1");
  });

  it("renders focusable exact warrant and binding review surfaces before approval", async () => {
    render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
      />,
    );

    expect(screen.getByTestId("canonical-warrant-document")).toHaveTextContent(
      warrant.canonicalDocument,
    );
    expect(screen.getByTestId("canonical-warrant-document")).toHaveAttribute(
      "data-warrant-sha256",
      warrant.warrantHash,
    );
    expect(screen.getByText(warrant.warrantHash)).toBeVisible();
    expect(screen.getByLabelText("Exact canonical warrant document")).toHaveAttribute(
      "tabindex",
      "0",
    );
    await userEvent.click(screen.getByText("Review bound paths and test plan"));
    expect(screen.getByRole("region", { name: "Bound paths and catalog test plan" })).toHaveAttribute(
      "tabindex",
      "0",
    );
  });

  it("requires the exact REJECT confirmation before rejection", async () => {
    const reject = vi.fn().mockResolvedValue(undefined);
    render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
        onReject={reject}
      />,
    );

    const confirmation = screen.getByRole("textbox", { name: "Type REJECT to confirm" });
    const button = screen.getByRole("button", { name: "Reject warrant" });
    await userEvent.type(confirmation, "not yet");
    expect(button).toBeDisabled();
    await userEvent.clear(confirmation);
    await userEvent.type(confirmation, "REJECT");
    await userEvent.click(button);

    expect(reject).toHaveBeenCalledWith("war-1", "REJECT");
  });

  it("requires live-trial reasons and supports a separately confirmed revision", async () => {
    const reject = vi.fn().mockResolvedValue(undefined);
    const revise = vi.fn().mockResolvedValue(undefined);
    render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
        liveTrial
        onReject={reject}
        onRequestRevision={revise}
      />,
    );

    const rejectConfirmation = screen.getByRole("textbox", {
      name: "Type REJECT to confirm",
    });
    const rejectionReason = screen.getByRole("textbox", { name: "Rejection reason" });
    await userEvent.type(rejectConfirmation, "REJECT");
    expect(screen.getByRole("button", { name: "Reject warrant" })).toBeDisabled();
    await userEvent.type(rejectionReason, "The evidence does not justify this scope.");
    await userEvent.click(screen.getByRole("button", { name: "Reject warrant" }));
    expect(reject).toHaveBeenCalledWith(
      "war-1",
      "The evidence does not justify this scope.",
    );

    const review = screen.getByRole("checkbox", {
      name: /reviewed the exact canonical warrant/i,
    });
    const guidance = screen.getByRole("textbox", {
      name: "Revision guidance for Counsel",
    });
    await userEvent.click(review);
    await userEvent.type(guidance, "Narrow the patch using cited evidence.");
    await userEvent.click(screen.getByRole("button", { name: "Request revision" }));
    expect(revise).toHaveBeenCalledWith(
      "war-1",
      "Narrow the patch using cited evidence.",
    );
  });

  it("invalidates all human input when any reviewed warrant byte binding changes", async () => {
    const { rerender } = render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
      />,
    );
    const checkbox = screen.getByRole("checkbox", {
      name: /reviewed the exact canonical warrant/i,
    });
    const rejection = screen.getByRole("textbox", { name: "Type REJECT to confirm" });
    await userEvent.click(checkbox);
    await userEvent.type(rejection, "REJECT");

    rerender(
      <ApprovalGate
        warrant={{
          ...warrant,
          id: "war-2",
          warrantHash: "e".repeat(64),
          canonicalDocument: '{"base_sha":"bbbb","incident_id":"inc-1","revision":2}',
        }}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
      />,
    );

    expect(screen.getByRole("checkbox", {
      name: /reviewed the exact canonical warrant/i,
    })).not.toBeChecked();
    expect(screen.getByRole("textbox", { name: "Type REJECT to confirm" })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reject warrant" })).toBeDisabled();
  });

  it("resets reviewed input after the authority state stops being actionable", async () => {
    const { rerender } = render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
      />,
    );
    await userEvent.click(
      screen.getByRole("checkbox", { name: /reviewed the exact canonical warrant/i }),
    );
    await userEvent.type(screen.getByRole("textbox", { name: "Type REJECT to confirm" }), "REJECT");

    rerender(
      <ApprovalGate warrant={warrant} incidentState="ABSTAINED" approvalCredentialsAvailable />,
    );
    rerender(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable
      />,
    );

    expect(screen.getByRole("checkbox", {
      name: /reviewed the exact canonical warrant/i,
    })).not.toBeChecked();
    expect(screen.getByRole("textbox", { name: "Type REJECT to confirm" })).toHaveValue("");
  });

  it("fails closed with a same-origin recovery path when approval credentials are absent", () => {
    render(
      <ApprovalGate
        warrant={warrant}
        incidentState="APPROVAL_PENDING"
        approvalCredentialsAvailable={false}
      />,
    );

    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "Approval credentials are unavailable in this browser tab",
    );
    expect(screen.getByRole("link", { name: "Enter approver credentials" })).toHaveAttribute(
      "href",
      "/open-incident#join-incident-title",
    );
  });
});
