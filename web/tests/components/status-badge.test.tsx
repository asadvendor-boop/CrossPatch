import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatusBadge } from "@/components/StatusBadge";

describe("StatusBadge incident tones", () => {
  it.each(["REPRODUCING", "ANALYZING", "PATCHING", "EXECUTING"] as const)(
    "shows %s as active work",
    (state) => {
      render(<StatusBadge state={state} />);
      const expected = state.charAt(0) + state.slice(1).toLowerCase();
      expect(screen.getByText(expected)).toHaveAttribute("data-tone", "active");
    },
  );

  it("shows human escalation as a warning without disguising it as success", () => {
    render(<StatusBadge state="HUMAN_ESCALATION" />);

    expect(screen.getByText("Human escalation")).toHaveAttribute("data-tone", "warning");
  });

  it("keeps locked verdict vocabulary exact while sentence-casing machine states", () => {
    const { rerender } = render(<StatusBadge state="warning" label="REMAND" />);

    expect(screen.getByText("REMAND")).toBeVisible();

    rerender(<StatusBadge state="APPROVAL_PENDING" />);
    expect(screen.getByText("Approval pending")).toBeVisible();
    expect(screen.queryByText("APPROVAL_PENDING")).not.toBeInTheDocument();
  });
});
