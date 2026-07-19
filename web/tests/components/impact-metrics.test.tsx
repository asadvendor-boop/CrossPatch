import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ImpactMetrics } from "@/components/exhibits/ImpactMetrics";

describe("record-derived impact metrics", () => {
  it("labels scope and renders every available interval plus spend by escalation", () => {
    render(<ImpactMetrics
      scope="across this published set"
      metrics={{
        caseCount: 2,
        measuredEvidenceToVerifiedCount: 2,
        medianEvidenceToVerifiedMs: 15_000,
        measuredHumanGateDwellCount: 2,
        medianHumanGateDwellMs: 6_000,
        measuredExecutionVerificationCount: 1,
        medianExecutionVerificationMs: 2_000,
        totalSpendUsd: 0.03,
        seatSpend: [
          { seat: "Inspector", effort: "medium", escalationCount: 0, costUsd: 0.01 },
          { seat: "Counsel", effort: "high", escalationCount: 1, costUsd: 0.02 },
        ],
      }}
    />);

    const panel = screen.getByRole("region", { name: "Recorded impact metrics" });
    expect(panel).toHaveTextContent("Across this published set");
    expect(panel).toHaveTextContent("Median evidence to verified");
    expect(panel).toHaveTextContent("15s");
    expect(panel).toHaveTextContent("Median human-gate dwell");
    expect(panel).toHaveTextContent("6s");
    expect(panel).toHaveTextContent("Median execution + verification");
    expect(panel).toHaveTextContent("2s");
    expect(panel).toHaveTextContent("$0.0300");
    const spend = within(panel).getByRole("list", { name: "Spend by seat and escalation" });
    expect(within(spend).getByText(/Inspector · medium · base effort/i)).toBeVisible();
    expect(within(spend).getByText(/Counsel · high · escalation 1/i)).toBeVisible();
  });

  it("omits unavailable measurements instead of rendering estimates", () => {
    render(<ImpactMetrics
      scope="this published case"
      metrics={{
        evidenceToVerifiedMs: 10_000,
        humanGateDwellMs: null,
        executionVerificationMs: null,
        totalSpendUsd: null,
        seatSpend: [],
      }}
    />);

    const panel = screen.getByRole("region", { name: "Recorded impact metrics" });
    expect(panel).toHaveTextContent("Evidence to verified");
    expect(panel).not.toHaveTextContent("Human-gate dwell");
    expect(panel).not.toHaveTextContent("Execution + verification");
    expect(panel).not.toHaveTextContent("Model spend");
  });

  it("renders sub-second recorded intervals without a misleading zero-second label", () => {
    render(<ImpactMetrics
      scope="across this published set"
      metrics={{
        caseCount: 2,
        measuredEvidenceToVerifiedCount: 0,
        medianEvidenceToVerifiedMs: null,
        measuredHumanGateDwellCount: 0,
        medianHumanGateDwellMs: null,
        measuredExecutionVerificationCount: 2,
        medianExecutionVerificationMs: 0,
        totalSpendUsd: null,
        seatSpend: [],
      }}
    />);

    const panel = screen.getByRole("region", { name: "Recorded impact metrics" });
    expect(panel).toHaveTextContent("Median execution + verification");
    expect(panel).toHaveTextContent("<1s");
    expect(panel).not.toHaveTextContent("0s");
  });
});
