import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PublishedSetOverview } from "@/components/exhibits/PublishedSetOverview";
import { PublishedStatsRibbon } from "@/components/exhibits/PublishedStatsRibbon";
import { publicCaseSummary } from "../fixtures/public-cases";

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("sealed cohort and published-set reconciliation", () => {
  it("renders the exact reconciled statement without treating publication as the cohort", () => {
    render(<PublishedStatsRibbon publishedCount={3} />);

    const ribbon = screen.getByTestId("published-stats-ribbon");
    expect(ribbon).toHaveTextContent(
      "Verified repairs through human-governed due process",
    );
    expect(ribbon).toHaveTextContent(
      "Sealed 10-run cohort, verified · 3 cases explicitly published",
    );
    expect(ribbon).toHaveTextContent(
      "Publication is a deliberate subset of that cohort.",
    );
  });

  it("loads the public index once for Overview and derives scoped medians", async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ cases: [
      publicCaseSummary(),
      publicCaseSummary({
        incident_id: "inc-public-2",
        evidence_to_verified_seconds: 285,
        human_gate_dwell_seconds: 120,
        execution_verification_seconds: null,
        recorded_cost_usd: 0.0232,
      }),
    ] }));
    vi.stubGlobal("fetch", fetcher);

    render(<PublishedSetOverview />);

    const ribbon = await screen.findByTestId("published-stats-ribbon");
    expect(ribbon).toHaveTextContent(
      "Verified repairs through human-governed due process",
    );
    expect(ribbon).toHaveTextContent(
      "Sealed 10-run cohort, verified · 2 cases explicitly published",
    );
    const impact = screen.getByRole("region", { name: "Recorded impact metrics" });
    expect(impact).toHaveTextContent("Across this published set");
    expect(impact).toHaveTextContent("Median evidence to verified");
    expect(impact).toHaveTextContent("4m 30s");
    expect(impact).toHaveTextContent("Median human-gate dwell");
    expect(impact).toHaveTextContent("1m 30s");
    expect(impact).toHaveTextContent("Median execution + verification");
    expect(impact).toHaveTextContent("20s");
    expect(within(impact).getByText("$0.0400")).toBeVisible();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("reports an unavailable live count without changing the sealed statement", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    render(<PublishedSetOverview />);

    const ribbon = await screen.findByTestId("published-stats-ribbon");
    expect(ribbon).toHaveTextContent("Sealed 10-run cohort, verified");
    expect(ribbon).toHaveTextContent("Published count unavailable");
    expect(screen.queryByRole("region", { name: "Recorded impact metrics" }))
      .not.toBeInTheDocument();
  });
});
