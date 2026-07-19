import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApprovalsPage } from "@/components/pages/ApprovalsPage";
import { ArtifactsPage } from "@/components/pages/ArtifactsPage";
import { OpenIncidentPage } from "@/components/pages/OpenIncidentPage";
import { publicCaseSummary } from "../fixtures/public-cases";

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  sessionStorage.clear();
  vi.unstubAllGlobals();
});

describe("purposeful zero-credential states", () => {
  it("explains the operator and private live-trial paths before opening an incident", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary()] })));

    render(<OpenIncidentPage />);

    const guide = await screen.findByRole("region", { name: "No incident credential" });
    expect(guide).toHaveTextContent("Operators and invited live-trial judges");
    expect(within(guide).getByRole("link", { name: "Watch a published incident replay" }))
      .toHaveAttribute("href", "/cases/inc-public-1#recorded-replay");
    expect(within(guide).getByRole("link", { name: "Run a private live trial" }))
      .toHaveAttribute("href", "/open-incident#live-trial-entry");
    expect(guide).toHaveTextContent("Trials never publish");
    expect(guide).toHaveTextContent("global model-spend cap");
  });

  it("keeps approval unavailable while linking to a published warrant example", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary()] })));

    render(<ApprovalsPage />);

    const guide = await screen.findByRole("region", { name: "No incident credential" });
    expect(guide).toHaveTextContent("Approval controls remain unavailable");
    await waitFor(() => expect(
      within(guide).getByRole("link", { name: "Inspect a published warrant" }),
    ).toHaveAttribute("href", "/cases/inc-public-1#warrant-anatomy"));
    expect(screen.getByRole("button", { name: "Load approval review" })).toBeDisabled();
  });

  it("keeps exports unavailable while linking to published recorded artifacts", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary()] })));

    render(<ArtifactsPage />);

    const guide = await screen.findByRole("region", { name: "No incident credential" });
    expect(guide).toHaveTextContent("No artifact availability is inferred");
    await waitFor(() => expect(
      within(guide).getByRole("link", { name: "Inspect published recorded artifacts" }),
    ).toHaveAttribute("href", "/cases/inc-public-1#recorded-artifacts"));
    expect(screen.getByRole("button", { name: "Load incident artifacts" })).toBeDisabled();
  });

  it("falls back to the public gallery when the published index cannot be observed", async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error("public index unavailable"));
    vi.stubGlobal("fetch", fetcher);

    render(<ApprovalsPage />);

    const guide = await screen.findByRole("region", { name: "No incident credential" });
    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    expect(within(guide).getByRole("link", { name: "Inspect a published warrant" }))
      .toHaveAttribute("href", "/cases");
    expect(guide).not.toHaveTextContent(/inc-public/i);
  });
});
