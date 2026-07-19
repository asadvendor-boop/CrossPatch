import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CasesPage } from "@/components/pages/CasesPage";
import { PublicLandingPage } from "@/components/pages/PublicLandingPage";
import { PublishedCasePage } from "@/components/pages/PublishedCasePage";
import { publicCaseEnvelope, publicCaseSummary } from "../fixtures/public-cases";

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function preventNavigation(link: HTMLElement): void {
  link.addEventListener("click", (event) => event.preventDefault(), { once: true });
}

afterEach(() => vi.unstubAllGlobals());

describe("credential-free judge entry", () => {
  it("makes the strongest verified case the single dominant one-click judge entry", async () => {
    const strongestIncidentId = "inc_03d46c72ab2f4ca8943f3fa5fd83b152";
    const fetcher = vi.fn()
      .mockResolvedValueOnce(json({ cases: [
        publicCaseSummary({
          incident_id: strongestIncidentId,
          title: "Equivalent webhook retry rejected",
          scenario: "webhook-payload-equivalence",
        }),
      ] }))
      .mockResolvedValueOnce(json(publicCaseEnvelope()));
    vi.stubGlobal("fetch", fetcher);
    expect(sessionStorage.length).toBe(0);

    const landing = render(<PublicLandingPage />);
    const strongest = screen.getByRole("link", { name: "See the remanded repair" });
    await waitFor(() => expect(strongest).toHaveAttribute(
      "href", `/cases/${strongestIncidentId}`,
    ));
    expect(strongest.className).toMatch(/primaryLink/);
    expect(screen.getAllByRole("link").filter((link) => link.className.match(/primaryLink/)))
      .toHaveLength(1);
    preventNavigation(strongest);
    await userEvent.click(strongest);
    landing.unmount();

    render(<PublishedCasePage incidentId="inc-public-1" />);
    expect(await screen.findByRole("heading", { level: 1, name: "Webhook receipt race" }))
      .toBeVisible();
    expect(screen.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");
    expect(screen.getByText(/publication is the authorization boundary/i)).toBeVisible();
    expect(sessionStorage.length).toBe(0);
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([
      "/api/public/cases",
      "/api/public/cases/inc-public-1",
    ]);
    for (const [, init] of fetcher.mock.calls as Array<[string, RequestInit]>) {
      expect(new Headers(init?.headers).has("Authorization")).toBe(false);
    }
  });

  it("falls back to the first recorded case instead of linking to an absent production ID", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(json({
      cases: [publicCaseSummary({
        incident_id: "inc-replay-available",
        title: "Recorded replay case",
      })],
    }));
    vi.stubGlobal("fetch", fetcher);

    render(<PublicLandingPage />);

    const strongest = screen.getByRole("link", { name: "See the remanded repair" });
    expect(strongest).toHaveAttribute("href", "/cases");
    await waitFor(() => expect(strongest).toHaveAttribute(
      "href", "/cases/inc-replay-available",
    ));
  });
});
