import { readFileSync } from "node:fs";
import path from "node:path";

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CasesPage } from "@/components/pages/CasesPage";
import { PublishedCasePage } from "@/components/pages/PublishedCasePage";
import {
  publicCaseEnvelope,
  publicPayloadEquivalenceEnvelope,
  publicCaseSummary,
  publicCaseWithWarrantEnvelope,
  publicCaseWithHypothesesEnvelope,
  sealPublicCaseEnvelope,
} from "../fixtures/public-cases";

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("public Cases gallery", () => {
  it("shows a real loading state before the public index resolves", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => undefined)));

    render(<CasesPage />);

    expect(screen.getByRole("status")).toHaveTextContent("Loading published cases");
    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
  });

  it("renders a plain-language verified badge and record-derived verdict, cost, and duration", async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      verdict_path: ["REMAND", "CLEAR"],
      recorded_cost_usd: 0.0042,
      duration_seconds: 91.4,
    })] }));
    vi.stubGlobal("fetch", fetcher);

    render(<CasesPage />);

    const card = await screen.findByTestId("published-case-card");
    expect(screen.getByTestId("published-stats-ribbon")).toHaveTextContent(
      "Verified repairs through human-governed due process",
    );
    expect(screen.getByTestId("published-stats-ribbon")).toHaveTextContent(
      "Sealed 10-run cohort, verified · 1 case explicitly published",
    );
    expect(screen.getByTestId("published-stats-ribbon")).toHaveTextContent(
      "Publication is a deliberate subset",
    );
    expect(within(card).getByRole("heading", { name: "Webhook receipt race" })).toBeVisible();
    expect(screen.getByText("Published proof / signed records")).toBeVisible();
    expect(within(card).getByTestId("published-case-status")).toHaveTextContent("Verified");
    expect(within(card).getByTestId("published-case-status")).toHaveAttribute(
      "data-recorded-state",
      "VERIFIED",
    );
    expect(within(card).getByText("webhook-race")).toBeVisible();
    const verdictPath = within(card).getByLabelText("Recorded verdict path");
    expect(within(verdictPath).getAllByTestId("verdict-step").map((step) => step.textContent))
      .toEqual(["REMAND", "CLEAR"]);
    expect(within(card).getByText("$0.0042")).toBeVisible();
    expect(within(card).getByText("1m 31s")).toBeVisible();
    expect(within(card).queryByRole("region", { name: "What happened" }))
      .not.toBeInTheDocument();
    expect(within(card).getByText("Revision 3")).toBeVisible();
    const crypto = within(card).getByText("Inspect cryptographic details").closest("details");
    expect(crypto).not.toBeNull();
    expect(within(crypto!).getByText("a".repeat(64))).toBeInTheDocument();
    expect(within(card).getByRole("link", { name: /open published case/i }))
      .toHaveAttribute("href", "/cases/inc-public-1");
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("names hostile-evidence due process only when the published C2 record is present", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      incident_id: "inc_39338e35925c4650bb16445cb3761a3d",
      title: "Poisoned webhook logs — due process held",
    })] })));

    render(<CasesPage />);

    expect(await screen.findByTestId("published-stats-ribbon")).toHaveTextContent(
      "Routine repairs through hostile-evidence due process",
    );
  });

  it("pins the two strongest genuine cases ahead of the remaining public index", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [
      publicCaseSummary({ incident_id: "inc-other", title: "Other verified repair" }),
      publicCaseSummary({
        incident_id: "inc_39338e35925c4650bb16445cb3761a3d",
        title: "Poisoned webhook logs — due process held",
      }),
      publicCaseSummary({
        incident_id: "inc_03d46c72ab2f4ca8943f3fa5fd83b152",
        title: "Equivalent webhook retry rejected",
        scenario: "webhook-payload-equivalence",
      }),
    ] })));

    render(<CasesPage />);

    const cards = await screen.findAllByTestId("published-case-card");
    expect(cards.map((card) => within(card).getByRole("heading", { level: 3 }).textContent))
      .toEqual([
        "Equivalent webhook retry rejected",
        "Poisoned webhook logs — due process held",
        "Other verified repair",
      ]);
  });

  it("keeps long scenario metadata in its own collision-safe region", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      scenario: "webhook-payload-equivalence",
    })] })));

    render(<CasesPage />);

    const scenario = await screen.findByLabelText("Scenario context");
    expect(scenario).toHaveTextContent("webhook-payload-equivalence");
    expect(scenario).toHaveTextContent("Equivalent valid JSON retries");
  });

  it("labels a closed payload-equivalence summary from native scenario metadata", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [publicCaseSummary({
      title: "Equivalent webhook retry rejected",
      scenario: "webhook-payload-equivalence",
    })] })));

    render(<CasesPage />);

    const card = await screen.findByTestId("published-case-card");
    expect(within(card).getByText("webhook-payload-equivalence")).toBeVisible();
    expect(within(card).getByText(
      "Equivalent valid JSON retries are mistaken for conflicts.",
    )).toBeVisible();
  });

  it("renders an honest empty state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [] })));

    render(<CasesPage />);

    expect(await screen.findByText("No cases have been published.")).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("No cases have been published");
    expect(screen.queryByTestId("published-case-card")).not.toBeInTheDocument();
  });

  it("does not offer an incident-opening control in recorded replay mode", async () => {
    vi.stubEnv("NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE", "1");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [] })));

    render(<CasesPage />);

    expect(await screen.findByText("No cases have been published.")).toBeVisible();
    expect(screen.queryByRole("link", { name: /open an operator incident/i }))
      .not.toBeInTheDocument();
    expect(screen.getByText("The signed replay contains no published case."))
      .toBeVisible();
  });

  it("calculates recorded cost per verified repair only from public summary records", async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ cases: [
      publicCaseSummary({ recorded_cost_usd: 0.0042 }),
      publicCaseSummary({
        incident_id: "inc-public-2",
        title: "Second verified repair",
        recorded_cost_usd: 0.0158,
      }),
    ] }));
    vi.stubGlobal("fetch", fetcher);

    render(<CasesPage />);

    const metric = await screen.findByLabelText("Recorded cost per verified repair");
    expect(within(metric).getByText("Recorded cost / verified repair")).toBeVisible();
    expect(within(metric).getByText("$0.0100")).toBeVisible();
    expect(within(metric).getByText("2 verified repairs")).toBeVisible();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("withholds the aggregate when any published repair lacks recorded spend", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ cases: [
      publicCaseSummary({ recorded_cost_usd: 0.0042 }),
      publicCaseSummary({ incident_id: "inc-public-2", recorded_cost_usd: null }),
    ] })));

    render(<CasesPage />);

    const metric = await screen.findByLabelText("Recorded cost per verified repair");
    expect(within(metric).getByText("Unavailable")).toBeVisible();
    expect(within(metric).getByText("Incomplete recorded metrics")).toBeVisible();
    expect(within(metric).queryByText(/\$\d/)).not.toBeInTheDocument();
  });

  it("fails closed visibly and retries the public index", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(json({ detail: "Published case index unavailable" }, 503))
      .mockResolvedValueOnce(json({ cases: [publicCaseSummary()] }));
    vi.stubGlobal("fetch", fetcher);

    render(<CasesPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Published case index unavailable");
    await userEvent.click(screen.getByRole("button", { name: "Retry published cases" }));
    expect(await screen.findByTestId("published-case-card")).toBeVisible();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

describe("published case detail", () => {
  it("projects every room region from the selected canonical event prefix", async () => {
    const fetcher = vi.fn().mockResolvedValue(json(publicCaseEnvelope()));
    vi.stubGlobal("fetch", fetcher);

    render(<PublishedCasePage incidentId="inc-public-1" />);

    const room = await screen.findByTestId("room-experience");
    const slider = screen.getByRole("slider", { name: "Recorded event position" });
    expect(slider).toHaveValue("8");
    expect(room).toHaveAttribute("data-story-step", "verified");

    fireEvent.change(slider, { target: { value: "4" } });
    expect(screen.getByText("Event 4 of 8")).toBeVisible();
    expect(room).toHaveAttribute("data-story-step", "approval");
    expect(screen.getByTestId("recorded-room-state")).toHaveTextContent("Approval pending");
    expect(within(screen.getByLabelText("Recorded room status")).getByText("4")).toBeVisible();

    fireEvent.change(slider, { target: { value: "8" } });
    expect(room).toHaveAttribute("data-story-step", "verified");
    expect(screen.getByTestId("recorded-room-state")).toHaveTextContent("Verified");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("renders the recorded warrant anatomy without adding a mutation request", async () => {
    const fetcher = vi.fn().mockResolvedValue(json(publicCaseWithWarrantEnvelope()));
    vi.stubGlobal("fetch", fetcher);

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("heading", { name: "Warrant anatomy" })).toBeVisible();
    expect(document.querySelector("#recorded-replay")).not.toBeNull();
    expect(document.querySelector("#warrant-anatomy")).not.toBeNull();
    expect(document.querySelector("#recorded-artifacts")).not.toBeNull();
    const lifecycle = screen.getByRole("region", { name: "Consumed authority lifecycle" });
    expect(lifecycle).toHaveTextContent("Issued");
    expect(lifecycle).toHaveTextContent("Consumed");
    expect(lifecycle).toHaveTextContent("1".repeat(64));
    await userEvent.click(screen.getByRole("button", { name: "Perturb one byte" }));
    expect(await screen.findByText("Mismatch — broker would refuse")).toBeVisible();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(String(fetcher.mock.calls[0]?.[0])).toBe("/api/public/cases/inc-public-1");
  });

  it("renders a read-only Signal replay with record-derived proof, cost, and duration", async () => {
    const fetcher = vi.fn().mockResolvedValue(json(publicCaseEnvelope()));
    vi.stubGlobal("fetch", fetcher);

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("heading", { level: 1, name: "Webhook receipt race" }))
      .toBeVisible();
    expect(screen.getByText("Published read-only case")).toBeVisible();
    expect(screen.getByText("Revision 3")).toBeVisible();
    const cryptographicDetails = screen.getByText("Inspect cryptographic details").closest("details");
    expect(cryptographicDetails).not.toBeNull();
    expect(within(cryptographicDetails!).getByText(publicCaseEnvelope().manifest_sha256))
      .toBeInTheDocument();
    expect(screen.getByTestId("record-derived-headline")).toHaveTextContent("1/2/2 failure");
    expect(screen.getByTestId("record-derived-headline")).toHaveTextContent("REMAND ×1");
    expect(screen.getByTestId("record-derived-headline")).toHaveTextContent("CLEAR");
    expect(screen.getByTestId("record-derived-headline")).toHaveTextContent("Proof pending");
    const explanation = screen.getByRole("region", { name: "What happened" });
    expect(explanation).toHaveTextContent(
      "The baseline recorded 1 receipt, 2 jobs, and 2 deliveries.",
    );
    expect(explanation).toHaveTextContent(
      "The Magistrate returned CLEAR after 1 REMAND.",
    );
    expect(explanation).not.toHaveTextContent("Trusted verification recorded");
    const facts = screen.getByLabelText("Recorded case facts");
    expect(within(facts).getByText("$0.0168")).toBeVisible();
    expect(within(facts).getByText("4m 28s")).toBeVisible();
    expect(within(facts).getByText("8 events")).toBeVisible();
    const impact = screen.getByRole("region", { name: "Recorded impact metrics" });
    expect(impact).toHaveTextContent("This published case");
    expect(impact).toHaveTextContent("Evidence to verified");
    expect(impact).toHaveTextContent("4m 15s");
    expect(impact).not.toHaveTextContent("Human-gate dwell");
    expect(screen.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");
    expect(screen.queryByRole("button", { name: /approve warrant/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /export case file/i })).not.toBeInTheDocument();
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([
      "/api/public/cases/inc-public-1",
    ]);
  });

  it("renders recorded payload-equivalence statuses and counts as public proof", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(publicPayloadEquivalenceEnvelope())));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("heading", {
      level: 1,
      name: "Equivalent webhook retry rejected",
    })).toBeVisible();
    const explanation = screen.getByRole("region", { name: "What happened" });
    expect(explanation).toHaveTextContent(
      "Trusted verification recorded HTTP 202 / 200 / 409 with 1 receipt, 1 job, and 1 delivery.",
    );
    const comparison = screen.getByRole("region", {
      name: "Retry semantics, before and after",
    });
    expect(comparison).toHaveTextContent("Affected reproduction");
    expect(comparison).toHaveTextContent("202 / 409 / 409");
    expect(comparison).toHaveTextContent("Sanitized incident evidence");
    expect(comparison).toHaveTextContent("Trusted verification");
    expect(comparison).toHaveTextContent("202 / 200 / 409");
    expect(comparison).toHaveTextContent("Post-patch sidecar oracle");
    expect(comparison).toHaveTextContent("Database oracle");
    expect(comparison).toHaveTextContent("1 receipt / 1 job / 1 delivery");
    expect(comparison).toHaveTextContent("Trusted PostgreSQL observation");
    expect(screen.getByLabelText("Recorded case facts")).toHaveTextContent("8 events");
  });

  it("renders non-default trusted proof counts directly from the recorded receipt", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(
      publicPayloadEquivalenceEnvelope(
        "victim.payload-equivalence.candidate",
        { receipts: 2, jobs: 3, deliveries: 4 },
      ),
    )));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    const facts = await screen.findByLabelText("Recorded case facts");
    expect(within(facts).getByText("2 / 3 / 4")).toBeVisible();
    expect(within(facts).queryByText("1 / 1 / 1")).not.toBeInTheDocument();
    const comparison = screen.getByRole("region", {
      name: "Retry semantics, before and after",
    });
    expect(comparison).toHaveTextContent("2 receipts / 3 jobs / 4 deliveries");
  });

  it("shows an unknown plan as neutral recorded data and omits a verified-proof sentence", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      json(publicPayloadEquivalenceEnvelope("victim.unknown.candidate")),
    ));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    const explanation = await screen.findByRole("region", { name: "What happened" });
    expect(explanation).toHaveTextContent("Recorded plan: victim.unknown.candidate.");
    expect(explanation).not.toHaveTextContent("Trusted verification recorded");
    expect(screen.queryByRole("region", { name: "Retry semantics, before and after" }))
      .not.toBeInTheDocument();
  });

  it("shows the provenance-linked rival that did not survive the recorded CLEAR", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(publicCaseWithHypothesesEnvelope())));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    const exhibit = await screen.findByRole("region", { name: "The hypothesis that died" });
    expect(exhibit).toHaveTextContent("Check then insert race");
    expect(exhibit).toHaveTextContent("Worker retry duplication");
    expect(exhibit).toHaveTextContent("victim.duplicate-race.baseline");
    expect(exhibit).toHaveTextContent("Prosecutor rival eliminated");
    expect(exhibit).toHaveTextContent("CLEAR");
    expect(exhibit).toHaveTextContent("ev-public-baseline");
    expect(within(exhibit).queryByRole("button")).not.toBeInTheDocument();
  });

  it("omits the hypothesis exhibit when the public record has no supported rival", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(publicCaseEnvelope())));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("heading", { level: 1, name: "Webhook receipt race" }))
      .toBeVisible();
    expect(screen.queryByRole("region", { name: "The hypothesis that died" }))
      .not.toBeInTheDocument();
  });

  it("keeps malformed public projections out of the room", async () => {
    const malformed = publicCaseEnvelope({
      projection: {
        ...(publicCaseEnvelope().projection as Record<string, unknown>),
        pending_warrant: { id: "must-not-be-public" },
      },
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(malformed)));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Published case failed validation");
    expect(screen.queryByTestId("room-experience")).not.toBeInTheDocument();
  });

  it("renders the policy-safe display title and never the legacy run label", async () => {
    const envelope = structuredClone(publicCaseEnvelope());
    envelope.display_title = "Duplicate order-paid delivery";
    envelope.projection.incident.title = "Genuine fresh-output release evaluation 10";
    const resealed = sealPublicCaseEnvelope(envelope);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(resealed)));

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("heading", {
      level: 1,
      name: "Duplicate order-paid delivery",
    })).toBeVisible();
    expect(screen.queryByText(/fresh-output|release evaluation/i)).not.toBeInTheDocument();
  });

  it("uses a dedicated solid Tracepaper stylesheet", () => {
    const css = readFileSync(
      path.resolve(process.cwd(), "components/pages/Cases.module.css"),
      "utf8",
    );

    expect(css).toContain("var(--trace)");
    expect(css).toContain("var(--ink-1)");
    expect(css).toContain("var(--line-strong)");
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(css).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
  });

  it("uses chartreuse only as a solid fill behind dark text", () => {
    const css = readFileSync(
      path.resolve(process.cwd(), "components/pages/Cases.module.css"),
      "utf8",
    );
    const chartreuseDeclarations = css
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.includes("var(--trace)"));

    expect(chartreuseDeclarations.length).toBeGreaterThan(0);
    for (const declaration of chartreuseDeclarations) {
      expect(declaration).toMatch(/^background(?:-color)?:\s*var\(--trace\);$/);
    }
  });

  it("shows a retryable error when the published case is unavailable", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(json({ detail: "Published case unavailable" }, 503))
      .mockResolvedValueOnce(json(publicCaseEnvelope()));
    vi.stubGlobal("fetch", fetcher);

    render(<PublishedCasePage incidentId="inc-public-1" />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Published case unavailable");
    await userEvent.click(screen.getByRole("button", { name: "Retry published case" }));
    await waitFor(() => expect(screen.getByTestId("room-experience")).toBeVisible());
  });
});
