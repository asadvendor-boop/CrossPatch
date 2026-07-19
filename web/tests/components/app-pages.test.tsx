import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ApprovalsRoute from "@/app/approvals/page";
import ArtifactsRoute from "@/app/artifacts/page";
import CasesRoute from "@/app/cases/page";
import DoctrineRoute from "@/app/doctrine/page";
import HomeRoute from "@/app/page";
import OpenIncidentRoute from "@/app/open-incident/page";
import OverviewRoute from "@/app/overview/page";
import { DEFAULT_SEATS } from "@/lib/tokens";

const webRoot = path.resolve(import.meta.dirname, "../..");

const requiredRouteFiles = [
  "app/overview/page.tsx",
  "app/open-incident/page.tsx",
  "app/cases/page.tsx",
  "app/doctrine/page.tsx",
  "app/approvals/page.tsx",
  "app/artifacts/page.tsx",
] as const;

describe("whole-app route surfaces", () => {
  it("ships every capture-ready application route", () => {
    const missing = requiredRouteFiles.filter((file) => !existsSync(path.join(webRoot, file)));

    expect(missing).toEqual([]);
  });

  it("hands the public root to the dedicated landing surface", () => {
    const source = readFileSync(path.join(webRoot, "app/page.tsx"), "utf8");

    expect(source).toContain("PublicLandingPage");
    expect(source).not.toContain("IncidentOpenForm");
    expect(source).not.toContain("IncidentAccessForm");
  });

  it.each([
    ["landing", HomeRoute],
    ["overview", OverviewRoute],
    ["open-incident", OpenIncidentRoute],
    ["cases", CasesRoute],
    ["doctrine", DoctrineRoute],
    ["approvals", ApprovalsRoute],
    ["artifacts", ArtifactsRoute],
  ] as const)("renders one accessible page title on %s", (page, Route) => {
    const { container } = render(<Route />);

    expect(container.querySelector("main")).toHaveAttribute("id", "main-content");
    expect(container.querySelector("main")).toHaveAttribute("data-page", page);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(container.querySelectorAll("svg").length).toBeGreaterThan(0);
  });

  it("makes the public landing a visual proof story with two honest entry points", () => {
    render(<HomeRoute />);

    expect(screen.getByRole("heading", {
      level: 1,
      name: "The evidence was tampered with. The release gate held.",
    }))
      .toBeVisible();
    expect(screen.getByText(
      /an instruction hidden inside a signed incident log was denied authority while the legitimate repair still moved through clear.*human approval.*verified/i,
    )).toBeVisible();
    expect(screen.getByText("CrossPatch is a due-process layer for agent-proposed changes."))
      .toBeVisible();
    expect(screen.getByText(/for SRE and platform teams who won't trust autonomous agents in production/i))
      .toBeVisible();
    expect(screen.getByRole("link", { name: "Enter the control plane" }))
      .toHaveAttribute("href", "/overview");
    expect(screen.getByRole("link", { name: "Open a real incident" }))
      .toHaveAttribute("href", "/open-incident");
    expect(screen.getByRole("link", { name: "Run a live incident yourself" }))
      .toHaveAttribute("href", "/open-incident#live-trial-entry");
    expect(screen.getByText(/fresh model output.*global spend cap.*you approve the warrant/i))
      .toBeVisible();
    expect(screen.getAllByTestId("landing-seat")).toHaveLength(5);
    expect(screen.getByText("Evidence → challenge → approval → verified repair")).toBeVisible();
  });

  it("shows the sealed cohort, exact five seats, and six bounded steps on Overview", () => {
    render(<OverviewRoute />);

    expect(screen.getByText(/agent remediation is unauditable, so humans can't safely delegate/i))
      .toBeVisible();
    const metrics = screen.getByLabelText("Verified cohort summary");
    expect(within(metrics).getByText("10 genuine cases")).toBeVisible();
    expect(within(metrics).getByText("10 human-approved")).toBeVisible();
    expect(within(metrics).getByText("10 verified repairs")).toBeVisible();
    const seatCards = within(screen.getByRole("list", { name: "Five model-driven seats" }))
      .getAllByRole("listitem");
    expect(seatCards).toHaveLength(5);
    expect(seatCards.map((card) => card.dataset.seatTone))
      .toEqual(["mint", "cyan", "violet", "amber", "blue"]);
    for (const card of seatCards) expect(card.querySelector("svg")).not.toBeNull();
    for (const [index, seat] of DEFAULT_SEATS.entries()) {
      expect(within(seatCards[index]).getByText(seat.model, { exact: true })).toBeVisible();
    }
    expect(within(screen.getByLabelText("Repair control flow")).getAllByRole("listitem"))
      .toHaveLength(6);
  });

  it("marks Overview figures as one immutable sealed-cohort statement", async () => {
    const overviewModule = await import("@/components/pages/OverviewPage") as {
      IMMUTABLE_SEALED_COHORT_STATEMENT?: {
        cohortGitSha: string;
        genuineCases: number;
        humanApproved: number;
        verifiedRepairs: number;
      };
    };
    const statement = overviewModule.IMMUTABLE_SEALED_COHORT_STATEMENT;

    expect(statement).toEqual({
      cohortGitSha: "8a19ef1115bc1d665665a972f94d7c708a9dcbf5",
      genuineCases: 10,
      humanApproved: 10,
      verifiedRepairs: 10,
    });
    expect(Object.isFrozen(statement)).toBe(true);

    const source = readFileSync(
      path.join(webRoot, "components/pages/OverviewPage.tsx"),
      "utf8",
    );
    expect(source).toContain("IMMUTABLE_SEALED_COHORT_STATEMENT");
    expect(source).not.toContain("<strong>10 / 10</strong>");
    expect(source).not.toContain("<strong>10 genuine cases</strong>");
    expect(source).not.toContain("<strong>10 human-approved</strong>");
    expect(source).not.toContain("<strong>10 verified repairs</strong>");
  });

  it("never ellipsizes exact model identifiers in the seat strip", () => {
    const css = readFileSync(path.join(webRoot, "components/pages/AppPages.module.css"), "utf8");
    const modelRule = css.match(/\.seatModel\s*\{([\s\S]*?)\}/)?.[1] ?? "";

    expect(modelRule).toContain("overflow-wrap: anywhere");
    expect(modelRule).toContain("white-space: normal");
    expect(modelRule).not.toMatch(/overflow:\s*hidden|text-overflow|white-space:\s*nowrap/);
  });

  it("keeps opening and joining real incidents together with tab-scoped credential guidance", () => {
    render(<OpenIncidentRoute />);

    expect(screen.getByRole("heading", { level: 1, name: "Start a real incident or rejoin one." }))
      .toBeVisible();
    expect(screen.getByRole("button", { name: "Open webhook-race incident" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Open incident room" })).toBeDisabled();
    expect(screen.getByText(/credentials remain in this browser tab/i)).toBeVisible();
    expect(screen.getByText(/csrf and step-up credentials unlock approval controls only/i))
      .toBeVisible();
    expect(screen.getByRole("heading", { level: 2, name: "Open either bundled scenario" }))
      .toBeVisible();
    expect(screen.getByText("Operators can open either bundled scenario.")).toBeVisible();
    expect(screen.getByText("Invited live-trial judges can open webhook-race only.")).toBeVisible();
  });

  it.each([
    [ApprovalsRoute, "Approval review", "Load approval review"],
    [ArtifactsRoute, "Artifacts & exports", "Load incident artifacts"],
  ] as const)("renders %s as an incident-bound production surface", (Route, title, action) => {
    render(<Route />);

    expect(screen.getByRole("heading", { level: 1, name: title })).toBeVisible();
    expect(screen.getByRole("button", { name: action })).toBeDisabled();
    expect(screen.queryByText(/phase 2 preview/i)).not.toBeInTheDocument();
  });

  it("removes preview scaffolding without deleting the persona monogram fallback", () => {
    const primitives = readFileSync(path.join(webRoot, "components/pages/PagePrimitives.tsx"), "utf8");
    const css = readFileSync(path.join(webRoot, "components/pages/AppPages.module.css"), "utf8");
    const portrait = readFileSync(path.join(webRoot, "components/PersonaPortrait.tsx"), "utf8");

    expect(primitives).not.toMatch(/preview\??:/);
    expect(primitives).not.toContain("Phase 2 preview");
    expect(css).not.toMatch(/\.preview[A-Z]/);
    expect(css).not.toMatch(/\.(?:emptyCanvas|anatomyCard|fieldAnatomy|artifactAnatomy)/);
    expect(portrait).toContain("persona-portrait--placeholder");
    expect(portrait).toContain("portrait placeholder");
  });

  it("styles every surface through semantic theme variables without literal colors", () => {
    const cssPath = path.join(webRoot, "components/pages/AppPages.module.css");
    expect(existsSync(cssPath)).toBe(true);
    if (!existsSync(cssPath)) return;
    const css = readFileSync(cssPath, "utf8");

    for (const token of ["--ink-1", "--text", "--muted", "--accent", "--line", "--radius-card"]) {
      expect(css).toContain(`var(${token})`);
    }
    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(css).not.toMatch(/\b(?:rgb|rgba|hsl|hsla)\(/i);
    expect(css).not.toMatch(/:\s*(?:black|white|red|green|blue|gray|grey|transparent)\b/i);
  });
});
