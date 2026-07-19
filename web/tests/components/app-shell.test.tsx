import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppShell } from "@/components/shell/AppShell";

const navigation = vi.hoisted(() => ({ pathname: "/incidents/inc-recorded" }));

vi.mock("next/navigation", () => ({ usePathname: () => navigation.pathname }));

afterEach(() => {
  navigation.pathname = "/incidents/inc-recorded";
  vi.unstubAllEnvs();
});

describe("persistent application shell", () => {
  it("shows the approved information architecture with one active location", () => {
    render(<AppShell><main>Room content</main></AppShell>);

    const navigation = screen.getByRole("navigation", { name: "CrossPatch workspace" });
    expect(navigation).toBeVisible();
    expect(screen.getByText("Overview")).toBeVisible();
    expect(screen.getByText("Open incident")).toBeVisible();
    expect(screen.getByText("Cases")).toBeVisible();
    expect(screen.getByText("Doctrine")).toBeVisible();
    expect(screen.getByText("Incident room")).toBeVisible();
    expect(screen.getByText("Approvals")).toBeVisible();
    expect(screen.getByText("Artifacts & exports")).toBeVisible();
    expect(screen.getByText("Incident room").closest("a")).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("href", "/overview");
    expect(screen.getByRole("link", { name: "Open incident" })).toHaveAttribute("href", "/open-incident");
    expect(screen.getByRole("link", { name: "Cases" })).toHaveAttribute("href", "/cases");
    expect(screen.getByRole("link", { name: "Doctrine" })).toHaveAttribute("href", "/doctrine");
    expect(screen.getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByRole("link", { name: "Artifacts & exports" })).toHaveAttribute("href", "/artifacts");
    expect(withinDisabledNavigation(navigation)).toEqual([]);
  });

  it("restores incident-bound destinations from this tab outside an incident pathname", async () => {
    navigation.pathname = "/overview";
    sessionStorage.setItem("crosspatch_incident_id", "inc/remembered");

    render(<AppShell><main>Overview content</main></AppShell>);

    expect(await screen.findByRole("link", { name: "Incident room" }))
      .toHaveAttribute("href", "/incidents/inc%2Fremembered");
    expect(screen.getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByRole("link", { name: "Artifacts & exports" }))
      .toHaveAttribute("href", "/artifacts");
    expect(withinDisabledNavigation(screen.getByRole("navigation", {
      name: "CrossPatch workspace",
    }))).toEqual([]);
  });

  it("fails closed on every incident-bound destination when this tab has no incident", () => {
    navigation.pathname = "/overview";

    render(<AppShell><main>Overview content</main></AppShell>);

    const workspace = screen.getByRole("navigation", { name: "CrossPatch workspace" });
    expect(withinDisabledNavigation(workspace)).toEqual([
      "Incident room",
      "Approvals",
      "Artifacts & exports",
    ]);
    expect(within(workspace).queryByRole("link", { name: "Incident room" })).not.toBeInTheDocument();
    expect(within(workspace).queryByRole("link", { name: "Approvals" })).not.toBeInTheDocument();
    expect(within(workspace).queryByRole("link", { name: "Artifacts & exports" }))
      .not.toBeInTheDocument();
    expect(within(workspace).getByRole("link", { name: "Doctrine" }))
      .toHaveAttribute("href", "/doctrine");
  });

  it("captures a direct incident pathname as the remembered tab context", async () => {
    navigation.pathname = "/incidents/inc%2Fdirect";

    render(<AppShell><main>Direct room</main></AppShell>);

    expect(screen.getByRole("link", { name: "Incident room" }))
      .toHaveAttribute("href", "/incidents/inc%2Fdirect");
    await waitFor(() => {
      expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc/direct");
    });
  });

  it("rebinds the pathname incident synchronously before approval navigation", () => {
    navigation.pathname = "/incidents/inc-current";
    render(<AppShell><main>Current room</main></AppShell>);
    sessionStorage.setItem("crosspatch_incident_id", "inc-stale");

    fireEvent.click(screen.getByRole("link", { name: "Approvals" }));

    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc-current");
  });

  it("keeps a visible publication and execution boundary status card", () => {
    render(<AppShell><main>Room content</main></AppShell>);

    const status = screen.getByTestId("shell-trust-status");
    expect(status).toHaveTextContent("Sanitized projections only");
    expect(status).toHaveTextContent("Human approval required");
    expect(status).toHaveTextContent("Sandbox execution");
  });

  it("uses a public header instead of the authenticated workspace rail on the landing page", () => {
    navigation.pathname = "/";

    render(<AppShell><main>Public landing</main></AppShell>);

    expect(screen.queryByRole("navigation", { name: "CrossPatch workspace" }))
      .not.toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "CrossPatch public" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Published cases" })).toHaveAttribute(
      "href",
      "/cases",
    );
    expect(screen.getByRole("link", { name: "Doctrine" })).toHaveAttribute(
      "href",
      "/doctrine",
    );
    expect(screen.queryByRole("link", { name: "Enter workspace" })).not.toBeInTheDocument();
  });

  it("persists a keyless recorded-replay boundary and disables every live control", () => {
    vi.stubEnv("NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE", "1");
    navigation.pathname = "/cases";

    render(<AppShell><main>Recorded case gallery</main></AppShell>);

    expect(screen.getByRole("status")).toHaveTextContent(
      "RECORDED REPLAY — signed export, no model calls",
    );
    const replayNavigation = screen.getByRole("navigation", { name: "CrossPatch recorded replay" });
    expect(within(replayNavigation).getByRole("link", { name: "Published cases" }))
      .toHaveAttribute("href", "/cases");
    expect(withinDisabledNavigation(replayNavigation)).toEqual([
      "Overview",
      "Open incident",
      "Incident room",
      "Approvals",
      "Artifacts & exports",
    ]);
    expect(screen.getByText("Recorded case gallery")).toBeVisible();
    expect(screen.getByTestId("shell-trust-status")).toHaveTextContent("Signed export verified");
    expect(screen.getByTestId("shell-trust-status")).toHaveTextContent("No mutation capability");
  });

  it("withholds route children when a live-only URL is requested in replay mode", () => {
    vi.stubEnv("NEXT_PUBLIC_CROSSPATCH_REPLAY_MODE", "1");
    navigation.pathname = "/open-incident";

    render(<AppShell><button type="button">Live mutation control</button></AppShell>);

    expect(screen.queryByRole("button", { name: "Live mutation control" })).not.toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveTextContent("Unavailable in recorded replay");
    expect(screen.getByRole("main")).toHaveTextContent("Published cases remain available");
  });
});

function withinDisabledNavigation(navigation: HTMLElement): string[] {
  return [...navigation.querySelectorAll<HTMLElement>("[aria-disabled='true']")]
    .map((item) => item.textContent?.trim() ?? "");
}
