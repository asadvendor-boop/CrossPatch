import { createHash } from "node:crypto";

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { IncidentRoom } from "@/components/IncidentRoom";

const canonicalDocument = JSON.stringify({
  incident_id: "inc-14",
  patch_sha256: "c".repeat(64),
  base_sha: "b".repeat(40),
  allowed_paths: ["victim/src/victim/db.py"],
  execution_plans: [{ plan_id: "victim.duplicate-race.candidate" }],
  expires_at: "2099-07-14T04:00:00Z",
});
const warrantHash = createHash("sha256").update(canonicalDocument).digest("hex");

function warrant(status = "PENDING_APPROVAL") {
  return {
    id: "war-1",
    incident_id: "inc-14",
    status,
    warrant_sha256: warrantHash,
    expires_at: "2099-07-14T04:00:00Z",
    canonical_document: canonicalDocument,
  };
}

function warrantHistory(status = "PENDING_APPROVAL") {
  return {
    warrant_id: "war-1",
    canonical_sha256: warrantHash,
    binding_hashes: {
      authority_snapshot_sha256: "1".repeat(64),
      base_sha: "b".repeat(40),
      environment_digest: "2".repeat(64),
      patch_sha256: "c".repeat(64),
      repository_manifest_sha256: "3".repeat(64),
      reviewed_evidence_manifest_sha256: "4".repeat(64),
      reviewed_timeline_head: "5".repeat(64),
      runner_digest: "6".repeat(64),
      test_plan_sha256: "7".repeat(64),
      verdict_sha256: "8".repeat(64),
    },
    approval_status: status,
    approval_id: status === "APPROVED" ? "apr-1" : null,
    consumption_status: status === "APPROVED" ? "APPROVED" : "NOT_MATERIALIZED",
    execution_status: "NOT_EXECUTED",
    receipt_ids: [],
    created_at: "2026-07-14T00:00:00Z",
    expires_at: "2099-07-14T04:00:00Z",
    consumed_at: null,
  };
}

function projection({
  id = "inc-14",
  state = "ABSTAINED",
  viewerRole = "operator",
  seats = [],
  events = [],
  diff = null,
  tests = [],
  artifactWarrant = null,
  pendingWarrant = null,
  warrants = [],
  specialistSummaries = [],
}: {
  id?: string;
  state?: string;
  viewerRole?: "read_only" | "operator" | "approver" | "live_trial";
  seats?: unknown[];
  events?: unknown[];
  diff?: string | null;
  tests?: unknown[];
  artifactWarrant?: ReturnType<typeof warrant> | null;
  pendingWarrant?: ReturnType<typeof warrant> | null;
  warrants?: unknown[];
  specialistSummaries?: unknown[];
} = {}) {
  return {
    viewer_role: viewerRole,
    incident: {
      id,
      title: "Receipt race",
      state,
      severity: "UNSET",
      scenario: "webhook-worker",
      base_sha: "f".repeat(40),
      created_at: "2026-07-14T00:00:00Z",
      updated_at: "2026-07-14T00:01:00Z",
    },
    seats,
    events,
    specialist_summaries: specialistSummaries,
    warrants,
    artifacts: {
      evidence: [],
      diff: diff
        ? {
            classification: "UNTRUSTED_EVIDENCE",
            incident_id: id,
            candidate_id: "candidate-1",
            patch_sha256: "c".repeat(64),
            text: diff,
            sanitized_sha256: "d".repeat(64),
            tags: [],
            created_at: "2026-07-14T00:00:30Z",
          }
        : null,
      tests,
      warrant: artifactWarrant,
    },
    pending_warrant: pendingWarrant,
  };
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("IncidentRoom", () => {
  beforeEach(() => sessionStorage.clear());

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads one real incident snapshot without inventing artifacts or events", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection());
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByRole("heading", { level: 1, name: "Receipt race" })).toBeVisible();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.queryByRole("link", { name: "CrossPatch home" })).not.toBeInTheDocument();
    expect(screen.getByText("No incident events yet")).toBeVisible();
    expect(screen.getByText("No evidence recorded")).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByText("not recorded", { exact: true })).toBeVisible();
    expect(screen.queryByText("UNSET", { exact: true })).not.toBeInTheDocument();
    expect(screen.getAllByText("Abstained", { exact: true }).length).toBeGreaterThan(0);
    expect(screen.getByTestId("record-derived-headline"))
      .toHaveTextContent("Authorized record / derived headline");
    expect(screen.getByText("Authorized incident projection")).toBeVisible();
    expect(screen.queryByText("Published projection", { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByText("Published snapshot only", { exact: true })).not.toBeInTheDocument();
    await waitFor(() =>
      expect(fetcher).toHaveBeenCalledWith("/api/incidents/inc-14/room", expect.anything()),
    );
  });

  it("labels a read-only public room as published without changing its controls", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({ viewerRole: "read_only" }));
    }));

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByTestId("record-derived-headline"))
      .toHaveTextContent("Published record / derived headline");
    expect(screen.getByText("Published snapshot only")).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
  });

  it("renders Signal as the sole production room while preserving approval and artifact controls", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection());
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByTestId("room-experience")).toHaveAttribute(
      "data-room-layout",
      "signal",
    );
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByRole("tab", { name: "Evidence" })).toBeVisible();
  });

  it("shows a visible fail-closed error instead of a synthetic room", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("missing", { status: 404 })));

    render(<IncidentRoom incidentId="missing" />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Request failed (404)");
    expect(screen.queryByTestId("room-experience")).not.toBeInTheDocument();
  });

  it("keeps a pending warrant disabled when this tab lacks approval credentials", async () => {
    sessionStorage.setItem("crosspatch_access_token", "operator-token");
    const pending = warrant();
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({
        state: "APPROVAL_PENDING",
        artifactWarrant: pending,
        pendingWarrant: pending,
      }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByRole("button", { name: "Approve warrant" })).toBeDisabled();
    expect(screen.getByTestId("approval-unavailable-reason")).toHaveTextContent(
      "Approval credentials are unavailable in this browser tab",
    );
  });

  it("rejects the exact warrant hash displayed in the incident room", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        return json(warrant("REJECTED"));
      }
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      const pending = warrant();
      return json(projection({
        state: "APPROVAL_PENDING",
        artifactWarrant: pending,
        pendingWarrant: pending,
      }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);
    const confirmation = await screen.findByRole("textbox", { name: "Type REJECT to confirm" });
    await userEvent.type(confirmation, "REJECT");
    await userEvent.click(screen.getByRole("button", { name: "Reject warrant" }));

    await waitFor(() =>
      expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(true),
    );
    const [, rejection] = fetcher.mock.calls.find(([, init]) => init?.method === "POST") as [
      string,
      RequestInit,
    ];
    expect(rejection.body).toBe(
      JSON.stringify({ confirmation: "REJECT", warrant_sha256: warrantHash }),
    );
  });

  it("refetches the room after approval and displays the authoritative warrant status", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    let approved = false;
    let roomRequests = 0;
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (init?.method === "POST") {
        approved = true;
        return json(warrant("APPROVED"));
      }
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      roomRequests += 1;
      const current = warrant(approved ? "APPROVED" : "PENDING_APPROVAL");
      return json(projection({
        state: approved ? "APPROVED" : "APPROVAL_PENDING",
        artifactWarrant: current,
        pendingWarrant: approved ? null : current,
        warrants: [warrantHistory(approved ? "APPROVED" : "PENDING_APPROVAL")],
      }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);
    await userEvent.click(
      await screen.findByRole("checkbox", { name: /reviewed the exact canonical warrant/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Approve warrant" }));

    await waitFor(() => expect(roomRequests).toBeGreaterThan(1));
    expect(screen.getAllByText("Approved").length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("tab", { name: "Warrants" }));
    expect(screen.getByRole("tabpanel")).toHaveTextContent("Approved");
  });

  it("keeps a loaded room visible when case export fails", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/export")) return json({ detail: "Case export unavailable" }, 503);
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({ state: "VERIFIED" }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);
    await userEvent.click(await screen.findByRole("button", { name: "Export case file" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Case export unavailable");
    expect(screen.getByRole("heading", { level: 1, name: "Receipt race" })).toBeVisible();
    expect(screen.getByTestId("room-experience")).toBeVisible();
  });

  it("keeps case export unavailable until the incident is verified", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({ state: "APPROVAL_PENDING" }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByRole("button", { name: "Export case file" })).toBeDisabled();
    expect(screen.getByText("Export available after verified execution.")).toBeVisible();
  });

  it.each(["VERIFIED", "BLOCKED"])(
    "treats a terminal %s room as a complete record and never opens SSE",
    async (state) => {
      const fetcher = vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).includes("/events/stream")) {
          throw new Error("terminal room must not open an event stream");
        }
        return json(projection({ state }));
      });
      vi.stubGlobal("fetch", fetcher);

      render(<IncidentRoom incidentId="inc-14" />);

      expect(await screen.findByText("Record complete")).toHaveAttribute("data-stream", "complete");
      await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
      expect(fetcher.mock.calls.some(([url]) => String(url).includes("/events/stream"))).toBe(false);
    },
  );

  it("revalidates the authoritative room when a suspended tab becomes visible", async () => {
    let roomRequests = 0;
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      roomRequests += 1;
      return json(projection({ state: roomRequests === 1 ? "EXECUTING" : "BLOCKED" }));
    });
    vi.stubGlobal("fetch", fetcher);
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });

    render(<IncidentRoom incidentId="inc-14" />);
    expect((await screen.findAllByText("Executing")).length).toBeGreaterThan(0);

    document.dispatchEvent(new Event("visibilitychange"));

    await waitFor(() => {
      expect(roomRequests).toBeGreaterThan(1);
      expect(screen.getAllByText("Blocked").length).toBeGreaterThan(0);
    }, { timeout: 5_000 });
    expect(screen.getByText("Record complete")).toBeVisible();
  });

  it("renders the full authoritative still frame when reduced motion is requested", async () => {
    vi.stubGlobal("matchMedia", vi.fn().mockImplementation((query: string) => ({
      matches: query === "(prefers-reduced-motion: reduce)",
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })));
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({ state: "EXECUTING" }));
    }));

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByTestId("room-experience")).toHaveAttribute("data-story-step");
    expect(document.querySelector("[data-motion]")).toHaveAttribute("data-motion", "static");
  });

  it("refetches authoritative seats, diff, tests, and warrant after an SSE event", async () => {
    sessionStorage.setItem("crosspatch_access_token", "approver-token");
    sessionStorage.setItem("crosspatch_csrf_token", "csrf-token");
    sessionStorage.setItem("crosspatch_step_up_token", "step-up-token");
    let roomRequests = 0;
    const pending = warrant();
    const event = {
      id: "evt-1",
      incident_id: "inc-14",
      sequence: 1,
      type: "PATCH_CANDIDATE_PUBLISHED",
      actor: "Counsel",
      summary: "Candidate and test projection changed",
      details: {},
      event_hash: "e".repeat(64),
      created_at: "2026-07-14T00:02:00Z",
      published: true,
    };
    const authoritativeEvent = {
      ...event,
      summary: "Authoritative candidate projection published",
    };
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/events/stream")) {
        return new Response(
          `id: 1\nevent: PATCH_CANDIDATE_PUBLISHED\ndata: ${JSON.stringify(event)}\n\n`,
          { status: 200, headers: { "Content-Type": "text/event-stream" } },
        );
      }
      roomRequests += 1;
      if (roomRequests === 1) return json(projection());
      return json(projection({
        state: "APPROVAL_PENDING",
        seats: [{
          name: "Counsel",
          role: "Live repair author",
          model: "gpt-5.6-terra",
          tier_rationale: "Live controlled synthesis",
          effort: "high",
          escalation_count: 1,
          state: "complete",
        }],
        events: [authoritativeEvent],
        diff: "@@ -1 +1 @@\n-racy\n+atomic",
        tests: [{
          id: "victim.candidate-race",
          label: "Candidate race",
          state: "failed",
          duration_ms: 812,
          detail: "duplicate remained",
        }],
        artifactWarrant: pending,
        pendingWarrant: pending,
      }));
    });
    vi.stubGlobal("fetch", fetcher);

    render(<IncidentRoom incidentId="inc-14" />);

    expect(await screen.findByText("Authoritative candidate projection published")).toBeVisible();
    const counsel = screen.getByTestId("seat-counsel");
    expect(counsel).toHaveTextContent("Proposes the smallest testable repair");
    expect(counsel).toHaveTextContent("Controlled patch and test-intent synthesis");
    expect(counsel).toHaveTextContent("Effort: high");
    expect(counsel).toHaveTextContent("Escalations: 1/2");
    expect(counsel).not.toHaveTextContent("Live repair author");
    expect(counsel).not.toHaveTextContent("Live controlled synthesis");
    expect(screen.queryByText("Candidate and test projection changed")).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Type REJECT to confirm" })).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: "Diff" }));
    expect(screen.getByText(/\+atomic/)).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: "Tests" }));
    expect(screen.getByText("Candidate race")).toBeVisible();
    expect(screen.getByText("duplicate remained")).toBeVisible();
    expect(roomRequests).toBeGreaterThan(1);
  });

  it("does not stream a new incident until its authorized room projection loads", async () => {
    let resolveSecondRoom: ((response: Response) => void) | undefined;
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/inc-second/room")) {
        return new Promise<Response>((resolve) => {
          resolveSecondRoom = resolve;
        });
      }
      if (url.includes("/events/stream")) {
        return new Response(": connected\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return json(projection({ id: "inc-first" }));
    });
    vi.stubGlobal("fetch", fetcher);

    const { rerender } = render(<IncidentRoom incidentId="inc-first" />);
    await screen.findByRole("heading", { level: 1, name: "Receipt race" });
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([url]) => String(url).includes("inc-first/events/stream")))
        .toBe(true),
    );

    rerender(<IncidentRoom incidentId="inc-second" />);
    await waitFor(() => expect(resolveSecondRoom).toBeTypeOf("function"));
    expect(
      fetcher.mock.calls.some(([url]) => String(url).includes("inc-second/events/stream")),
    ).toBe(false);

    resolveSecondRoom?.(json(projection({ id: "inc-second" })));
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([url]) => String(url).includes("inc-second/events/stream")))
        .toBe(true),
    );
  });
});
