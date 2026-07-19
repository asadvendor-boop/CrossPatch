import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IncidentOpenForm } from "@/components/IncidentOpenForm";

function openedIncidentResponse(
  scenario = "webhook-race",
  title = "Duplicate order-paid delivery",
): Response {
  return new Response(
    JSON.stringify({
      id: "inc-live",
      title,
      scenario,
      state: "OPEN",
      timeline_head: null,
      pending_warrant_id: null,
    }),
    { status: 201, headers: { "Content-Type": "application/json" } },
  );
}

describe("IncidentOpenForm", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("opens the genuine webhook race and keeps its bearer token session-only", async () => {
    const fetcher = vi.fn().mockResolvedValue(openedIncidentResponse());
    const open = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    render(<IncidentOpenForm onOpen={open} />);

    const button = screen.getByRole("button", { name: "Open webhook-race incident" });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Operator or live-trial bearer token"), "operator-secret");
    expect(button).toBeEnabled();
    await userEvent.click(button);

    await waitFor(() => expect(open).toHaveBeenCalledWith("/incidents/inc-live"));
    expect(sessionStorage.getItem("crosspatch_access_token")).toBe("operator-secret");
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc-live");
    expect(localStorage.getItem("crosspatch_access_token")).toBeNull();
    expect(localStorage.getItem("crosspatch_incident_id")).toBeNull();
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it.each([
    ["webhook-race", "Duplicate order-paid delivery"],
    ["webhook-payload-equivalence", "Equivalent webhook retry rejected"],
  ])("opens the selected closed %s scenario with its safe title", async (scenario, title) => {
    const fetcher = vi.fn().mockResolvedValue(openedIncidentResponse(scenario, title));
    vi.stubGlobal("fetch", fetcher);
    render(<IncidentOpenForm onOpen={vi.fn()} />);

    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Incident scenario" }),
      scenario,
    );
    expect(screen.getByLabelText("Incident title")).toHaveValue(title);
    await userEvent.type(screen.getByLabelText(/bearer token/i), "operator-secret");
    await userEvent.click(screen.getByRole("button", { name: `Open ${scenario} incident` }));

    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const [, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBe(JSON.stringify({
      scenario,
      title,
      evidence_profile: "standard",
    }));
  });

  it("opens the operator-only C2 profile through the normal incident request", async () => {
    const title = "Poisoned webhook logs — due process held";
    const fetcher = vi.fn().mockResolvedValue(openedIncidentResponse("webhook-race", title));
    vi.stubGlobal("fetch", fetcher);
    render(<IncidentOpenForm onOpen={vi.fn()} />);

    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Evidence fixture" }),
      "instruction-like-log",
    );
    expect(screen.getByLabelText("Incident title")).toHaveValue(title);
    expect(screen.getByText(/operator-only sanitizer demonstration/i)).toBeVisible();
    await userEvent.type(
      screen.getByLabelText("Operator or live-trial bearer token"),
      "operator-secret",
    );
    await userEvent.click(screen.getByRole("button", { name: "Open webhook-race incident" }));

    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    const [, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBe(JSON.stringify({
      scenario: "webhook-race",
      title,
      evidence_profile: "instruction-like-log",
    }));
  });

  it("keeps payload equivalence operator-only without claiming live-trial support", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(openedIncidentResponse()));
    render(<IncidentOpenForm onOpen={vi.fn()} />);

    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Incident scenario" }),
      "webhook-payload-equivalence",
    );

    expect(screen.getByLabelText("Operator bearer token")).toBeVisible();
    expect(screen.queryByRole("combobox", { name: "Evidence fixture" }))
      .not.toBeInTheDocument();
    expect(screen.queryByLabelText("Operator or live-trial bearer token")).not.toBeInTheDocument();
    expect(screen.getByText(/private live trials remain fixed to webhook-race/i)).toBeVisible();
  });

  it("clears stale approval credentials and never approves the opened incident", async () => {
    sessionStorage.setItem("crosspatch_csrf_token", "stale-csrf");
    sessionStorage.setItem("crosspatch_step_up_token", "stale-step-up");
    const fetcher = vi.fn().mockResolvedValue(openedIncidentResponse());
    vi.stubGlobal("fetch", fetcher);
    render(<IncidentOpenForm onOpen={vi.fn()} />);

    await userEvent.type(screen.getByLabelText("Operator or live-trial bearer token"), "operator-secret");
    await userEvent.click(screen.getByRole("button", { name: "Open webhook-race incident" }));

    await waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
    expect(sessionStorage.getItem("crosspatch_csrf_token")).toBeNull();
    expect(sessionStorage.getItem("crosspatch_step_up_token")).toBeNull();
    const [url] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/incidents");
  });

  it("locks repeated submission while opening and restores an accessible error", async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    const fetcher = vi.fn(
      () => new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      }),
    );
    vi.stubGlobal("fetch", fetcher);
    render(<IncidentOpenForm onOpen={vi.fn()} />);

    await userEvent.clear(screen.getByLabelText("Incident title"));
    await userEvent.type(screen.getByLabelText("Incident title"), "Live receipt race");
    await userEvent.type(screen.getByLabelText("Operator or live-trial bearer token"), "wrong-token");
    const button = screen.getByRole("button", { name: "Open webhook-race incident" });
    await userEvent.click(button);

    expect(button).toBeDisabled();
    expect(button).toHaveTextContent("Opening real incident…");
    expect(fetcher).toHaveBeenCalledOnce();
    resolveResponse?.(
      new Response(JSON.stringify({ detail: "Operator access denied" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Operator access denied");
    expect(button).toBeEnabled();
    expect(button).toHaveTextContent("Open webhook-race incident");
  });
});
