import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IncidentAccessForm } from "@/components/IncidentAccessForm";

describe("IncidentAccessForm", () => {
  it("keeps every supplied credential session-scoped and opens only the requested incident", async () => {
    const open = vi.fn();
    render(<IncidentAccessForm onOpen={open} />);

    const button = screen.getByRole("button", { name: "Open incident room" });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByRole("textbox", { name: "Incident ID" }), "inc/14");
    const accessToken = screen.getByLabelText("Access token");
    expect(accessToken).toHaveAttribute("autocomplete", "off");
    await userEvent.type(accessToken, "operator-token");
    await userEvent.type(screen.getByLabelText("CSRF token"), "csrf-token");
    await userEvent.type(screen.getByLabelText("Step-up token"), "step-up-token");
    await userEvent.click(button);

    expect(sessionStorage.getItem("crosspatch_access_token")).toBe("operator-token");
    expect(sessionStorage.getItem("crosspatch_csrf_token")).toBe("csrf-token");
    expect(sessionStorage.getItem("crosspatch_step_up_token")).toBe("step-up-token");
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc/14");
    expect(localStorage.getItem("crosspatch_access_token")).toBeNull();
    expect(localStorage.getItem("crosspatch_csrf_token")).toBeNull();
    expect(localStorage.getItem("crosspatch_step_up_token")).toBeNull();
    expect(localStorage.getItem("crosspatch_incident_id")).toBeNull();
    expect(open).toHaveBeenCalledWith("/incidents/inc%2F14");
  });

  it("requires only the access token to open a room and clears stale approval credentials", async () => {
    sessionStorage.setItem("crosspatch_csrf_token", "stale-csrf");
    sessionStorage.setItem("crosspatch_step_up_token", "stale-step-up");
    const open = vi.fn();
    render(<IncidentAccessForm onOpen={open} />);

    await userEvent.type(screen.getByRole("textbox", { name: "Incident ID" }), "inc-15");
    await userEvent.type(screen.getByLabelText("Access token"), "reader-token");
    await userEvent.click(screen.getByRole("button", { name: "Open incident room" }));

    expect(open).toHaveBeenCalledWith("/incidents/inc-15");
    expect(sessionStorage.getItem("crosspatch_csrf_token")).toBeNull();
    expect(sessionStorage.getItem("crosspatch_step_up_token")).toBeNull();
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe("inc-15");
    expect(localStorage.getItem("crosspatch_incident_id")).toBeNull();
  });
});
