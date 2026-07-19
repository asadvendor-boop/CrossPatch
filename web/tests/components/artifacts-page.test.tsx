import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ArtifactsPage } from "@/components/pages/ArtifactsPage";
import { recordedRoomSnapshot } from "@/tests/fixtures/recorded-room";

const api = vi.hoisted(() => ({
  downloadCaseFile: vi.fn(),
  getIncidentRoom: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/api")>(),
  ...api,
}));

describe("ArtifactsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("starts with an explicit incident selection rather than a fictional global index", async () => {
    render(<ArtifactsPage />);

    expect(screen.getByRole("heading", { name: "Select one incident" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Load incident artifacts" })).toBeDisabled();
    expect(await screen.findByText(/no incident is selected in this browser tab/i)).toBeVisible();
    expect(api.getIncidentRoom).not.toHaveBeenCalled();
  });

  it("renders the real inspector and keeps export disabled before VERIFIED", async () => {
    const snapshot = recordedRoomSnapshot();
    sessionStorage.setItem("crosspatch_incident_id", snapshot.incident.id);
    api.getIncidentRoom.mockResolvedValue({
      ...snapshot,
      incident: { ...snapshot.incident, state: "REVIEWING" },
    });

    render(<ArtifactsPage />);

    expect(await screen.findByText("Webhook receipt race")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Incident artifacts" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Export signed case file" })).toBeDisabled();
    expect(screen.getByText(/export unlocks only after trusted execution reaches verified/i))
      .toBeVisible();
    expect(api.downloadCaseFile).not.toHaveBeenCalled();
  });

  it("downloads only a VERIFIED case and describes real offline verification", async () => {
    const snapshot = recordedRoomSnapshot();
    sessionStorage.setItem("crosspatch_incident_id", snapshot.incident.id);
    api.getIncidentRoom.mockResolvedValue(snapshot);
    api.downloadCaseFile.mockResolvedValue(undefined);

    render(<ArtifactsPage />);

    const exportButton = await screen.findByRole("button", { name: "Export signed case file" });
    expect(exportButton).toBeEnabled();
    await userEvent.click(exportButton);

    await waitFor(() => expect(api.downloadCaseFile).toHaveBeenCalledWith(snapshot.incident.id));
    expect(screen.getByRole("status")).toHaveTextContent(/download started/i);
    expect(screen.getByText(/crosspatch\.export\.verify_export/)).toBeVisible();
    expect(screen.getByText(/download success is not cryptographic verification/i)).toBeVisible();
    expect(screen.getByRole("link", { name: "Production export key" })).toHaveAttribute(
      "href",
      "/verification/production-export-public-key.json",
    );
    expect(screen.getByRole("link", { name: "Sealed cohort key" })).toHaveAttribute(
      "href",
      "/verification/sealed-cohort-export-public-key.json",
    );
    expect(screen.getByRole("link", { name: "Key provenance manifest" })).toHaveAttribute(
      "href",
      "/verification/export-public-keys.json",
    );
  });

  it("surfaces a load failure and permits an incident replacement", async () => {
    const snapshot = recordedRoomSnapshot();
    sessionStorage.setItem("crosspatch_incident_id", "inc-missing");
    api.getIncidentRoom
      .mockRejectedValueOnce(new Error("Incident projection unavailable"))
      .mockResolvedValueOnce(snapshot);

    render(<ArtifactsPage />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Incident projection unavailable");
    const input = screen.getByRole("textbox", { name: "Incident ID" });
    await userEvent.clear(input);
    await userEvent.type(input, snapshot.incident.id);
    await userEvent.click(screen.getByRole("button", { name: "Load incident artifacts" }));

    expect(await screen.findByText("Webhook receipt race")).toBeVisible();
    expect(sessionStorage.getItem("crosspatch_incident_id")).toBe(snapshot.incident.id);
  });
});
