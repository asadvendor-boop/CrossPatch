import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { WarrantAnatomy } from "@/components/exhibits/WarrantAnatomy";
import { decodePublishedCase } from "@/lib/api";
import { publicCaseWithWarrantEnvelope } from "../fixtures/public-cases";

describe("WarrantAnatomy", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("annotates every recorded binding beside the exact nonce-safe canonical bytes", async () => {
    const published = await decodePublishedCase(publicCaseWithWarrantEnvelope());
    const warrant = published.snapshot.warrants[0];

    render(<WarrantAnatomy warrant={warrant} />);

    expect(screen.getByRole("heading", { name: "Warrant anatomy" })).toBeVisible();
    expect(screen.getByText(
      "This is what the human approved. One changed byte and the broker refuses.",
    )).toBeVisible();
    const annotations = screen.getByTestId("warrant-anatomy-bindings");
    for (const label of [
      "Full broker-bound SHA-256",
      "Public anatomy SHA-256",
      "Verdict hash",
      "Evidence manifest",
      "Timeline head",
      "Base SHA",
      "Patch bytes SHA-256",
      "Authority snapshot",
      "Repository manifest",
      "Environment digest",
      "Test plan SHA-256",
      "Allowed paths",
      "Plan IDs",
      "Runner digest",
      "Expiry",
      "Approver",
      "Nonce SHA-256",
    ]) {
      expect(within(annotations).getByText(label)).toBeVisible();
    }
    expect(screen.getByTestId("canonical-public-warrant-bytes").textContent)
      .toBe(warrant.publicWarrantBytes);
    expect(screen.getByText(/secret-bearing nonce and patch bytes are replaced/i)).toBeVisible();
  });

  it("recomputes a disposable byte copy locally and shows the broker mismatch", async () => {
    const published = await decodePublishedCase(publicCaseWithWarrantEnvelope());
    const warrant = published.snapshot.warrants[0];
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);

    render(<WarrantAnatomy warrant={warrant} />);

    expect(await screen.findByText("Integrity match")).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Perturb one byte" }));
    expect(await screen.findByText("Mismatch — broker would refuse")).toBeVisible();
    expect(screen.getByTestId("canonical-public-warrant-bytes").textContent)
      .toBe(warrant.publicWarrantBytes);
    expect(screen.getByTestId("warrant-integrity-copy").textContent)
      .not.toBe(warrant.publicWarrantBytes);
    expect(fetcher).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Reset bytes" }));
    await waitFor(() => expect(screen.getByText("Integrity match")).toBeVisible());
  });

  it("omits the exhibit when no safe recorded warrant exists", () => {
    const { container } = render(<WarrantAnatomy warrant={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
