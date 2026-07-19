import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PersonaPortrait, PORTRAIT_CONTRACT, validateReplacement } from "@/components/PersonaPortrait";
import { PersonaRail } from "@/components/PersonaRail";
import { DEFAULT_SEATS } from "@/lib/tokens";
import type { SeatView } from "@/lib/types";

describe("PersonaRail", () => {
  it("renders the five seats in exact order with the approval gate before Bailiff", () => {
    render(<PersonaRail seats={DEFAULT_SEATS} pendingWarrant={null} />);

    expect(
      screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent),
    ).toEqual([
      "Prosecutor",
      "Inspector",
      "Counsel",
      "Magistrate",
      "Human approval",
      "Bailiff",
    ]);
  });

  it("pins locked seat identity while preserving live execution state", () => {
    const seats: SeatView[] = DEFAULT_SEATS.map((seat) =>
      seat.name === "Prosecutor"
        ? {
            ...seat,
            role: "Live role from the room projection",
            model: "live-model-id",
            tierRationale: "Live tier rationale",
            effort: "high",
            escalationCount: 2,
            state: "working",
          }
        : { ...seat },
    );

    render(<PersonaRail seats={seats} pendingWarrant={null} />);

    const prosecutor = screen.getByTestId("seat-prosecutor");
    expect(prosecutor).toHaveTextContent("Challenges the leading incident hypothesis");
    expect(prosecutor).toHaveTextContent("gpt-5.6-luna");
    expect(prosecutor).toHaveTextContent("Fast rival-hypothesis pressure testing");
    expect(prosecutor).not.toHaveTextContent("Live role from the room projection");
    expect(prosecutor).not.toHaveTextContent("live-model-id");
    expect(prosecutor).not.toHaveTextContent("Live tier rationale");
    expect(prosecutor).toHaveTextContent("Effort: high");
    expect(prosecutor).toHaveTextContent("Escalations: 2/2");
    expect(prosecutor).toHaveTextContent("Working");
  });

  it("keeps exact seat order but marks missing live seats unavailable", () => {
    render(<PersonaRail seats={[DEFAULT_SEATS[0]]} pendingWarrant={null} />);

    expect(
      screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent),
    ).toEqual([
      "Prosecutor",
      "Inspector",
      "Counsel",
      "Magistrate",
      "Human approval",
      "Bailiff",
    ]);
    const inspector = screen.getByTestId("seat-inspector");
    expect(inspector).toHaveTextContent("Live seat data unavailable");
    expect(inspector).toHaveTextContent("Effort: unavailable");
    expect(inspector).toHaveTextContent("Escalations: unavailable");
  });

  it.each([
    ["Prosecutor", "gpt-5.6-luna", "low"],
    ["Inspector", "gpt-5.6-terra", "medium"],
    ["Counsel", "gpt-5.6-terra", "medium"],
    ["Magistrate", "gpt-5.6-sol", "medium"],
    ["Bailiff", "gpt-5.6-luna", "none"],
  ] as const)("renders %s with the exact card contract", (seat, model, effort) => {
    render(<PersonaRail seats={DEFAULT_SEATS} pendingWarrant={null} />);

    const card = screen.getByTestId(`seat-${seat.toLowerCase()}`);
    expect(
      within(card).getByRole("img", { name: new RegExp(`${seat} portrait`, "i") }),
    ).toHaveStyle({ width: "72px", height: "90px" });
    expect(within(card).getByTestId("seat-role")).toHaveClass("single-line");
    expect(card).toHaveTextContent(model);
    expect(within(card).getByTestId("tier-rationale")).not.toBeEmptyDOMElement();
    expect(card).toHaveTextContent(`Effort: ${effort}`);
    expect(card).toHaveTextContent("Escalations: 0/2");
  });

  it("loads the configured final portrait asset", () => {
    render(<PersonaPortrait seat="Prosecutor" expanded={false} />);

    expect(screen.getByRole("img", { name: "Prosecutor portrait" })).toHaveAttribute(
      "src",
      "/personas/prosecutor.webp",
    );
  });

  it("falls back to an accessible neutral monogram when a configured image fails", () => {
    render(<PersonaPortrait seat="Prosecutor" expanded={false} assetAvailable />);

    fireEvent.error(screen.getByRole("img", { name: "Prosecutor portrait" }));

    expect(
      screen.getByRole("img", { name: "Prosecutor portrait placeholder" }),
    ).toHaveTextContent("P");
  });

  it("validates exact source/crop dimensions and renders the expanded slot", async () => {
    expect(PORTRAIT_CONTRACT).toMatchObject({
      source: [1024, 1536],
      crop: [800, 1000],
    });
    await expect(validateReplacement({ width: 1024, height: 1536 }, "source")).resolves.toBe(
      true,
    );
    await expect(validateReplacement({ width: 800, height: 1000 }, "crop")).resolves.toBe(
      true,
    );
    await expect(validateReplacement({ width: 799, height: 1000 }, "crop")).resolves.toBe(
      false,
    );

    render(<PersonaPortrait seat="Inspector" expanded />);
    expect(screen.getByRole("img", { name: /inspector portrait/i })).toHaveStyle({
      width: "160px",
      height: "200px",
    });
  });
});
