import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";

import { RecordScrubber } from "@/components/exhibits/RecordScrubber";

function matchMedia(reduced: boolean) {
  return vi.fn().mockImplementation((query: string) => ({
    matches: reduced && query === "(prefers-reduced-motion: reduce)",
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

function Harness({ initial = 0 }: { initial?: number }) {
  const [value, setValue] = useState(initial);
  return (
    <RecordScrubber
      eventCount={8}
      selectedEventCount={value}
      selectedTimestamp={value ? `2026-07-16T12:00:0${value}Z` : null}
      onChange={setValue}
    />
  );
}

describe("RecordScrubber", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("steps, scrubs, plays, and pauses only the local recorded ordinal", async () => {
    vi.stubGlobal("matchMedia", matchMedia(false));
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    vi.useFakeTimers();
    render(<Harness />);

    expect(screen.getByText("Event 0 of 8")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Step forward" }));
    expect(screen.getByText("Event 1 of 8")).toBeVisible();
    fireEvent.change(screen.getByRole("slider", { name: "Recorded event position" }), {
      target: { value: "5" },
    });
    expect(screen.getByText("Event 5 of 8")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Play recorded events" }));
    act(() => vi.advanceTimersByTime(900));
    expect(screen.getByText("Event 6 of 8")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Pause recorded events" }));
    act(() => vi.advanceTimersByTime(1800));
    expect(screen.getByText("Event 6 of 8")).toBeVisible();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("restarts a complete record from ordinal zero before playback", async () => {
    vi.stubGlobal("matchMedia", matchMedia(false));
    render(<Harness initial={8} />);

    await userEvent.click(screen.getByRole("button", { name: "Play recorded events" }));

    expect(screen.getByText("Event 0 of 8")).toBeVisible();
  });

  it("falls back to step-only controls when reduced motion is requested", async () => {
    vi.stubGlobal("matchMedia", matchMedia(true));
    render(<Harness initial={4} />);

    expect(screen.queryByRole("button", { name: /play recorded events/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("slider", { name: "Recorded event position" })).not.toBeInTheDocument();
    expect(screen.getByText(/reduced motion: step through the record/i)).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Step backward" }));
    expect(screen.getByText("Event 3 of 8")).toBeVisible();
  });
});
