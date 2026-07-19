import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Timeline } from "@/components/Timeline";
import { ESCALATION_EXPLANATION } from "@/lib/tokens";
import { persistedEvent } from "@/lib/events";
import type { TimelineEvent } from "@/lib/types";

const failed: TimelineEvent = {
  id: "evt-12",
  eventHash: "a".repeat(64),
  rawPublicJson: '{"id":"evt-12"}',
  sequence: 12,
  kind: "TEST_FAILED",
  actor: "runner",
  occurredAt: "2026-07-14T01:00:00Z",
  summary: "Candidate test failed",
  state: "failed",
};

const retry: TimelineEvent = {
  id: "evt-13",
  eventHash: "b".repeat(64),
  rawPublicJson: '{"id":"evt-13"}',
  sequence: 13,
  kind: "RETRY_STARTED",
  actor: "Inspector",
  occurredAt: "2026-07-14T01:00:01Z",
  summary: "Retry started",
  state: "active",
};

const escalation: TimelineEvent = {
  id: "evt-14",
  eventHash: "c".repeat(64),
  rawPublicJson: '{"id":"evt-14"}',
  sequence: 14,
  kind: "EFFORT_ESCALATED",
  actor: "Inspector",
  occurredAt: "2026-07-14T01:00:02Z",
  summary: "Effort changed to high",
  state: "warning",
  explanation: ESCALATION_EXPLANATION,
};

describe("Timeline", () => {
  it("politely announces only the newest incident event", () => {
    const { rerender } = render(<Timeline events={[failed]} connectionState="live" />);

    const announcement = screen.getByTestId("timeline-live-announcement");
    expect(announcement).toHaveTextContent("Latest incident event: Test failed. Candidate test failed");

    rerender(<Timeline events={[failed, retry]} connectionState="live" />);

    expect(announcement).toHaveTextContent("Latest incident event: Retry started. Retry started");
    expect(announcement).not.toHaveTextContent("Candidate test failed");
  });

  it("keeps a failed event visibly failed after a retry begins", () => {
    render(<Timeline events={[failed, retry]} connectionState="live" />);

    expect(screen.getByTestId("event-test-failed")).toHaveAttribute("data-state", "failed");
    expect(screen.getByTestId("event-retry-started")).toBeVisible();
    expect(screen.getByTestId("event-test-failed")).toBeVisible();
  });

  it("shows and persists the exact escalation explanation", async () => {
    render(<Timeline events={[escalation]} connectionState="live" />);

    expect(screen.getByText(ESCALATION_EXPLANATION)).toBeVisible();
    expect(await persistedEvent(escalation.id)).toMatchObject({
      explanation: ESCALATION_EXPLANATION,
    });
  });

  it("renders a real empty state instead of fabricated incident activity", () => {
    render(<Timeline events={[]} connectionState="connecting" />);

    expect(screen.getByText("No incident events yet")).toBeVisible();
    expect(screen.getByText(/waiting for the first published event/i)).toBeVisible();
  });

  it("renders structured published event details without discarding fields", () => {
    render(
      <Timeline
        events={[
          {
            ...retry,
            details: { evidence_count: 1, evidence_ids: ["ev-1"] },
          },
        ]}
        connectionState="live"
      />,
    );

    const details = screen.getByTestId("event-retry-started-details");
    expect(details).toHaveTextContent('"evidence_count": 1');
    expect(details).toHaveTextContent('"ev-1"');
  });
});
