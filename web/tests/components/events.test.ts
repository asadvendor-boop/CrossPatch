import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mergeTimelineEvents, SseFrameDecoder, useIncidentEventStream } from "@/lib/events";
import type { TimelineEvent } from "@/lib/types";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("SseFrameDecoder", () => {
  it("does not synthesize actor prose while merging a recorded escalation event", () => {
    const event: TimelineEvent = {
      id: "evt-escalation",
      eventHash: "a".repeat(64),
      rawPublicJson: JSON.stringify({
        id: "evt-escalation",
        type: "REASONING_ESCALATED",
        summary: "Reasoning escalated",
      }),
      sequence: 8,
      kind: "REASONING_ESCALATED",
      actor: "Counsel",
      occurredAt: "2026-07-15T00:00:08Z",
      summary: "Reasoning escalated",
      details: { seat: "Counsel", effort: "high", escalation_count: 1 },
      state: "warning",
      explanation: null,
    };

    expect(mergeTimelineEvents([], [event])).toEqual([event]);
  });

  it("reassembles split authenticated SSE frames without losing event data", () => {
    const decoder = new SseFrameDecoder();

    expect(decoder.push("id: 2\nevent: TEST_FAILED\ndata: {\"id\":\"evt-2\","))
      .toEqual([]);
    expect(decoder.push("\"sequence\":2}\n\n")).toEqual([
      {
        id: "2",
        event: "TEST_FAILED",
        data: '{"id":"evt-2","sequence":2}',
      },
    ]);
  });

  it("ignores SSE comments and joins multiple data lines", () => {
    const decoder = new SseFrameDecoder();

    expect(decoder.push(": heartbeat\ndata: first\ndata: second\n\n")).toEqual([
      { id: "", event: "message", data: "first\nsecond" },
    ]);
  });

  it("opens the authenticated stream from the authoritative projection head", async () => {
    sessionStorage.setItem("crosspatch_access_token", "reader-token");
    const fetcher = vi.fn().mockResolvedValue(
      new Response(": connected\n\n", {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      }),
    );
    vi.stubGlobal("fetch", fetcher);

    const { unmount } = renderHook(() =>
      useIncidentEventStream({
        incidentId: "inc-1",
        initialLastEventId: "17",
        onEvent: vi.fn(),
        onState: vi.fn(),
        decode: vi.fn(),
        url: "/api/incidents/inc-1/events/stream?limit=500",
      }),
    );

    await waitFor(() => expect(fetcher).toHaveBeenCalled());
    const [url, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/incidents/inc-1/events/stream?limit=500");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer reader-token");
    expect(new Headers(init.headers).get("Last-Event-ID")).toBe("17");
    expect(init.credentials).toBeUndefined();
    unmount();
  });

  it("reconnects from the last delivered event ID without replaying the record head", async () => {
    vi.useFakeTimers();
    const payload = {
      id: "evt-18",
      incident_id: "inc-1",
      sequence: 18,
      type: "SEAT_COMPLETED",
      actor: "Inspector",
      summary: "Inspector completed",
      details: {},
      event_hash: "e".repeat(64),
      created_at: "2026-07-15T00:00:00Z",
      published: true,
    };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(
        `id: 18\nevent: SEAT_COMPLETED\ndata: ${JSON.stringify(payload)}\n\n`,
        { status: 200, headers: { "Content-Type": "text/event-stream" } },
      ))
      .mockResolvedValue(new Response(": connected\n\n", {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      }));
    vi.stubGlobal("fetch", fetcher);
    const onEvent = vi.fn();

    const { unmount } = renderHook(() =>
      useIncidentEventStream({
        incidentId: "inc-1",
        initialLastEventId: "17",
        onEvent,
        onState: vi.fn(),
        decode: (value) => value as TimelineEvent,
        url: "/api/incidents/inc-1/events/stream?limit=500",
      }),
    );

    await vi.waitFor(() => expect(onEvent).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(1_000);
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));

    const [, reconnect] = fetcher.mock.calls[1] as [string, RequestInit];
    expect(new Headers(reconnect.headers).get("Last-Event-ID")).toBe("18");
    expect(onEvent).toHaveBeenCalledTimes(1);
    unmount();
  });
});
