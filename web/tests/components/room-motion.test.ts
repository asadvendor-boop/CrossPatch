import { describe, expect, it } from "vitest";

import { projectRoomMotion } from "@/lib/room-motion";
import { recordedRoomSnapshot } from "../fixtures/recorded-room";

describe("room motion projection", () => {
  it("ordered delivery and a rapid out-of-order burst converge to the same final state", () => {
    const ordered = recordedRoomSnapshot();
    const burst = recordedRoomSnapshot();
    burst.events = [...burst.events].reverse();

    expect(projectRoomMotion(burst)).toEqual(projectRoomMotion(ordered));
  });

  it("reload and reconnect replay reconstruct the same authoritative still frame", () => {
    const snapshot = recordedRoomSnapshot();
    const reconnected = recordedRoomSnapshot();
    reconnected.events = [
      ...reconnected.events.slice(0, 6),
      ...reconnected.events,
      ...reconnected.events.slice(6),
    ];

    expect(projectRoomMotion(reconnected)).toEqual(projectRoomMotion(snapshot));
    expect(projectRoomMotion(snapshot)).toMatchObject({
      eventHead: "d".repeat(64),
      storyStep: "verified",
      activeSeat: null,
      barrierState: "unlocked",
      proofState: "verified",
      regions: {
        header: { ordinal: 1, state: "complete" },
        seats: { ordinal: 2, state: "complete" },
        topology: { ordinal: 3, state: "complete" },
        feed: { ordinal: 4, state: "complete" },
        humanGate: { ordinal: 5, state: "unlocked" },
        proof: { ordinal: 6, state: "verified" },
        actions: { ordinal: 7, state: "complete" },
        artifacts: { ordinal: 8, state: "complete" },
        ledger: { ordinal: 9, state: "complete" },
      },
    });
  });

  it("reduced motion changes choreography only and preserves the full story state", () => {
    const snapshot = recordedRoomSnapshot();
    const full = projectRoomMotion(snapshot);
    const reduced = projectRoomMotion(snapshot, { reducedMotion: true });

    expect(reduced.choreography).toBe("static");
    expect(full.choreography).toBe("progressive");
    expect({ ...reduced, choreography: full.choreography }).toEqual(full);
  });

  it("never opens the approval barrier without a recorded approval event", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.events = snapshot.events.filter((event) => event.kind !== "WARRANT_APPROVED");

    expect(projectRoomMotion(snapshot).barrierState).toBe("sealed");
  });

  it("never claims proof without the trusted verified receipt", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.tests[0] = {
      ...snapshot.artifacts.tests[0],
      receiptSha256: null,
    };

    expect(projectRoomMotion(snapshot).proofState).toBe("unavailable");
  });

  it.each(["VERIFIED", "BLOCKED"] as const)(
    "projects terminal %s incidents as complete records",
    (state) => {
      const snapshot = recordedRoomSnapshot();
      const terminal = {
        ...snapshot,
        incident: { ...snapshot.incident, state },
      };

      expect(projectRoomMotion(terminal).recordState).toBe("complete");
      expect(projectRoomMotion(terminal).regions.header.state).toBe("complete");
      expect(projectRoomMotion(terminal).regions.ledger.state).toBe("complete");
    },
  );

  it("keeps an executing incident record active", () => {
    const snapshot = recordedRoomSnapshot();
    const active = {
      ...snapshot,
      incident: { ...snapshot.incident, state: "EXECUTING" as const },
    };

    expect(projectRoomMotion(active)).toMatchObject({
      recordState: "active",
      regions: {
        header: { ordinal: 1, state: "active" },
        feed: { ordinal: 4, state: "active" },
        ledger: { ordinal: 9, state: "active" },
      },
    });
  });
});
