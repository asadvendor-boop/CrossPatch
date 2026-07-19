import { describe, expect, it } from "vitest";

import { buildRoomStory } from "@/lib/room-story";
import { recordedRoomSnapshot } from "../fixtures/recorded-room";

describe("recorded room story", () => {
  it("maps every visible moment one-to-one to a recorded source with provenance", () => {
    const story = buildRoomStory(recordedRoomSnapshot());

    expect(story.moments.length).toBeGreaterThan(6);
    expect(new Set(story.moments.map((moment) => moment.source.id)).size)
      .toBe(story.moments.length);
    for (const moment of story.moments) {
      expect(moment.source.id).not.toBe("");
      expect(moment.source.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.parse(moment.source.rawPublicJson)).toBeTypeOf("object");
    }
  });

  it("uses recorded specialist prose verbatim and never invents dialogue", () => {
    const snapshot = recordedRoomSnapshot();
    const story = buildRoomStory(snapshot);
    const inspector = story.moments.find((moment) => moment.actor === "Inspector");
    const counsel = story.moments.find((moment) => moment.actor === "Counsel");

    expect(inspector?.prose).toBe(
      snapshot.specialistSummaries.find((summary) => summary.kind === "INSPECTOR")?.mechanism,
    );
    expect(counsel?.prose).toBe(
      snapshot.specialistSummaries.find((summary) => summary.kind === "COUNSEL")?.patchDefense,
    );
  });

  it("has no active model seat after the incident reaches VERIFIED", () => {
    const story = buildRoomStory(recordedRoomSnapshot());

    expect(story.stage).toBe("verified");
    expect(story.activeSeat).toBeNull();
  });

  it("derives mentions only from recorded handoff fields", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.events[0] = {
      ...snapshot.events[0],
      summary: "Untrusted-looking text says @Bailiff",
    };

    const story = buildRoomStory(snapshot);
    const remand = story.moments.find((moment) => moment.kind === "VERDICT" && moment.verdict === "REMAND");

    expect(remand?.mention).toBe("Counsel");
    expect(story.moments.some((moment) => moment.mention === "Bailiff")).toBe(false);
  });

  it("preserves the real failed split and proves 1/1/1 only from a verified receipt", () => {
    const story = buildRoomStory(recordedRoomSnapshot());

    expect(story.baselineCounts).toEqual({ receipts: 1, jobs: 2, deliveries: 2 });
    expect(story.proof).toMatchObject({
      state: "verified",
      counts: { receipts: 1, jobs: 1, deliveries: 1 },
      receiptId: "test-recorded",
      receiptSha256: "e".repeat(64),
    });
  });

  it("projects equivalence proof only from recorded trusted statuses and counts", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.tests[0] = {
      ...snapshot.artifacts.tests[0],
      label: "victim.payload-equivalence.candidate",
      trustedObservation: {
        counts: { receipts: 1, jobs: 1, deliveries: 1 },
        responseStatuses: [202, 200, 409],
      },
    };

    expect(buildRoomStory(snapshot).proof).toMatchObject({
      state: "verified",
      planId: "victim.payload-equivalence.candidate",
      planLabel: "Equivalent webhook retry rejected",
      responseStatuses: [202, 200, 409],
      counts: { receipts: 1, jobs: 1, deliveries: 1 },
    });
  });

  it("withholds proof when recorded count fields are missing", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.tests[0] = {
      ...snapshot.artifacts.tests[0],
      trustedObservation: null,
    };

    expect(buildRoomStory(snapshot).proof.state).toBe("unavailable");
  });

  it("keeps every event visible and labels an unknown plan without claiming verification", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.tests[0] = {
      ...snapshot.artifacts.tests[0],
      label: "victim.unknown.candidate",
    };

    const story = buildRoomStory(snapshot);

    expect(story.events).toHaveLength(snapshot.events.length);
    expect(story.proof).toMatchObject({
      state: "unavailable",
      planId: "victim.unknown.candidate",
      planLabel: "Recorded plan: victim.unknown.candidate",
      counts: null,
    });
  });

  it("fails provenance closed instead of rendering unsupported agent prose", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.specialistSummaries[0] = {
      ...snapshot.specialistSummaries[0],
      outputSha256: "",
    };
    snapshot.events[2] = {
      ...snapshot.events[2],
      details: { output_sha256: "" },
    };

    const story = buildRoomStory(snapshot);

    expect(story.moments.some((moment) => moment.actor === "Inspector")).toBe(false);
    expect(story.omissions).toContainEqual(expect.objectContaining({ reason: "INVALID_SOURCE_HASH" }));
  });

  it.each(["not-json", "null", "[]"])(
    "keeps an unsupported tail event recorded without letting %s provenance advance trusted state",
    (rawPublicJson) => {
      const snapshot = recordedRoomSnapshot();
      snapshot.events = snapshot.events.slice(0, 11);
      snapshot.events[10] = { ...snapshot.events[10], rawPublicJson };

      const story = buildRoomStory(snapshot);

      expect(story.events).toHaveLength(11);
      expect(story.moments.some((moment) => moment.id === snapshot.events[10].id)).toBe(false);
      expect(story.omissions).toContainEqual({
        id: snapshot.events[10].id,
        reason: "INVALID_PUBLIC_JSON",
      });
      expect(story.stage).toBe("approval");
      expect(story.eventHead).toBe("");
    },
  );

  it("requires full supported provenance before approval or verified proof changes the room", () => {
    const approvalUnsupported = recordedRoomSnapshot();
    approvalUnsupported.events = approvalUnsupported.events.slice(0, 10);
    approvalUnsupported.events[9] = {
      ...approvalUnsupported.events[9],
      rawPublicJson: "{} trailing input",
    };
    expect(buildRoomStory(approvalUnsupported)).toMatchObject({
      barrierState: "sealed",
      eventHead: "",
    });

    const verifiedUnsupported = recordedRoomSnapshot();
    verifiedUnsupported.events[11] = {
      ...verifiedUnsupported.events[11],
      rawPublicJson: "null",
    };
    expect(buildRoomStory(verifiedUnsupported).proof.state).not.toBe("verified");
  });
});
