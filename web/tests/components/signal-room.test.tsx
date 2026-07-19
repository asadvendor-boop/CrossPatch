import { render, screen, within } from "@testing-library/react";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { RecordDerivedHeadline } from "@/components/room/RecordDerivedHeadline";
import { SignalRoom } from "@/components/room/SignalRoom";
import { decodeIncidentRoom, decodeTimelineEvent } from "@/lib/api";
import { projectRoomMotion } from "@/lib/room-motion";
import { buildRoomStory } from "@/lib/room-story";
import { ESCALATION_EXPLANATION, SEAT_ORDER } from "@/lib/tokens";
import { recordedRoomSnapshot } from "../fixtures/recorded-room";

function signalRoom(snapshot = recordedRoomSnapshot(), reducedMotion = false) {
  const story = buildRoomStory(snapshot);
  return (
    <SignalRoom
      snapshot={snapshot}
      story={story}
      motion={projectRoomMotion(snapshot, { reducedMotion })}
    />
  );
}

function renderSignal(snapshot = recordedRoomSnapshot()) {
  const story = buildRoomStory(snapshot);
  render(signalRoom(snapshot));
  return { snapshot, story };
}

function semanticRoomMarkup(container: HTMLElement): string {
  const room = container.querySelector<HTMLElement>("[data-testid='room-experience']");
  if (!room) throw new Error("Signal Room did not render");
  const copy = room.cloneNode(true) as HTMLElement;
  copy.querySelector<HTMLElement>("[data-motion]")?.removeAttribute("data-motion");
  return copy.outerHTML;
}

function regionContract(container: HTMLElement) {
  return [...container.querySelectorAll<HTMLElement>("[data-motion-region]")].map((region) => ({
    name: region.dataset.motionRegion,
    ordinal: region.dataset.motionOrdinal,
    state: region.dataset.motionState,
    activeSeat: region.dataset.motionActiveSeat,
  }));
}

function renderSignalWithConnection(
  snapshot = recordedRoomSnapshot(),
  connectionState: "connecting" | "live" | "reconnecting" | "offline" = "reconnecting",
) {
  const story = buildRoomStory(snapshot);
  render(
    <SignalRoom
      snapshot={snapshot}
      story={story}
      motion={projectRoomMotion(snapshot)}
      connectionState={connectionState}
    />,
  );
}

describe("Signal Room production layout", () => {
  it("is the single selected room treatment and keeps the exact seat order", () => {
    renderSignal();

    expect(screen.getByTestId("room-experience")).toHaveAttribute("data-room-layout", "signal");
    expect([...document.querySelectorAll("[data-room-seat]")].map((seat) => seat.getAttribute("data-seat")))
      .toEqual(SEAT_ORDER);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });

  it("folds every provenance-valid recorded moment into the feed with agent portraits and recorded mentions", () => {
    const { story } = renderSignal();
    const feed = screen.getByTestId("recorded-moment-feed");

    expect(within(feed).getAllByTestId("recorded-dialogue")).toHaveLength(story.moments.length);
    for (const actor of SEAT_ORDER) {
      expect(within(feed).getAllByText(actor, { exact: true }).length).toBeGreaterThan(0);
    }
    expect(within(feed).getAllByText("@Counsel", { exact: true }).length).toBeGreaterThan(0);
    expect(within(feed).getAllByRole("img").length).toBeGreaterThanOrEqual(SEAT_ORDER.length);
    const fallbackAvatars = within(feed).getAllByTestId("non-persona-avatar");
    expect(fallbackAvatars.length).toBeGreaterThan(0);
    for (const avatar of fallbackAvatars) {
      expect(avatar).toHaveTextContent(/^[A-Z0-9]{1,2}$/);
    }
    expect(feed).toHaveAttribute("role", "log");
    expect(feed).toHaveAttribute("aria-live", "polite");
  });

  it("keeps every recorded event visible while unsupported provenance is excluded from dialogue only", () => {
    const snapshot = recordedRoomSnapshot();
    const unsupportedId = snapshot.events[0].id;
    const unsupported = {
      ...snapshot,
      events: snapshot.events.map((event, index) => index === 0
        ? { ...event, eventHash: "unsupported-provenance" }
        : event),
    };
    renderSignal(unsupported);

    expect(screen.getAllByTestId("recorded-event")).toHaveLength(unsupported.events.length);
    const rawCard = screen.getAllByTestId("recorded-event")
      .find((card) => card.dataset.eventId === unsupportedId);
    expect(rawCard).toBeDefined();
    expect(within(rawCard!).getByText("Raw event")).toBeVisible();
    expect(screen.queryByTestId(`moment-${unsupportedId}`)).not.toBeInTheDocument();
  });

  it("renders all 58 events from the sealed two-remand case and exposes the recorded handoff", () => {
    const snapshot = sealedTwoRemandSnapshot();
    renderSignal(snapshot);

    expect(snapshot.events).toHaveLength(58);
    expect(screen.getAllByTestId("recorded-event")).toHaveLength(58);
    expect(screen.getByTestId("record-handoff-spotlight")).toHaveTextContent("@Counsel");
  });

  it("renders escalation prose only when the sentence exists in the recorded public JSON", () => {
    const withoutRecordedSentence = recordedRoomSnapshot();
    const escalation = withoutRecordedSentence.events.find(
      (event) => event.kind === "REASONING_ESCALATED",
    );
    if (!escalation) throw new Error("Recorded fixture is missing its escalation event");
    expect(JSON.parse(escalation.rawPublicJson)).not.toHaveProperty("explanation");

    const first = render(signalRoom(withoutRecordedSentence));
    expect(screen.getByTestId(`moment-${escalation.id}`)).toHaveTextContent(escalation.summary);
    expect(screen.getByTestId(`moment-${escalation.id}`))
      .not.toHaveTextContent(ESCALATION_EXPLANATION);
    expect(screen.getAllByTestId("recorded-event"))
      .toHaveLength(withoutRecordedSentence.events.length);
    first.unmount();

    const recordedPublicEvent = {
      ...JSON.parse(escalation.rawPublicJson),
      explanation: ESCALATION_EXPLANATION,
    };
    const withRecordedSentence = recordedRoomSnapshot();
    withRecordedSentence.events = withRecordedSentence.events.map((event) =>
      event.id === escalation.id ? decodeTimelineEvent(recordedPublicEvent) : event);

    render(signalRoom(withRecordedSentence));
    expect(screen.getByTestId(`moment-${escalation.id}`))
      .toHaveTextContent(ESCALATION_EXPLANATION);
    expect(JSON.parse(
      withRecordedSentence.events.find((event) => event.id === escalation.id)!.rawPublicJson,
    )).toHaveProperty("explanation", ESCALATION_EXPLANATION);
    expect(screen.getAllByTestId("recorded-event"))
      .toHaveLength(withRecordedSentence.events.length);
  });

  it("shows the real split, human boundary, and trusted proof", () => {
    renderSignal();

    expect(screen.getByTestId("delivery-split")).toHaveTextContent("1 receipt");
    expect(screen.getByTestId("delivery-split")).toHaveTextContent("2 jobs");
    expect(screen.getByTestId("delivery-split")).toHaveTextContent("2 deliveries");
    expect(screen.getByRole("separator", { name: "Human approval boundary" })).toBeVisible();
    expect(screen.getByTestId("approval-barrier")).toHaveAttribute("data-state", "unlocked");
    expect(screen.getByTestId("verified-proof")).toHaveTextContent("1 / 1 / 1");
  });

  it("promotes a recorded sanitizer boundary when hostile evidence redaction removes baseline counts", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.evidence = snapshot.artifacts.evidence.map((evidence, index) => (
      index === 0
        ? {
            ...evidence,
            content: "[PRIVATE_AUTHORITY_MATERIAL_REDACTED]",
            tags: [
              "POTENTIAL_INSTRUCTION_REDACTED",
              "PRIVATE_AUTHORITY_MATERIAL_REDACTED",
            ],
          }
        : evidence
    ));

    renderSignal(snapshot);

    const boundary = screen.getByTestId("sanitizer-boundary");
    expect(boundary).toHaveAttribute("data-classification", "UNTRUSTED_EVIDENCE");
    expect(boundary).toHaveTextContent("Untrusted evidence");
    expect(boundary).toHaveTextContent("Potential instruction redacted");
    expect(boundary).toHaveTextContent("Private authority material redacted");
    expect(boundary).toHaveTextContent("ev-baseline");
    expect(boundary).toHaveTextContent("Instruction-like material was removed before model context");
    expect(boundary).not.toHaveTextContent(/hostile log/i);
    expect(screen.queryByText(/baseline counts are unavailable/i)).not.toBeInTheDocument();
    expect(boundary).not.toHaveTextContent("1 / 2 / 2");
  });

  it("does not infer instruction content from an authority-only redaction", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.evidence = snapshot.artifacts.evidence.map((evidence, index) => (
      index === 0
        ? {
            ...evidence,
            content: "[PRIVATE_AUTHORITY_MATERIAL_REDACTED]",
            tags: ["PRIVATE_AUTHORITY_MATERIAL_REDACTED"],
          }
        : evidence
    ));

    renderSignal(snapshot);

    const boundary = screen.getByTestId("sanitizer-boundary");
    expect(boundary).toHaveTextContent("Sensitive authority material was withheld from model context");
    expect(boundary).not.toHaveTextContent(/instruction-like/i);
    expect(boundary).not.toHaveTextContent(/hostile log/i);
  });

  it("requires an exact recorded sanitizer tag before promoting the boundary", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.artifacts.evidence = snapshot.artifacts.evidence.map((evidence, index) => (
      index === 0
        ? {
            ...evidence,
            content: "redacted",
            tags: ["NOT_POTENTIAL_INSTRUCTION_REDACTED_SUFFIX"],
          }
        : evidence
    ));

    renderSignal(snapshot);

    expect(screen.queryByTestId("sanitizer-boundary")).not.toBeInTheDocument();
    expect(screen.getByText(/baseline counts have not been reached in this recorded view/i))
      .toHaveAttribute("data-baseline-state", "not-reached");
  });

  it("keeps an unavailable replay prefix compact without revealing future baseline evidence", () => {
    const snapshot = recordedRoomSnapshot();
    const evidenceCapturedIndex = snapshot.events.findIndex(
      (event) => event.kind === "EVIDENCE_CAPTURED",
    );
    expect(evidenceCapturedIndex).toBeGreaterThan(0);
    const prefix = {
      ...snapshot,
      events: snapshot.events.slice(0, evidenceCapturedIndex),
      artifacts: { ...snapshot.artifacts, evidence: [] },
    };

    renderSignal(prefix);

    const note = screen.getByText(/baseline counts have not been reached in this recorded view/i);
    expect(note).toHaveAttribute("data-baseline-state", "not-reached");
    expect(note).toHaveTextContent("The completed record remains available in the ledger.");
    expect(screen.queryByText("1 receipt")).not.toBeInTheDocument();
    expect(screen.queryByText("2 jobs")).not.toBeInTheDocument();
  });

  it.each(["VERIFIED", "BLOCKED"] as const)(
    "marks the stream record complete for terminal %s incidents even when transport reconnects",
    (state) => {
      const snapshot = recordedRoomSnapshot();
      renderSignalWithConnection({
        ...snapshot,
        incident: { ...snapshot.incident, state },
      });

      expect(screen.getByText("Record complete")).toHaveAttribute("data-stream", "complete");
      expect(screen.getByTestId("room-experience")).toHaveAttribute(
        "data-record-terminal",
        state.toLowerCase(),
      );
      expect(screen.queryByText("reconnecting", { exact: false })).not.toBeInTheDocument();
    },
  );

  it("keeps the live transport state visible for a non-terminal incident", () => {
    const snapshot = recordedRoomSnapshot();
    renderSignalWithConnection({
      ...snapshot,
      incident: { ...snapshot.incident, state: "EXECUTING" },
    });

    expect(screen.getByText("reconnecting")).toHaveAttribute("data-stream", "reconnecting");
    expect(screen.getByTestId("room-experience")).toHaveAttribute("data-record-terminal", "active");
    expect(screen.queryByText("Record complete")).not.toBeInTheDocument();
  });

  it("derives the reusable case headline from recorded counts and verdicts", () => {
    const story = buildRoomStory(recordedRoomSnapshot());
    render(
      <RecordDerivedHeadline
        projectionScope="published"
        story={story}
        title="Webhook duplicate delivery"
      />,
    );

    const headline = screen.getByTestId("record-derived-headline");
    expect(headline).toHaveTextContent("1/2/2 failure");
    expect(headline).toHaveTextContent("1 receipt / 2 jobs / 2 deliveries");
    expect(headline).toHaveTextContent("REMAND ×1");
    expect(headline).toHaveTextContent("CLEAR");
    expect(headline).toHaveTextContent("Verified");
    expect(headline).toHaveTextContent("Webhook duplicate delivery");
    expect(headline).toHaveTextContent("Published record / derived headline");
  });

  it("shows recorded machine state and event kinds as plain language without losing source values", () => {
    renderSignal();

    const state = screen.getByTestId("recorded-room-state");
    expect(state).toHaveTextContent("Verified");
    expect(state).toHaveAttribute("data-recorded-state", "VERIFIED");
    const executionEvent = screen.getAllByTestId("recorded-event")
      .find((event) => event.dataset.eventId === "evt-11");
    expect(executionEvent).toBeDefined();
    expect(executionEvent).toHaveTextContent("Execution started");
    expect(executionEvent).not.toHaveTextContent("EXECUTION STARTED");
  });

  it.each([
    ["operator", "Authorized record / derived headline", "Authorized projection", "Authorized incident artifacts"],
    ["approver", "Authorized record / derived headline", "Authorized projection", "Authorized incident artifacts"],
    ["live_trial", "Private trial record / derived headline", "Private trial projection", "Private trial artifacts"],
  ] as const)(
    "does not describe a %s room as a published projection",
    (viewerRole, expectedScope, expectedProjection, expectedArtifactRegion) => {
      const snapshot = recordedRoomSnapshot();
      snapshot.viewerRole = viewerRole;
      const story = buildRoomStory(snapshot);
      render(
        <SignalRoom
          snapshot={snapshot}
          story={story}
          motion={projectRoomMotion(snapshot)}
          artifactInspector={<div>Authorized proof</div>}
        />,
      );

      const headline = screen.getByTestId("record-derived-headline");
      expect(headline).toHaveTextContent(expectedScope);
      expect(headline).not.toHaveTextContent(/published record/i);
      expect(screen.getByText(expectedProjection, { exact: true })).toBeVisible();
      expect(screen.getByLabelText(expectedArtifactRegion)).toBeVisible();
      expect(screen.queryByText("Published projection", { exact: true })).not.toBeInTheDocument();
      expect(screen.queryByText("Every published event remains visible", { exact: true }))
        .not.toBeInTheDocument();
      expect(screen.queryByText("Raw published JSON", { exact: true })).not.toBeInTheDocument();
    },
  );

  it("retains explicit publication language for the public read-only projection", () => {
    const snapshot = recordedRoomSnapshot();
    snapshot.viewerRole = "read_only";
    const story = buildRoomStory(snapshot);
    render(
      <SignalRoom
        snapshot={snapshot}
        story={story}
        motion={projectRoomMotion(snapshot)}
        artifactInspector={<div>Public proof</div>}
      />,
    );

    expect(screen.getByTestId("record-derived-headline"))
      .toHaveTextContent("Published record / derived headline");
    expect(screen.getByTestId("room-experience")).toHaveTextContent("Published projection");
    expect(screen.getByLabelText("Published incident artifacts")).toBeVisible();
  });

  it("uses hard-edged solid Tracepaper surfaces without gradients", () => {
    const css = ["RoomPrimitives.module.css", "SignalRoom.module.css", "RecordDerivedHeadline.module.css"]
      .map((file) => readFileSync(path.resolve(process.cwd(), "components/room", file), "utf8"))
      .join("\n");

    expect(css).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(css).not.toMatch(/(?:linear|radial|conic|repeating-linear)-gradient\(/i);
    expect(css).toContain("var(--trace)");
    expect(css).toContain("var(--anchor-background)");
  });

  it("ships deterministic state-driven choreography with a static reduced-motion equivalent", () => {
    const css = readFileSync(
      path.resolve(process.cwd(), "components/room/SignalRoom.module.css"),
      "utf8",
    );

    expect(css).toContain('[data-motion="progressive"]');
    expect(css).toContain('[data-motion="static"]');
    expect(css).toContain("@keyframes recorded-arrival");
    expect(css).not.toMatch(/animation-(?:delay|duration):\s*(?:var\(|calc\()/i);
  });

  it("keeps every progressive motion region readable at animation start", () => {
    const css = readFileSync(
      path.resolve(process.cwd(), "components/room/SignalRoom.module.css"),
      "utf8",
    );
    const entranceStart = css.slice(
      css.indexOf("@keyframes recorded-arrival"),
      css.indexOf('.signalShell[data-motion="progressive"] [data-motion-region]'),
    );
    const { container } = render(signalRoom());
    const regions = [...container.querySelectorAll<HTMLElement>("[data-motion-region]")];

    expect(entranceStart).toContain("@keyframes recorded-arrival");
    expect(entranceStart).not.toMatch(/opacity:\s*0\b/i);
    expect(entranceStart).not.toMatch(/visibility:\s*hidden\b/i);
    expect(entranceStart).not.toMatch(/display:\s*none\b/i);
    expect(regions.length).toBeGreaterThan(0);
    for (const region of regions) {
      expect(region).not.toHaveAttribute("hidden");
      expect(region).not.toHaveAttribute("aria-hidden", "true");
      expect(region.textContent?.trim()).not.toBe("");
    }
  });

  it("binds stable motion ordinals and motion-derived state to every semantic region", () => {
    const snapshot = recordedRoomSnapshot();
    const story = buildRoomStory(snapshot);
    const { container } = render(
      <SignalRoom
        snapshot={snapshot}
        story={story}
        motion={projectRoomMotion(snapshot)}
        approvalControls={<button type="button">Approve</button>}
        artifactInspector={<div>Published artifact</div>}
      />,
    );

    expect(regionContract(container)).toEqual([
      { name: "header", ordinal: "1", state: "complete", activeSeat: undefined },
      { name: "seats", ordinal: "2", state: "complete", activeSeat: "none" },
      { name: "topology", ordinal: "3", state: "complete", activeSeat: undefined },
      { name: "feed", ordinal: "4", state: "complete", activeSeat: undefined },
      { name: "human-gate", ordinal: "5", state: "unlocked", activeSeat: undefined },
      { name: "proof", ordinal: "6", state: "verified", activeSeat: undefined },
      { name: "actions", ordinal: "7", state: "complete", activeSeat: undefined },
      { name: "artifacts", ordinal: "8", state: "complete", activeSeat: undefined },
      { name: "ledger", ordinal: "9", state: "complete", activeSeat: undefined },
    ]);
  });

  it("renders one convergent semantic DOM for ordered, reordered, and duplicate reload data", () => {
    const ordered = recordedRoomSnapshot();
    const replayed = recordedRoomSnapshot();
    replayed.events = [
      ...replayed.events.slice().reverse(),
      ...replayed.events.slice(0, 8),
      ...replayed.events.slice(4, 12),
    ];

    const orderedRender = render(signalRoom(ordered));
    const orderedMarkup = semanticRoomMarkup(orderedRender.container);
    orderedRender.unmount();
    const replayedRender = render(signalRoom(replayed));

    expect(semanticRoomMarkup(replayedRender.container)).toBe(orderedMarkup);
  });

  it("converges after burst delivery and tab-return replay to the same fresh final projection", () => {
    const finalSnapshot = recordedRoomSnapshot();
    const initialSnapshot = recordedRoomSnapshot();
    initialSnapshot.incident = { ...initialSnapshot.incident, state: "EXECUTING" };
    initialSnapshot.events = initialSnapshot.events.slice(0, 9);
    initialSnapshot.artifacts = {
      ...initialSnapshot.artifacts,
      tests: initialSnapshot.artifacts.tests.map((test) => ({
        ...test,
        state: "running" as const,
        receiptSha256: null,
      })),
    };

    const recovered = render(signalRoom(initialSnapshot));
    recovered.rerender(signalRoom({
      ...finalSnapshot,
      events: [
        ...finalSnapshot.events.slice().reverse(),
        ...finalSnapshot.events.slice(0, 6),
      ],
    }));
    const recoveredMarkup = semanticRoomMarkup(recovered.container);
    recovered.unmount();
    const fresh = render(signalRoom(finalSnapshot));

    expect(semanticRoomMarkup(fresh.container)).toBe(recoveredMarkup);
  });

  it("preserves the exact semantic end state when reduced motion removes choreography", () => {
    const snapshot = recordedRoomSnapshot();
    const progressive = render(signalRoom(snapshot));
    const progressiveRegions = regionContract(progressive.container);
    const progressiveMarkup = semanticRoomMarkup(progressive.container);
    expect(progressive.container.querySelector("[data-motion]"))
      .toHaveAttribute("data-motion", "progressive");
    progressive.unmount();

    const reduced = render(signalRoom(snapshot, true));
    expect(reduced.container.querySelector("[data-motion]"))
      .toHaveAttribute("data-motion", "static");
    expect(regionContract(reduced.container)).toEqual(progressiveRegions);
    expect(semanticRoomMarkup(reduced.container)).toBe(progressiveMarkup);
  });

  it("derives authority and display state without timer-driven transitions", () => {
    const sources = ["lib/room-motion.ts", "components/room/SignalRoom.tsx"]
      .map((file) => readFileSync(path.resolve(process.cwd(), file), "utf8"))
      .join("\n");

    expect(sources).not.toMatch(/\bset(?:Timeout|Interval)\s*\(/);
    expect(sources).not.toMatch(/\brequestAnimationFrame\s*\(/);
  });
});

function sealedTwoRemandSnapshot() {
  const archive = path.resolve(
    process.cwd(),
    "../artifacts/verification/paced-batches/paced-20260714T103240Z/run-04/real-model-cases/inc_e032c6cde04f44b8a5dc6371c8c6f690.zip",
  );
  const member = "incidents/inc_e032c6cde04f44b8a5dc6371c8c6f690/case-file.json";
  const publicCase = JSON.parse(execFileSync("unzip", ["-p", archive, member], { encoding: "utf8" }));
  return decodeIncidentRoom(publicCase);
}
