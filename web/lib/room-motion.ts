import { buildRoomStory } from "./room-story";
import type { IncidentRoomSnapshot, IncidentState, SeatName, TimelineEvent } from "./types";

export type RoomMotionRegionState =
  | "pending"
  | "active"
  | "complete"
  | "unavailable"
  | "sealed"
  | "unlocked"
  | "verified";

export interface RoomMotionRegion {
  ordinal: number;
  state: RoomMotionRegionState;
}

export interface RoomMotionRegions {
  header: RoomMotionRegion;
  seats: RoomMotionRegion;
  topology: RoomMotionRegion;
  feed: RoomMotionRegion;
  humanGate: RoomMotionRegion;
  proof: RoomMotionRegion;
  actions: RoomMotionRegion;
  artifacts: RoomMotionRegion;
  ledger: RoomMotionRegion;
}

export interface RoomMotionState {
  eventHead: string;
  eventCount: number;
  storyStep: "evidence" | "analysis" | "repair" | "review" | "approval" | "execution" | "verified";
  activeSeat: SeatName | null;
  artifactId: string | null;
  barrierState: "sealed" | "pending" | "unlocked";
  proofState: "pending" | "verified" | "unavailable";
  recordState: "active" | "complete";
  regions: RoomMotionRegions;
  choreography: "progressive" | "static";
}

export function isRecordComplete(state: IncidentState): boolean {
  return state === "VERIFIED" || state === "BLOCKED";
}

function compareEvents(left: TimelineEvent, right: TimelineEvent): number {
  return left.sequence - right.sequence
    || left.id.localeCompare(right.id)
    || left.eventHash.localeCompare(right.eventHash)
    || left.rawPublicJson.localeCompare(right.rawPublicJson);
}

function canonicalEvents(events: readonly TimelineEvent[]): TimelineEvent[] {
  const ordered = [...events].sort(compareEvents);
  const unique = new Map<string, TimelineEvent>();
  for (const event of ordered) {
    if (!unique.has(event.id)) unique.set(event.id, event);
  }
  return [...unique.values()];
}

export function canonicalRoomSnapshot(snapshot: IncidentRoomSnapshot): IncidentRoomSnapshot {
  return { ...snapshot, events: canonicalEvents(snapshot.events) };
}

function region(ordinal: number, state: RoomMotionRegionState): RoomMotionRegion {
  return { ordinal, state };
}

export function projectRoomMotion(
  snapshot: IncidentRoomSnapshot,
  options: { reducedMotion?: boolean } = {},
): RoomMotionState {
  const canonicalSnapshot = canonicalRoomSnapshot(snapshot);
  const story = buildRoomStory(canonicalSnapshot);
  const latestMoment = story.moments.at(-1);
  const recordState = isRecordComplete(snapshot.incident.state) ? "complete" : "active";
  const artifactId = story.proof.receiptId ?? latestMoment?.source.id ?? null;
  return {
    eventHead: story.eventHead,
    eventCount: story.eventCount,
    storyStep: story.stage,
    activeSeat: story.activeSeat,
    artifactId,
    barrierState: story.barrierState,
    proofState: story.proof.state,
    recordState,
    regions: {
      header: region(1, recordState),
      seats: region(2, story.activeSeat ? "active" : recordState === "complete" ? "complete" : "pending"),
      topology: region(3, story.baselineCounts
        ? story.stage === "evidence" ? "active" : "complete"
        : "unavailable"),
      feed: region(4, story.eventCount ? recordState : "pending"),
      humanGate: region(5, story.barrierState),
      proof: region(6, story.proof.state),
      actions: region(7, recordState === "complete" ? "complete" : story.barrierState),
      artifacts: region(8, artifactId ? "complete" : "pending"),
      ledger: region(9, recordState),
    },
    choreography: options.reducedMotion ? "static" : "progressive",
  };
}
