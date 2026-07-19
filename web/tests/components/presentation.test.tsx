import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { InspectorPanel } from "@/components/InspectorPanel";
import { AuthorityLifecycle } from "@/components/exhibits/AuthorityLifecycle";
import { SignalRoom } from "@/components/room/SignalRoom";
import { formatPublicEnum, formatSeverity } from "@/lib/presentation";
import { projectRoomMotion } from "@/lib/room-motion";
import { buildRoomStory } from "@/lib/room-story";
import { recordedRoomSnapshot } from "../fixtures/recorded-room";

describe("public machine-value presentation", () => {
  it.each([
    ["APPROVAL_PENDING", "Approval pending"],
    ["SOME_NEW_MACHINE_STATE", "Some new machine state"],
    ["VERIFIED", "Verified"],
    ["CLEAR", "CLEAR"],
    ["REMAND", "REMAND"],
    ["BLOCK", "BLOCK"],
    ["ABSTAIN", "ABSTAIN"],
  ])("renders %s as %s", (recorded, visible) => {
    expect(formatPublicEnum(recorded)).toBe(visible);
  });

  it("renders missing severity as not recorded without changing a recorded severity", () => {
    expect(formatSeverity("UNSET")).toBe("not recorded");
    expect(formatSeverity("")).toBe("not recorded");
    expect(formatSeverity("SEV-2")).toBe("SEV-2");
  });

  it("keeps uppercase-snake values out of the room and exhibit surfaces", () => {
    const snapshot = recordedRoomSnapshot();
    const story = buildRoomStory(snapshot);
    const { container } = render(
      <>
        <SignalRoom
          snapshot={snapshot}
          story={story}
          motion={projectRoomMotion(snapshot, { reducedMotion: true })}
          artifactInspector={(
            <InspectorPanel
              artifacts={snapshot.artifacts}
              summaries={snapshot.specialistSummaries}
              warrants={snapshot.warrants}
            />
          )}
        />
        <AuthorityLifecycle items={[{
          warrantId: "war-format-contract",
          canonicalSha256: "a".repeat(64),
          issuedAt: "2026-07-16T10:00:00Z",
          approvedAt: "2026-07-16T10:01:00Z",
          approver: "operator",
          consumedAt: "2026-07-16T10:02:00Z",
          failureAt: "2026-07-16T10:03:00Z",
          receiptIds: ["receipt-1"],
          executionStatus: "TEST_FAILED",
          successorWarrantId: null,
          successorCanonicalSha256: null,
        }]} />
      </>,
    );
    const leaked: string[] = [];
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const parent = node.parentElement;
      if (!parent || parent.closest("pre, code, [data-verdict]")) continue;
      leaked.push(...(node.textContent?.match(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g) ?? []));
    }

    expect(leaked).toEqual([]);
  });
});
