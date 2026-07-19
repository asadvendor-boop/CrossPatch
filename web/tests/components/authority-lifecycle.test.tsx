import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuthorityLifecycle } from "@/components/exhibits/AuthorityLifecycle";
import type { AuthorityLifecycleItem } from "@/lib/case-exhibits";

const hash = (character: string) => character.repeat(64);

describe("consumed authority lifecycle", () => {
  it("renders issued, approved, consumed, failed, and successor authority from records", () => {
    const items: AuthorityLifecycleItem[] = [
      {
        warrantId: "war-first",
        canonicalSha256: hash("a"),
        issuedAt: "2026-07-16T10:00:00Z",
        approvedAt: "2026-07-16T10:01:00Z",
        approver: "operator-1",
        consumedAt: "2026-07-16T10:01:05Z",
        failureAt: "2026-07-16T10:01:10Z",
        receiptIds: ["receipt-failed"],
        executionStatus: "TEST_FAILED",
        successorWarrantId: "war-second",
        successorCanonicalSha256: hash("b"),
      },
      {
        warrantId: "war-second",
        canonicalSha256: hash("b"),
        issuedAt: "2026-07-16T10:01:15Z",
        approvedAt: null,
        approver: null,
        consumedAt: null,
        failureAt: null,
        receiptIds: [],
        executionStatus: "NOT_EXECUTED",
        successorWarrantId: null,
        successorCanonicalSha256: null,
      },
    ];

    render(<AuthorityLifecycle items={items} />);

    const region = screen.getByRole("region", { name: "Consumed authority lifecycle" });
    expect(region).toHaveTextContent("Issued");
    expect(region).toHaveTextContent("Approved by operator-1");
    expect(region).toHaveTextContent("Consumed");
    expect(region).toHaveTextContent("Candidate failed");
    expect(region).toHaveTextContent("Test failed");
    expect(region).not.toHaveTextContent("TEST_FAILED");
    expect(region).toHaveTextContent("Fresh approval required");
    const records = within(region).getAllByTestId("authority-record");
    expect(records).toHaveLength(2);
    expect(records[0]).toHaveTextContent(hash("a"));
    expect(records[0]).toHaveTextContent(hash("b"));
    expect(records[1]).toHaveTextContent("Awaiting its own approval");
  });

  it("does not invent an approval or failure step when the record omits them", () => {
    render(<AuthorityLifecycle items={[{
      warrantId: "war-pending",
      canonicalSha256: hash("c"),
      issuedAt: "2026-07-16T10:00:00Z",
      approvedAt: null,
      approver: null,
      consumedAt: null,
      failureAt: null,
      receiptIds: [],
      executionStatus: "NOT_EXECUTED",
      successorWarrantId: null,
      successorCanonicalSha256: null,
    }]} />);

    const region = screen.getByRole("region", { name: "Consumed authority lifecycle" });
    expect(region).toHaveTextContent("Issued");
    expect(region).toHaveTextContent("Awaiting its own approval");
    expect(region).not.toHaveTextContent("Approved by");
    expect(region).not.toHaveTextContent("Candidate failed");
  });
});
