import { ArrowRight } from "lucide-react";

import type { RoomStory } from "@/lib/room-story";

import styles from "./RecordDerivedHeadline.module.css";

export interface RecordHeadlineParts {
  baseline: string;
  remand: string;
  verdict: string;
  outcome: string;
}

export type ProjectionScope = "published" | "authorized" | "live-trial";

const SCOPE_COPY: Record<ProjectionScope, { eyebrow: string; detail: string }> = {
  published: {
    eyebrow: "Published record / derived headline",
    detail: "Every headline term is derived from the published record.",
  },
  authorized: {
    eyebrow: "Authorized record / derived headline",
    detail: "Every headline term is derived from the authorized incident record.",
  },
  "live-trial": {
    eyebrow: "Private trial record / derived headline",
    detail: "Every headline term is derived from this private trial record.",
  },
};

export function deriveRecordHeadline(story: RoomStory): RecordHeadlineParts {
  const remandCount = story.moments.filter(
    (moment) => moment.kind === "VERDICT" && moment.verdict === "REMAND",
  ).length;
  const clearCount = story.moments.filter(
    (moment) => moment.kind === "VERDICT" && moment.verdict === "CLEAR",
  ).length;
  const counts = story.baselineCounts;

  return {
    baseline: counts
      ? `${counts.receipts}/${counts.jobs}/${counts.deliveries} failure · ${counts.receipts} ${counts.receipts === 1 ? "receipt" : "receipts"} / ${counts.jobs} ${counts.jobs === 1 ? "job" : "jobs"} / ${counts.deliveries} ${counts.deliveries === 1 ? "delivery" : "deliveries"}`
      : "Failure unproven",
    remand: remandCount ? `REMAND ×${remandCount}` : "No REMAND",
    verdict: clearCount ? "CLEAR" : "No CLEAR",
    outcome: story.proof.state === "verified" ? "Verified" : "Proof pending",
  };
}

export function RecordDerivedHeadline({
  projectionScope,
  story,
  title,
}: {
  projectionScope: ProjectionScope;
  story: RoomStory;
  title: string;
}) {
  const parts = deriveRecordHeadline(story);
  const copy = SCOPE_COPY[projectionScope];

  return (
    <div className={styles.headline} data-testid="record-derived-headline">
      <span className={styles.eyebrow}>{copy.eyebrow}</span>
      <h2>
        <span data-state="failed">{parts.baseline}</span>
        <ArrowRight aria-hidden="true" />
        <span data-state="warning">{parts.remand}</span>
        <ArrowRight aria-hidden="true" />
        <span data-state="clear">{parts.verdict}</span>
        <ArrowRight aria-hidden="true" />
        <span data-state="verified">{parts.outcome}</span>
      </h2>
      <p>{title}. {copy.detail}</p>
    </div>
  );
}
