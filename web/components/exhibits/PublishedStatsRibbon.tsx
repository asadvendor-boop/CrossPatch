import { ArchiveRestore, BookOpenCheck } from "lucide-react";

import styles from "./PublishedStatsRibbon.module.css";

export function PublishedStatsRibbon({
  hasHostileEvidence = false,
  publishedCount,
  status = publishedCount === null ? "unavailable" : "ready",
}: {
  hasHostileEvidence?: boolean;
  publishedCount: number | null;
  status?: "ready" | "loading" | "unavailable";
}) {
  const publication = status === "ready" && publishedCount !== null
    ? `${publishedCount} ${publishedCount === 1 ? "case" : "cases"} explicitly published`
    : status === "loading"
      ? "Reading published count"
      : "Published count unavailable";

  return (
    <section
      className={styles.ribbon}
      aria-label="Verification cohort and publication scope"
      data-testid="published-stats-ribbon"
    >
      <ArchiveRestore aria-hidden="true" />
      <div>
        <strong>
          {hasHostileEvidence
            ? "Routine repairs through hostile-evidence due process"
            : "Verified repairs through human-governed due process"}
        </strong>
        <p>
          Sealed 10-run cohort, verified · {publication}. Publication is a deliberate
          subset of that cohort.
        </p>
      </div>
      <span><BookOpenCheck aria-hidden="true" />Public index</span>
    </section>
  );
}
