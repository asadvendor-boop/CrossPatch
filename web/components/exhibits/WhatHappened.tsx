import { FileText } from "lucide-react";

import styles from "./WhatHappened.module.css";

export function WhatHappened({
  sentences,
  compact = false,
}: {
  sentences: readonly string[];
  compact?: boolean;
}) {
  if (!sentences.length) return null;

  return (
    <section
      className={`${styles.explanation} ${compact ? styles.compact : ""}`}
      aria-label="What happened"
      data-testid="what-happened"
    >
      <header>
        <FileText aria-hidden="true" />
        <h2>What happened</h2>
        <span>Recorded facts only</span>
      </header>
      <ol>
        {sentences.map((sentence, index) => (
          <li key={`${index}-${sentence}`}>{sentence}</li>
        ))}
      </ol>
    </section>
  );
}
