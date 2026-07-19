import Link from "next/link";

import { PublishedCaseEntryLink } from "./PublishedCaseEntryLink";
import styles from "./ZeroCredentialGuide.module.css";

type Surface = "open" | "approvals" | "artifacts";

const SURFACE_COPY: Record<Surface, {
  heading: string;
  state: string;
  publicAction: string;
  publicAnchor: string;
}> = {
  open: {
    heading: "Choose a real access path",
    state: "Operators and invited live-trial judges enter with separately issued credentials. No credential is bundled into this page.",
    publicAction: "Watch a published incident replay",
    publicAnchor: "recorded-replay",
  },
  approvals: {
    heading: "Approval is incident-bound",
    state: "No incident is selected in this browser tab. No incident credential is present. Approval controls remain unavailable until an authorized incident is selected.",
    publicAction: "Inspect a published warrant",
    publicAnchor: "warrant-anatomy",
  },
  artifacts: {
    heading: "Artifacts are record-bound",
    state: "No incident is selected in this browser tab. No incident credential is present. No artifact availability is inferred until an authorized incident is selected.",
    publicAction: "Inspect published recorded artifacts",
    publicAnchor: "recorded-artifacts",
  },
};

export function ZeroCredentialGuide({ surface }: { surface: Surface }) {
  const copy = SURFACE_COPY[surface];

  return (
    <section className={styles.guide} aria-label="No incident credential">
      <div className={styles.copy}>
        <span className={styles.eyebrow}>No incident credential</span>
        <h2>{copy.heading}</h2>
        <p>{copy.state}</p>
        <div className={styles.actions}>
          <PublishedCaseEntryLink className={styles.secondary} anchor={copy.publicAnchor}>
            {copy.publicAction}
          </PublishedCaseEntryLink>
          <Link className={styles.primary} href="/open-incident#live-trial-entry">
            Run a private live trial
          </Link>
        </div>
      </div>
      <aside className={styles.boundary} aria-label="Live-trial boundary">
        <strong>Fresh inference, bounded authority</strong>
        <p>
          A live-trial credential can open and decide only its own incident. Fresh model output is
          protected by a global model-spend cap and per-credential rate limit; the judge approves
          the exact warrant before sandbox-confined execution.
        </p>
        <p>Trials never publish and never enter the shared case gallery.</p>
      </aside>
    </section>
  );
}
