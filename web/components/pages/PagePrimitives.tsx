import { Fragment } from "react";
import Link from "next/link";
import { ArrowRight, ShieldCheck, Sparkles } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { PersonaPortrait } from "@/components/PersonaPortrait";
import { DEFAULT_SEATS } from "@/lib/tokens";

import styles from "./AppPages.module.css";

const SEAT_TONES = ["mint", "cyan", "violet", "amber", "blue"] as const;

interface PageIntroProps {
  eyebrow: string;
  title: string;
  summary: string;
  icon: LucideIcon;
}

export function PageIntro({ eyebrow, title, summary, icon: Icon }: PageIntroProps) {
  return (
    <header className={styles.pageIntro}>
      <div className={styles.introIcon} aria-hidden="true"><Icon /></div>
      <div className={styles.introCopy}>
        <div className={styles.eyebrowRow}>
          <span className={styles.eyebrow}>{eyebrow}</span>
        </div>
        <h1>{title}</h1>
        <p>{summary}</p>
      </div>
    </header>
  );
}

export function SeatStrip({ landing = false }: { landing?: boolean }) {
  return (
    <ol className={landing ? styles.landingSeats : styles.seatStrip} aria-label="Five model-driven seats">
      {DEFAULT_SEATS.map((seat, index) => (
        <Fragment key={seat.name}>
          {!landing && seat.name === "Bailiff" ? (
            <li
              className={styles.overviewGate}
              role="separator"
              aria-label="Human approval boundary"
            >
              <span>Magistrate</span>
              <strong>Human gate</strong>
              <span>Bailiff</span>
            </li>
          ) : null}
          <li
            data-testid={landing ? "landing-seat" : undefined}
            data-seat-tone={SEAT_TONES[index]}
          >
            <span className={styles.seatIndex} aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
            <PersonaPortrait seat={seat.name} />
            <div>
              <strong>{seat.name}<Sparkles className={styles.seatGlyph} aria-hidden="true" /></strong>
              <span className={styles.seatModel}>{seat.model}</span>
              {!landing ? (
                <>
                  <p>{seat.role}</p>
                  <small className={styles.seatRuntime}>
                    Effort {seat.effort} · Escalations {seat.escalationCount}/2
                  </small>
                </>
              ) : null}
            </div>
          </li>
        </Fragment>
      ))}
    </ol>
  );
}

export function PrimaryLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link className={styles.primaryLink} href={href}>
      {children}<ArrowRight aria-hidden="true" />
    </Link>
  );
}

export function SecondaryLink({ href, children }: { href: string; children: React.ReactNode }) {
  return <Link className={styles.secondaryLink} href={href}>{children}</Link>;
}

export function BoundaryNote() {
  return (
    <p className={styles.boundaryNote}>
      <ShieldCheck aria-hidden="true" />
      Sanitized projections in; hash-bound approval and sandbox-confined execution out.
    </p>
  );
}
