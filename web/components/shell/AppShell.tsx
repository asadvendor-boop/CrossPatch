"use client";

import { useEffect, useSyncExternalStore } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Archive,
  Boxes,
  CircleCheck,
  FileArchive,
  LayoutDashboard,
  LockKeyhole,
  RadioTower,
  Scale,
  ShieldCheck,
  Siren,
} from "lucide-react";

import { CrossPatchMark } from "@/components/brand/CrossPatchMark";
import { isRecordedReplay, RECORDED_REPLAY_BANNER } from "@/lib/replay";
import { readIncidentId, storeIncidentId, subscribeIncidentId } from "@/lib/session";

import styles from "./AppShell.module.css";

const WORKSPACE_NAV = [
  { label: "Overview", href: "/overview", icon: LayoutDashboard, incidentBound: false },
  { label: "Open incident", href: "/open-incident", icon: Siren, incidentBound: false },
  { label: "Cases", href: "/cases", icon: Archive, incidentBound: false },
  { label: "Doctrine", href: "/doctrine", icon: Scale, incidentBound: false },
  { label: "Approvals", href: "/approvals", icon: ShieldCheck, incidentBound: true },
  { label: "Artifacts & exports", href: "/artifacts", icon: FileArchive, incidentBound: true },
] as const;

function Brand({ href = "/" }: { href?: string }) {
  return (
    <Link className={styles.brand} href={href} aria-label="CrossPatch home">
      <CrossPatchMark className={styles.brandMark} size={42} />
      <span><strong>CrossPatch</strong><small>Failure-first SRE</small></span>
    </Link>
  );
}

function DisabledReplayDestination({
  icon: Icon,
  label,
}: {
  icon: typeof LayoutDashboard;
  label: string;
}) {
  return (
    <li>
      <span aria-disabled="true" title="Unavailable in recorded replay">
        <Icon aria-hidden="true" /><span>{label}</span>
      </span>
    </li>
  );
}

function ReplayShell({
  children,
  pathname,
}: {
  children: React.ReactNode;
  pathname: string;
}) {
  const routeAvailable = (
    pathname === "/cases"
    || pathname.startsWith("/cases/")
    || pathname === "/doctrine"
  );
  return (
    <div className={styles.replayRoot} data-replay-mode="recorded">
      <div className={styles.replayBanner} role="status">
        <CircleCheck aria-hidden="true" />
        <strong>{RECORDED_REPLAY_BANNER}</strong>
      </div>
      <div
        className={`${styles.shell} ${styles.replayShell}`}
        data-testid="app-shell"
        data-shell="replay"
      >
        <aside className={styles.sidebar} data-capture-landmark="primary">
          <Brand href="/cases" />
          <nav className={styles.nav} aria-label="CrossPatch recorded replay">
            <p className={styles.navLabel}>Recorded replay</p>
            <ul>
              <DisabledReplayDestination icon={LayoutDashboard} label="Overview" />
              <DisabledReplayDestination icon={Siren} label="Open incident" />
              <DisabledReplayDestination icon={RadioTower} label="Incident room" />
              <li>
                <Link href="/cases" aria-current={pathname.startsWith("/cases") ? "page" : undefined}>
                  <Archive aria-hidden="true" /><span>Published cases</span>
                </Link>
              </li>
              <li>
                <Link href="/doctrine" aria-current={pathname === "/doctrine" ? "page" : undefined}>
                  <Scale aria-hidden="true" /><span>Doctrine</span>
                </Link>
              </li>
              <DisabledReplayDestination icon={ShieldCheck} label="Approvals" />
              <DisabledReplayDestination icon={FileArchive} label="Artifacts & exports" />
            </ul>
          </nav>
          <section className={styles.trust} data-testid="shell-trust-status" aria-label="Replay boundaries">
            <span>Replay boundary</span>
            <p><CircleCheck aria-hidden="true" />Signed export verified</p>
            <p><LockKeyhole aria-hidden="true" />No mutation capability</p>
            <p><Boxes aria-hidden="true" />No model calls</p>
          </section>
        </aside>
        <div className={styles.content}>
          {routeAvailable ? children : (
            <main id="main-content" className={styles.replayUnavailable} tabIndex={-1}>
              <span>Recorded boundary</span>
              <h1>Unavailable in recorded replay</h1>
              <p>
                This image contains signed published projections only. Live controls,
                credentials, model calls, approvals, exports, and execution are absent.
              </p>
              <Link href="/cases">Published cases remain available</Link>
            </main>
          )}
        </div>
      </div>
    </div>
  );
}

function incidentIdFromPath(pathname: string): string {
  const prefix = "/incidents/";
  if (!pathname.startsWith(prefix)) return "";
  const encoded = pathname.slice(prefix.length);
  if (!encoded) return "";
  try {
    return decodeURIComponent(encoded);
  } catch {
    return "";
  }
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const replayMode = isRecordedReplay();
  const rememberedIncidentId = useSyncExternalStore(
    subscribeIncidentId,
    readIncidentId,
    () => "",
  );
  const pathnameIncidentId = incidentIdFromPath(pathname);
  const activeIncidentId = pathnameIncidentId || rememberedIncidentId;
  const incidentPath = activeIncidentId
    ? `/incidents/${encodeURIComponent(activeIncidentId)}`
    : null;
  const publicLanding = pathname === "/";

  useEffect(() => {
    if (!replayMode && pathnameIncidentId) storeIncidentId(pathnameIncidentId);
  }, [pathnameIncidentId, replayMode]);

  if (replayMode) {
    return <ReplayShell pathname={pathname}>{children}</ReplayShell>;
  }

  if (publicLanding) {
    return (
      <div className={styles.publicShell} data-testid="app-shell" data-shell="public">
        <header className={styles.publicHeader} data-capture-landmark="primary">
          <Brand />
          <nav className={styles.publicNav} aria-label="CrossPatch public">
            <Link href="/overview">Overview</Link>
            <Link href="/cases">Published cases</Link>
            <Link href="/doctrine">Doctrine</Link>
            <Link href="/open-incident">Open incident</Link>
          </nav>
        </header>
        <div className={styles.publicContent}>{children}</div>
      </div>
    );
  }

  return (
    <div className={styles.shell} data-testid="app-shell" data-shell="workspace">
      <aside className={styles.sidebar} data-capture-landmark="primary">
        <Brand />
        <nav className={styles.nav} aria-label="CrossPatch workspace">
          <p className={styles.navLabel}>Workspace</p>
          <ul>
            {WORKSPACE_NAV.slice(0, 2).map(({ label, href, icon: Icon }) => (
              <li key={href}>
                <Link href={href} aria-current={pathname === href ? "page" : undefined}>
                  <Icon aria-hidden="true" /><span>{label}</span>
                </Link>
              </li>
            ))}
            <li>
              {incidentPath ? (
                <Link
                  href={incidentPath}
                  aria-current={pathnameIncidentId ? "page" : undefined}
                >
                  <RadioTower aria-hidden="true" /><span>Incident room</span>
                </Link>
              ) : (
                <span aria-disabled="true" title="Open or join an incident first">
                  <RadioTower aria-hidden="true" /><span>Incident room</span>
                </span>
              )}
            </li>
            {WORKSPACE_NAV.slice(2).map(({ label, href, icon: Icon, incidentBound }) => {
              return (
                <li key={href}>
                  {!incidentBound || activeIncidentId ? (
                    <Link
                      href={href}
                      aria-current={pathname === href ? "page" : undefined}
                      onClick={() => {
                        if (pathnameIncidentId) storeIncidentId(pathnameIncidentId);
                      }}
                    >
                      <Icon aria-hidden="true" /><span>{label}</span>
                    </Link>
                  ) : (
                    <span aria-disabled="true" title="Open or join an incident first">
                      <Icon aria-hidden="true" /><span>{label}</span>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </nav>
        <section className={styles.trust} data-testid="shell-trust-status" aria-label="Trust boundaries">
          <span>Control boundary</span>
          <p><CircleCheck aria-hidden="true" />Sanitized projections only</p>
          <p><LockKeyhole aria-hidden="true" />Human approval required</p>
          <p><Boxes aria-hidden="true" />Sandbox execution</p>
        </section>
      </aside>
      <div className={styles.content}>{children}</div>
    </div>
  );
}
