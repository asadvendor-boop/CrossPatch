import type { EventVisualState, IncidentState, SeatRunState } from "@/lib/types";
import { formatPublicEnum } from "@/lib/presentation";

type BadgeState = EventVisualState | IncidentState | SeatRunState | "live" | "connecting" | "reconnecting" | "offline";

interface StatusBadgeProps {
  state: BadgeState;
  label?: string;
}

function tone(state: BadgeState): string {
  const value = state.toLowerCase();
  if (/fail|error|abstain|block|offline|reject/.test(value)) return "failure";
  if (/verified|pass|clear|complete|live|approved/.test(value)) return "success";
  if (/warning|remand|pending|connecting|reconnecting|escalation/.test(value)) return "warning";
  if (/active|working|executing|running|reproducing|analyzing|patching/.test(value)) return "active";
  return "neutral";
}

export function StatusBadge({ state, label }: StatusBadgeProps) {
  const recordedLabel = label ?? state;
  return (
    <span
      className={`status-badge status-badge--${tone(state)}`}
      data-recorded-state={state}
      data-tone={tone(state)}
    >
      <span className="status-badge__dot" aria-hidden="true" />
      {formatPublicEnum(recordedLabel)}
    </span>
  );
}
