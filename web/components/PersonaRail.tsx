import { ApprovalGate } from "./ApprovalGate";
import { PersonaPortrait } from "./PersonaPortrait";
import { StatusBadge } from "./StatusBadge";
import { DEFAULT_SEATS, SEAT_ORDER } from "@/lib/tokens";
import type { IncidentState, PendingWarrant, SeatName, SeatView } from "@/lib/types";

interface PersonaRailProps {
  seats: readonly SeatView[];
  pendingWarrant: PendingWarrant | null;
  incidentState?: IncidentState;
  approvalCredentialsAvailable?: boolean;
  liveTrial?: boolean;
  onApprove?: (id: string) => Promise<void>;
  onReject?: (id: string, reason: string) => Promise<void>;
  onRequestRevision?: (id: string, comment: string) => Promise<void>;
}

interface RailSeat {
  seat: SeatView;
  available: boolean;
}

function exactSeats(seats: readonly SeatView[]): RailSeat[] {
  const updates = new Map(seats.map((seat) => [seat.name, seat]));
  return SEAT_ORDER.map((name) => {
    const baseline = DEFAULT_SEATS.find((seat) => seat.name === name) as SeatView;
    const update = updates.get(name);
    return update
      ? {
          seat: {
            ...baseline,
            effort: update.effort,
            escalationCount: update.escalationCount,
            state: update.state,
          },
          available: true,
        }
      : { seat: { ...baseline, state: "unavailable" }, available: false };
  });
}

function SeatCard({ seat, index, available }: RailSeat & { index: number }) {
  return (
    <article
      className={`seat-card seat-card--${seat.state} panel-corners`}
      data-testid={`seat-${seat.name.toLowerCase()}`}
    >
      <div className="seat-card__index" aria-hidden="true">{String(index + 1).padStart(2, "0")}</div>
      <PersonaPortrait seat={seat.name as SeatName} />
      <div className="seat-card__body">
        <div className="seat-card__title-row">
          <h2>{seat.name}</h2>
          <StatusBadge state={seat.state} label={available ? undefined : "Unavailable"} />
        </div>
        <p className="seat-card__role single-line" data-testid="seat-role" title={seat.role}>{seat.role}</p>
        <p className="seat-card__model">{seat.model}</p>
        <p className="seat-card__rationale" data-testid="tier-rationale">{seat.tierRationale}</p>
        {available ? (
          <div className="seat-card__metrics">
            <span>Effort: <strong>{seat.effort}</strong></span>
            <span>Escalations: <strong>{seat.escalationCount}/2</strong></span>
          </div>
        ) : (
          <div className="seat-card__metrics" aria-label={`${seat.name} live status unavailable`}>
            <span>Live seat data unavailable</span>
            <span>Effort: <strong>unavailable</strong></span>
            <span>Escalations: <strong>unavailable</strong></span>
          </div>
        )}
      </div>
    </article>
  );
}

export function PersonaRail({
  seats,
  pendingWarrant,
  incidentState = "OPEN",
  approvalCredentialsAvailable = false,
  liveTrial = false,
  onApprove,
  onReject,
  onRequestRevision,
}: PersonaRailProps) {
  const ordered = exactSeats(seats);
  const magistrateIndex = ordered.findIndex(({ seat }) => seat.name === "Magistrate");
  const beforeGate = ordered.slice(0, magistrateIndex + 1);
  const afterGate = ordered.slice(magistrateIndex + 1);

  return (
    <aside className="persona-rail" data-testid="persona-rail" aria-label="Incident analysis seats and approval gate">
      <div className="rail-heading">
        <span className="coordinate-label">SEAT RAIL / 05</span>
        <span className="rail-heading__rule" aria-hidden="true" />
      </div>
      {beforeGate.map(({ seat, available }, index) => (
        <SeatCard key={seat.name} seat={seat} available={available} index={index} />
      ))}
      <ApprovalGate
        warrant={pendingWarrant}
        incidentState={incidentState}
        approvalCredentialsAvailable={approvalCredentialsAvailable}
        liveTrial={liveTrial}
        onApprove={onApprove}
        onReject={onReject}
        onRequestRevision={onRequestRevision}
      />
      {afterGate.map(({ seat, available }) => (
        <SeatCard
          key={seat.name}
          seat={seat}
          available={available}
          index={SEAT_ORDER.indexOf(seat.name)}
        />
      ))}
    </aside>
  );
}
