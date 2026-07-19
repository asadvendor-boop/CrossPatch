interface EmptyStateProps {
  title: string;
  detail: string;
  compact?: boolean;
}

export function EmptyState({ title, detail, compact = false }: EmptyStateProps) {
  return (
    <div className={`empty-state${compact ? " empty-state--compact" : ""}`} role="status">
      <span className="empty-state__mark" aria-hidden="true">Ø</span>
      <div>
        <strong>{title}</strong>
        <p>{detail}</p>
      </div>
    </div>
  );
}

