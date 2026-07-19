const LOCKED_VERDICTS = new Set(["CLEAR", "REMAND", "BLOCK", "ABSTAIN"]);

const MACHINE_ENUM = /^[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*$/;

export function formatPublicEnum(value: string): string {
  const normalized = value.trim();
  if (!normalized || LOCKED_VERDICTS.has(normalized)) return normalized;
  if (!MACHINE_ENUM.test(normalized)) return normalized;

  const words = normalized.toLowerCase().replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function formatSeverity(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized === "UNSET") return "not recorded";
  return formatPublicEnum(normalized);
}

export function formatRecordedDurationMs(milliseconds: number): string {
  if (milliseconds < 1_000) return "<1s";
  const seconds = Math.round(milliseconds / 1_000);
  const hours = Math.floor(seconds / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remainder = seconds % 60;
  return [
    hours ? `${hours}h` : null,
    minutes ? `${minutes}m` : null,
    remainder || (!hours && !minutes) ? `${remainder}s` : null,
  ].filter((part): part is string => part !== null).join(" ");
}

export function formatRecordedDurationSeconds(seconds: number | null): string {
  return seconds === null ? "Not recorded" : formatRecordedDurationMs(seconds * 1_000);
}
