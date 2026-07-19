import type { SeatName, SeatView } from "./types";

export const ESCALATION_EXPLANATION =
  "The room only thinks harder when the judge is unsatisfied." as const;

export const SEAT_ORDER: readonly SeatName[] = [
  "Prosecutor",
  "Inspector",
  "Counsel",
  "Magistrate",
  "Bailiff",
] as const;

export const DEFAULT_SEATS: readonly SeatView[] = [
  {
    name: "Prosecutor",
    role: "Challenges the leading incident hypothesis",
    model: "gpt-5.6-luna",
    tierRationale: "Fast rival-hypothesis pressure testing",
    effort: "low",
    escalationCount: 0,
    state: "idle",
  },
  {
    name: "Inspector",
    role: "Builds the evidence-backed failure mechanism",
    model: "gpt-5.6-terra",
    tierRationale: "Balanced analysis across incident evidence",
    effort: "medium",
    escalationCount: 0,
    state: "idle",
  },
  {
    name: "Counsel",
    role: "Proposes the smallest testable repair",
    model: "gpt-5.6-terra",
    tierRationale: "Controlled patch and test-intent synthesis",
    effort: "medium",
    escalationCount: 0,
    state: "idle",
  },
  {
    name: "Magistrate",
    role: "Returns the fail-closed incident verdict",
    model: "gpt-5.6-sol",
    tierRationale: "Highest scrutiny at the approval boundary",
    effort: "medium",
    escalationCount: 0,
    state: "idle",
  },
  {
    name: "Bailiff",
    role: "Presents one approved warrant for execution",
    model: "gpt-5.6-luna",
    tierRationale: "No reasoning; single broker tool only",
    effort: "none",
    escalationCount: 0,
    state: "idle",
  },
] as const;

export const PORTRAIT_ASSETS: Record<SeatName, { source: string; crop: string }> = {
  Prosecutor: { source: "prosecutor-source.webp", crop: "prosecutor.webp" },
  Inspector: { source: "inspector-source.webp", crop: "inspector.webp" },
  Counsel: { source: "counsel-source.webp", crop: "counsel.webp" },
  Magistrate: { source: "magistrate-source.webp", crop: "magistrate.webp" },
  Bailiff: { source: "bailiff-source.webp", crop: "bailiff.webp" },
};

