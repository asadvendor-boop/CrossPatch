export type OperatorScenario = "webhook-race" | "webhook-payload-equivalence";
export type EvidenceProfile = "standard" | "instruction-like-log";

export const INSTRUCTION_LOG_TITLE = "Poisoned webhook logs — due process held";

export const OPERATOR_SCENARIOS = {
  "webhook-race": {
    title: "Duplicate order-paid delivery",
    description: "Concurrent valid deliveries can enqueue duplicate work.",
  },
  "webhook-payload-equivalence": {
    title: "Equivalent webhook retry rejected",
    description: "Equivalent valid JSON retries are mistaken for conflicts.",
  },
} as const satisfies Record<OperatorScenario, { title: string; description: string }>;

const CANDIDATE_PLAN_SCENARIOS = {
  "victim.duplicate-race.candidate": "webhook-race",
  "victim.payload-equivalence.candidate": "webhook-payload-equivalence",
} as const satisfies Record<string, OperatorScenario>;

export interface RecordedPlanPresentation {
  planId: string;
  label: string;
  scenario: OperatorScenario | null;
  known: boolean;
}

export function isOperatorScenario(value: string): value is OperatorScenario {
  return Object.hasOwn(OPERATOR_SCENARIOS, value);
}

export function scenarioMetadata(value: string) {
  return isOperatorScenario(value) ? OPERATOR_SCENARIOS[value] : null;
}

export function presentRecordedPlan(planId: string): RecordedPlanPresentation {
  const scenario = Object.hasOwn(CANDIDATE_PLAN_SCENARIOS, planId)
    ? CANDIDATE_PLAN_SCENARIOS[planId as keyof typeof CANDIDATE_PLAN_SCENARIOS]
    : null;
  return {
    planId,
    label: scenario ? OPERATOR_SCENARIOS[scenario].title : `Recorded plan: ${planId}`,
    scenario,
    known: scenario !== null,
  };
}
