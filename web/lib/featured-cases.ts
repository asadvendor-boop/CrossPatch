export const FEATURED_CASE_IDS = [
  "inc_03d46c72ab2f4ca8943f3fa5fd83b152",
  "inc_39338e35925c4650bb16445cb3761a3d",
] as const;

export const HOSTILE_EVIDENCE_CASE_IDS = [
  "inc_39338e35925c4650bb16445cb3761a3d",
] as const;

const FEATURED_PRIORITY = new Map<string, number>(
  FEATURED_CASE_IDS.map((incidentId, index) => [incidentId, index]),
);

export function pinFeaturedCases<T extends { incidentId: string }>(cases: readonly T[]): T[] {
  return cases
    .map((publishedCase, index) => ({ publishedCase, index }))
    .sort((left, right) => {
      const leftPriority = FEATURED_PRIORITY.get(left.publishedCase.incidentId);
      const rightPriority = FEATURED_PRIORITY.get(right.publishedCase.incidentId);
      if (leftPriority !== undefined || rightPriority !== undefined) {
        return (leftPriority ?? Number.MAX_SAFE_INTEGER)
          - (rightPriority ?? Number.MAX_SAFE_INTEGER);
      }
      return left.index - right.index;
    })
    .map(({ publishedCase }) => publishedCase);
}

export function isFeaturedCase(incidentId: string): boolean {
  return FEATURED_PRIORITY.has(incidentId);
}

export function isHostileEvidenceCase(incidentId: string): boolean {
  return (HOSTILE_EVIDENCE_CASE_IDS as readonly string[]).includes(incidentId);
}
