import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DoctrinePage } from "@/components/pages/DoctrinePage";
import { joinDoctrineRegistry, PUBLIC_DOCTRINE } from "@/lib/doctrine";

const repoRoot = path.resolve(import.meta.dirname, "../../..");
const claimMap = JSON.parse(
  readFileSync(path.join(repoRoot, "docs/CLAIM_MAP.json"), "utf8"),
) as { claims: Array<Record<string, unknown>> };
const doctrineRegistry = JSON.parse(
  readFileSync(path.join(repoRoot, "docs/DOCTRINE.json"), "utf8"),
) as { guarantees: Array<Record<string, unknown>> };

const expectedGuarantees = [
  "Bailiff has one tool",
  "Refusal becomes ABSTAIN",
  "Evidence stays untrusted",
  "Review escalation is bounded",
  "Authority is single-use and hash-bound",
  "Publication is the read boundary",
] as const;

describe("public due-process doctrine", () => {
  it("joins exactly six guarantees to real enforcing modules and generated claims", () => {
    expect(PUBLIC_DOCTRINE.map((row) => row.guarantee)).toEqual(expectedGuarantees);

    for (const row of PUBLIC_DOCTRINE) {
      expect(existsSync(path.join(repoRoot, row.enforcingModule))).toBe(true);
      expect(row.claimId).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/);
      expect(row.artifactSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(row.artifactPath).toMatch(/^artifacts\/verification\//);
      expect(row.generator).toMatch(/^scripts\//);
      expect(row.artifactStatus).toBe("PASS");
    }
  });

  it("fails the build-time join when a registry claim is missing", () => {
    const firstClaimId = doctrineRegistry.guarantees[0]?.claim_id;
    const missing = {
      ...claimMap,
      claims: claimMap.claims.filter((claim) => claim.claim_id !== firstClaimId),
    };

    expect(() => joinDoctrineRegistry(doctrineRegistry, missing))
      .toThrow(/missing doctrine claim/i);
  });

  it("rejects malformed public claim evidence instead of rendering it", () => {
    const firstClaimId = doctrineRegistry.guarantees[0]?.claim_id;
    const malformed = {
      ...claimMap,
      claims: claimMap.claims.map((claim) => claim.claim_id === firstClaimId
        ? { ...claim, artifact_sha256: "not-a-digest" }
        : claim),
    };

    expect(() => joinDoctrineRegistry(doctrineRegistry, malformed))
      .toThrow(/invalid doctrine artifact hash/i);
  });

  it("renders a falsifiable public table without provenance commands", () => {
    render(<DoctrinePage />);

    expect(screen.getByRole("heading", { level: 1, name: "Due process for AI agents" }))
      .toBeVisible();
    expect(screen.getByText(
      "The five personas are AI agents powered by GPT-5.6; portraits generated with ChatGPT Images; any resemblance to real persons is coincidental.",
    )).toBeVisible();
    const table = screen.getByRole("table", { name: "CrossPatch due-process guarantees" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(7);
    for (const guarantee of expectedGuarantees) {
      expect(within(table).getByRole("rowheader", { name: guarantee })).toBeVisible();
    }
    expect(table).toHaveTextContent("Enforcing module");
    expect(table).toHaveTextContent("Artifact SHA-256");
    expect(table).toHaveTextContent("Generator");
    expect(table).not.toHaveTextContent("uv run");
    expect(table).not.toHaveTextContent("npm ci");
    expect(table).not.toHaveTextContent("generated_at");
  });
});
