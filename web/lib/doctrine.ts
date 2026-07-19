import claimMapPayload from "../../docs/CLAIM_MAP.json";
import doctrineRegistryPayload from "../../docs/DOCTRINE.json";

const CLAIM_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_MODULE = /^(?:backend|web|scripts)\/(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_./-]+$/;
const SAFE_ARTIFACT = /^artifacts\/verification\/(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_./-]+$/;
const SAFE_GENERATOR = /^scripts\/(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_./-]+$/;

export interface PublicDoctrineRow {
  id: string;
  guarantee: string;
  detail: string;
  enforcingModule: string;
  claimId: string;
  artifactPath: string;
  artifactSha256: string;
  artifactStatus: "PASS";
  generator: string;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyText(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required`);
  return value;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

export function joinDoctrineRegistry(
  registryValue: unknown,
  claimMapValue: unknown,
): readonly PublicDoctrineRow[] {
  const registry = record(registryValue, "doctrine registry");
  const claimMap = record(claimMapValue, "claim map");
  if (registry.schema_version !== 1) throw new Error("unsupported doctrine registry schema");
  if (claimMap.schema_version !== 1) throw new Error("unsupported claim map schema");

  const guarantees = array(registry.guarantees, "doctrine guarantees");
  if (guarantees.length !== 6) throw new Error("doctrine registry must contain six guarantees");
  const claims = array(claimMap.claims, "claim map claims").map((value) => record(value, "claim"));
  const rows: PublicDoctrineRow[] = [];
  const seenIds = new Set<string>();

  for (const value of guarantees) {
    const guarantee = record(value, "doctrine guarantee");
    const id = nonEmptyText(guarantee.id, "doctrine id");
    const label = nonEmptyText(guarantee.guarantee, "doctrine guarantee");
    const detail = nonEmptyText(guarantee.detail, "doctrine detail");
    const enforcingModule = nonEmptyText(guarantee.enforcing_module, "enforcing module");
    const claimId = nonEmptyText(guarantee.claim_id, "doctrine claim id");
    if (!CLAIM_ID.test(id) || seenIds.has(id)) throw new Error(`invalid doctrine id: ${id}`);
    if (!SAFE_MODULE.test(enforcingModule)) {
      throw new Error(`unsafe doctrine module path: ${enforcingModule}`);
    }
    if (!CLAIM_ID.test(claimId)) throw new Error(`invalid doctrine claim id: ${claimId}`);
    seenIds.add(id);

    const matches = claims.filter((claim) => claim.claim_id === claimId);
    if (matches.length !== 1) throw new Error(`missing doctrine claim: ${claimId}`);
    const claim = matches[0];
    const artifactPath = nonEmptyText(claim.artifact_path, "doctrine artifact path");
    const artifactSha256 = nonEmptyText(claim.artifact_sha256, "doctrine artifact hash");
    const generator = nonEmptyText(claim.generator, "doctrine generator");
    if (!SAFE_ARTIFACT.test(artifactPath)) {
      throw new Error(`unsafe doctrine artifact path: ${artifactPath}`);
    }
    if (!SHA256.test(artifactSha256)) {
      throw new Error(`invalid doctrine artifact hash: ${claimId}`);
    }
    if (!SAFE_GENERATOR.test(generator)) {
      throw new Error(`unsafe doctrine generator: ${generator}`);
    }
    if (claim.artifact_status !== "PASS") {
      throw new Error(`doctrine claim is not PASS: ${claimId}`);
    }
    rows.push(Object.freeze({
      id,
      guarantee: label,
      detail,
      enforcingModule,
      claimId,
      artifactPath,
      artifactSha256,
      artifactStatus: "PASS",
      generator,
    }));
  }

  return Object.freeze(rows);
}

export const PUBLIC_DOCTRINE = joinDoctrineRegistry(
  doctrineRegistryPayload,
  claimMapPayload,
);
