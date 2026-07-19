const ACCESS_TOKEN_KEY = "crosspatch_access_token";
const CSRF_TOKEN_KEY = "crosspatch_csrf_token";
const STEP_UP_TOKEN_KEY = "crosspatch_step_up_token";
const INCIDENT_ID_KEY = "crosspatch_incident_id";
const INCIDENT_CONTEXT_EVENT = "crosspatch:incident-context";

function session(): Storage | null {
  return typeof window === "undefined" ? null : window.sessionStorage;
}

function storeOrClear(key: string, input: string): void {
  const storage = session();
  if (!storage) return;
  const normalized = input.trim();
  if (normalized) storage.setItem(key, normalized);
  else storage.removeItem(key);
}

export function readAccessToken(): string {
  return session()?.getItem(ACCESS_TOKEN_KEY) ?? "";
}

export function storeAccessToken(token: string): void {
  storeOrClear(ACCESS_TOKEN_KEY, token);
}

export function readIncidentId(): string {
  return session()?.getItem(INCIDENT_ID_KEY) ?? "";
}

export function storeIncidentId(incidentId: string): void {
  const before = readIncidentId();
  storeOrClear(INCIDENT_ID_KEY, incidentId);
  if (before !== readIncidentId() && typeof window !== "undefined") {
    window.dispatchEvent(new Event(INCIDENT_CONTEXT_EVENT));
  }
}

export function subscribeIncidentId(listener: () => void): () => void {
  if (typeof window === "undefined") return () => undefined;
  window.addEventListener(INCIDENT_CONTEXT_EVENT, listener);
  return () => window.removeEventListener(INCIDENT_CONTEXT_EVENT, listener);
}

export function storeApprovalCredentials(csrfToken: string, stepUpToken: string): void {
  storeOrClear(CSRF_TOKEN_KEY, csrfToken);
  storeOrClear(STEP_UP_TOKEN_KEY, stepUpToken);
}

export function readApprovalCredentials(): { csrfToken: string; stepUpToken: string } {
  const storage = session();
  return {
    csrfToken: storage?.getItem(CSRF_TOKEN_KEY) ?? "",
    stepUpToken: storage?.getItem(STEP_UP_TOKEN_KEY) ?? "",
  };
}

export function hasApprovalCredentials(): boolean {
  const { csrfToken, stepUpToken } = readApprovalCredentials();
  return Boolean(csrfToken && stepUpToken);
}
