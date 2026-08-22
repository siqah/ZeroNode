export const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://localhost:8000";

const CSRF_COOKIE = "zn_csrf";

export type ProposedAction = {
  device?: string;
  action?: string;
  command: string;
  rationale?: string;
  verified?: boolean;
  verification?: string[];
  rollback?: string;
  rollback_source?: "model" | "derived" | string;
  rollback_verified?: boolean;
};

export type Execution = {
  mode: string;
  state: "logged" | "applied" | "refused" | "rolled_back" | "rollback_failed";
  lines: string[];
  verification: string[];
  commands: string[];
  errors: string[];
};

export type ChangeWindow = {
  open: boolean;
  reason: string;
  next_open: string;
  policy: string;
};

export type AgentStatus = {
  thread_id: string;
  status: "queued" | "running" | "awaiting_approval" | "resolved" | "completed" | string;
  current_node: string | null;
  agent_summary: string;
  topology_context: string;
  zone_context: string;
  proposed_actions: ProposedAction[];
  reasoning_trace: string[];
  tool_log: string[];
  verification: string[];
  active_worker: string;
  alert_flags: string[];
  change_window: ChangeWindow;
  execution: Execution | null;
  execution_mode: string;
};

export type IncidentRow = {
  thread_id: string;
  description: string;
  severity: string;
  created_at: string | null;
  status: string;
};

export type Session = {
  email: string;
  role: string;
  kind: string;
  mfa: boolean;
  mfa_required_to_approve: boolean;
  can_approve: boolean;
};

export type UserRole = "viewer" | "operator" | "approver" | "admin";

export type UserRow = {
  email: string;
  role: UserRole;
  active: boolean;
  created_at: string | null;
  mfa_enabled: boolean;
  locked_until: string | null;
};

export type Enrolment = {
  secret: string;
  otpauth_uri: string;
};

export class MfaRequired extends Error {}

export type ApprovalReceipt = {
  hash: string;
  key_id: string;
  recorded_at: string;
} | null;

export class AuthError extends Error {}

/**
 * The session itself lives in an httpOnly cookie the browser attaches on its
 * own; this value is the paired CSRF token, which is readable precisely so it
 * can be echoed back in a header that a cross-site request cannot set.
 */
export function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const csrf = csrfToken();
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "include",
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...(init.headers ?? {}),
    },
  });

  if (res.status === 401) {
    let detail = "";
    try {
      detail = (await res.json()).detail ?? "";
    } catch {
      /* response had no JSON body */
    }
    if (detail === "mfa_required") throw new MfaRequired("A one-time code is required.");
    // A rejected credential and an expired session are both 401; saying "sign in
    // again" to someone who just mistyped a password is unhelpful.
    if (path.endsWith("/auth/login")) throw new Error(detail || "Sign-in failed");
    throw new AuthError("Session expired or missing. Sign in again.");
  }
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* response had no JSON body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export async function login(
  email: string,
  password: string,
  totpCode = ""
): Promise<Session> {
  await request("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password, totp_code: totpCode }),
  });
  return fetchSession();
}

export async function logout(): Promise<void> {
  await request("/api/v1/auth/logout", { method: "POST" });
}

export async function enrolMfa(): Promise<Enrolment> {
  return request<Enrolment>("/api/v1/auth/mfa/enrol", { method: "POST" });
}

export async function activateMfa(totpCode: string): Promise<void> {
  await request("/api/v1/auth/mfa/activate", {
    method: "POST",
    body: JSON.stringify({ totp_code: totpCode }),
  });
}

export async function fetchSession(): Promise<Session> {
  return request<Session>("/api/v1/auth/me");
}

export async function fetchUsers(): Promise<UserRow[]> {
  const data = await request<{ users: UserRow[] }>("/api/v1/auth/users");
  return data.users ?? [];
}

export async function createUser(
  email: string,
  password: string,
  role: UserRole
): Promise<{ email: string; role: UserRole }> {
  return request("/api/v1/auth/users", {
    method: "POST",
    body: JSON.stringify({ email, password, role }),
  });
}

export async function unlockUser(email: string): Promise<void> {
  await request(`/api/v1/auth/users/${encodeURIComponent(email)}/unlock`, {
    method: "POST",
  });
}

export async function fetchIncidents(): Promise<IncidentRow[]> {
  const data = await request<{ incidents: IncidentRow[] }>("/api/v1/incidents");
  return data.incidents ?? [];
}

export async function fetchStatus(threadId: string): Promise<AgentStatus> {
  return request<AgentStatus>(`/api/v1/incidents/${threadId}/status`);
}

export async function resumeIncident(
  threadId: string,
  decision: "approve" | "reject",
  feedback: string,
  override?: { reason: string }
): Promise<{ actor: string; receipt: ApprovalReceipt }> {
  return request(`/api/v1/incidents/${threadId}/resume`, {
    method: "POST",
    body: JSON.stringify({
      decision,
      feedback,
      override_window: Boolean(override),
      override_reason: override?.reason ?? "",
    }),
  });
}
