export const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://localhost:8000";

export type ProposedAction = {
  device?: string;
  action?: string;
  command: string;
  rationale?: string;
  verified?: boolean;
  verification?: string[];
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
};

export type IncidentRow = {
  thread_id: string;
  description: string;
  severity: string;
  created_at: string | null;
  status: string;
};

export async function fetchIncidents(): Promise<IncidentRow[]> {
  const res = await fetch(`${API_URL}/api/v1/incidents`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Incidents ${res.status}`);
  const data = await res.json();
  return data.incidents ?? [];
}

export async function fetchStatus(threadId: string): Promise<AgentStatus> {
  const res = await fetch(`${API_URL}/api/v1/incidents/${threadId}/status`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  return res.json();
}

export async function resumeIncident(
  threadId: string,
  decision: "approve" | "reject",
  feedback: string
): Promise<void> {
  const res = await fetch(`${API_URL}/api/v1/incidents/${threadId}/resume`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision, feedback }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(body || `Resume ${res.status}`);
  }
}
