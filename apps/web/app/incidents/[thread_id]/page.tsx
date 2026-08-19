"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import ApprovalGate from "@/components/ApprovalGate";
import PathVisualizer from "@/components/PathVisualizer";
import ReasoningTrace from "@/components/ReasoningTrace";
import SessionBar from "@/components/SessionBar";
import { useAgentState } from "@/hooks/useAgentState";
import { useSession } from "@/hooks/useSession";
import type { Session } from "@/lib/api";

function blockedReason(session?: Session) {
  if (!session || session.can_approve) return undefined;
  if (session.kind === "service") {
    return "Machine credentials cannot approve a change; sign in as a person.";
  }
  if (["approver", "admin"].includes(session.role) && !session.mfa) {
    return "Approvals require a second factor. Enrol an authenticator, then sign in again.";
  }
  return "Your role cannot approve changes. An approver must sign this decision.";
}

export default function IncidentPage() {
  const params = useParams<{ thread_id: string }>();
  const threadId = params.thread_id;
  const { session, signOut } = useSession();
  const { agentState, isError, isLoading, mutate } = useAgentState(threadId);

  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand">
          <Link href="/dashboard">ZeroNode</Link>
          <span>{threadId}</span>
        </div>
        <div className="topbar-right">
          <span className={`pill ${agentState?.status === "awaiting_approval" ? "wait" : ""}`}>
            {agentState?.status ?? (isLoading ? "loading" : "unknown")}
          </span>
          <SessionBar session={session} onSignOut={signOut} />
        </div>
      </div>
      <h1>Incident {threadId}</h1>
      <p className="lede">
        {agentState?.agent_summary ||
          (agentState?.status === "running"
            ? `Investigating${agentState.current_node ? ` (${agentState.current_node})` : ""}. Gemma is slow on CPU — poll continues until HITL pause.`
            : "Agent is investigating. This view polls until HITL pause.")}
      </p>
      {isError ? (
        <p className="empty">Could not load status. Is the API running?</p>
      ) : (
        <>
          <div className="grid" style={{ margin: "20px 0" }}>
            <div className="pane">
              <h2>Reasoning trace</h2>
              <ReasoningTrace steps={agentState?.reasoning_trace ?? []} />
            </div>
            <div className="pane">
              <h2>Blast radius / path</h2>
              <PathVisualizer context={agentState?.topology_context ?? ""} />
              {agentState?.zone_context ? (
                <p className="muted mono" style={{ marginTop: 12 }}>
                  {agentState.zone_context}
                </p>
              ) : null}
            </div>
          </div>
          {(agentState?.tool_log ?? []).length ? (
            <div className="pane" style={{ marginBottom: 16 }}>
              <h2>Tool results</h2>
              <ReasoningTrace steps={agentState?.tool_log ?? []} />
            </div>
          ) : null}
          {agentState?.status === "awaiting_approval" ? (
            <ApprovalGate
              threadId={threadId}
              proposedActions={agentState.proposed_actions ?? []}
              canApprove={Boolean(session?.can_approve)}
              blockedReason={blockedReason(session)}
              actor={session?.email}
              role={session?.role}
              changeWindow={agentState.change_window}
              alertFlags={agentState.alert_flags ?? []}
              onDone={() => mutate()}
            />
          ) : null}
        </>
      )}
    </div>
  );
}
