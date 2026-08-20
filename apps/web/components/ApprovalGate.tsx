"use client";

import { useState } from "react";
import {
  resumeIncident,
  type ApprovalReceipt,
  type ChangeWindow,
  type ProposedAction,
} from "@/lib/api";

export default function ApprovalGate({
  threadId,
  proposedActions,
  canApprove,
  blockedReason,
  actor,
  role,
  changeWindow,
  alertFlags = [],
  executionMode = "",
  onDone,
}: {
  threadId: string;
  proposedActions: ProposedAction[];
  canApprove: boolean;
  blockedReason?: string;
  actor?: string;
  role?: string;
  changeWindow?: ChangeWindow;
  alertFlags?: string[];
  executionMode?: string;
  onDone: () => void;
}) {
  const [feedback, setFeedback] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [overrideReason, setOverrideReason] = useState("");
  const [receipt, setReceipt] = useState<ApprovalReceipt>(null);

  const action = proposedActions[0];
  const windowClosed = changeWindow ? !changeWindow.open : false;
  const canOverride = role === "admin";
  // The single most important thing on this screen: whether pressing approve
  // writes to hardware. Never inferred from a default — the API says which.
  const willWrite = executionMode.startsWith("live execution");

  const handleDecision = async (decision: "approve" | "reject") => {
    setBusy(true);
    setError("");
    try {
      const override =
        decision === "approve" && windowClosed && overrideReason.trim()
          ? { reason: overrideReason.trim() }
          : undefined;
      const result = await resumeIncident(threadId, decision, feedback, override);
      setReceipt(result.receipt);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Resume failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="gate">
      <h3>Action required: approve configuration</h3>

      <div className={willWrite ? "verdict fail" : "notice"}>
        <strong>
          {willWrite
            ? "Approving will write this to the live device."
            : "Approving records the change; nothing will be sent to a device."}
        </strong>
        {willWrite ? (
          <p className="muted">
            {executionMode}. If the change does not verify against the device afterwards, it
            is rolled back automatically.
          </p>
        ) : null}
      </div>

      {alertFlags.length ? (
        <div className="notice">
          <strong>The alert text was flagged as untrusted input.</strong> It contained{" "}
          {alertFlags.join(", ")}. The agent treats it as data, but read the proposal below
          against the device evidence rather than against what the alert asked for.
        </div>
      ) : null}

      <pre className="diff">
        {proposedActions.map((item) => item.command).join("\n") || "(no commands)"}
      </pre>
      {action?.rationale ? <p className="muted">{action.rationale}</p> : null}

      {action?.rollback ? (
        <div className={action.rollback_verified ? "verdict pass" : "verdict fail"}>
          <strong>
            {action.rollback_verified
              ? "Rollback simulated: this returns the flow to its current state"
              : "Rollback could not be verified — you would be undoing this by hand"}
          </strong>
          <pre className="diff">{action.rollback}</pre>
          <p className="muted">
            {action.rollback_source === "model"
              ? "Written by the agent."
              : "Derived from the change, then simulated."}
          </p>
        </div>
      ) : (
        <div className="verdict fail">
          <strong>No rollback attached to this change.</strong>
        </div>
      )}

      {action?.verification?.length ? (
        <div className={action.verified ? "verdict pass" : "verdict fail"}>
          <strong>
            {action.verified
              ? "Simulation passed: flow restored, scope matches the evidence"
              : "Simulation flagged this change — review before approving"}
          </strong>
          <ul>
            {action.verification.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {windowClosed ? (
        <div className="verdict fail">
          <strong>Outside the change window.</strong>
          <p className="muted">
            {changeWindow?.reason}
            {changeWindow?.next_open ? ` Next window opens ${changeWindow.next_open}.` : ""}
          </p>
          {canOverride ? (
            <textarea
              placeholder="Break-glass reason: why this cannot wait for the next window…"
              value={overrideReason}
              onChange={(e) => setOverrideReason(e.target.value)}
            />
          ) : (
            <p className="muted">Only an admin can override this.</p>
          )}
        </div>
      ) : null}

      <textarea
        placeholder="Optional: add feedback or modify the intent before approving…"
        value={feedback}
        onChange={(e) => setFeedback(e.target.value)}
        disabled={!canApprove}
      />
      {error ? <p className="error">{error}</p> : null}
      {receipt ? (
        <p className="muted mono">
          Recorded in the approval ledger · {receipt.hash.slice(0, 16)}… · key {receipt.key_id}
        </p>
      ) : null}
      {canApprove ? (
        <p className="muted">
          This decision will be signed and recorded against <strong>{actor}</strong>.
        </p>
      ) : (
        <p className="error">
          {blockedReason ?? "Your role cannot approve changes. An approver must sign this decision."}
        </p>
      )}
      <div className="actions">
        <button
          className="btn-reject"
          disabled={busy || !canApprove}
          onClick={() => handleDecision("reject")}
        >
          Reject &amp; re-plan
        </button>
        <button
          className="btn-approve"
          disabled={
            busy ||
            !canApprove ||
            (windowClosed && (!canOverride || overrideReason.trim().length < 10))
          }
          onClick={() => handleDecision("approve")}
        >
          {windowClosed
            ? willWrite
              ? "Override window & apply"
              : "Override window & dry-run"
            : willWrite
              ? "Apply to device"
              : "Execute dry-run"}
        </button>
      </div>
    </div>
  );
}
