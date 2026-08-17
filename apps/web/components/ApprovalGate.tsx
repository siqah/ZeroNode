"use client";

import { useState } from "react";
import { resumeIncident, type ProposedAction } from "@/lib/api";

export default function ApprovalGate({
  threadId,
  proposedActions,
  onDone,
}: {
  threadId: string;
  proposedActions: ProposedAction[];
  onDone: () => void;
}) {
  const [feedback, setFeedback] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const handleDecision = async (decision: "approve" | "reject") => {
    setBusy(true);
    setError("");
    try {
      await resumeIncident(threadId, decision, feedback);
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
      <pre className="diff">
        {proposedActions.map((action) => action.command).join("\n") || "(no commands)"}
      </pre>
      {proposedActions[0]?.rationale ? (
        <p className="muted">{proposedActions[0].rationale}</p>
      ) : null}
      {proposedActions[0]?.verification?.length ? (
        <div className={proposedActions[0].verified ? "verdict pass" : "verdict fail"}>
          <strong>
            {proposedActions[0].verified
              ? "Simulation passed: flow restored, scope matches the evidence"
              : "Simulation flagged this change — review before approving"}
          </strong>
          <ul>
            {proposedActions[0].verification.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <textarea
        placeholder="Optional: add feedback or modify the intent before approving…"
        value={feedback}
        onChange={(e) => setFeedback(e.target.value)}
      />
      {error ? <p className="muted">{error}</p> : null}
      <div className="actions">
        <button className="btn-reject" disabled={busy} onClick={() => handleDecision("reject")}>
          Reject &amp; re-plan
        </button>
        <button className="btn-approve" disabled={busy} onClick={() => handleDecision("approve")}>
          Execute dry-run
        </button>
      </div>
    </div>
  );
}
