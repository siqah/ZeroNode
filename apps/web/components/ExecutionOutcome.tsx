"use client";

import type { Execution } from "@/lib/api";

const HEADLINE: Record<Execution["state"], string> = {
  logged: "Logged only — nothing was sent to a device",
  applied: "Applied to the device and confirmed afterwards",
  refused: "Not executed — a safety precondition failed",
  rolled_back: "Applied, failed its check, and was rolled back",
  rollback_failed: "The device could not be returned to its previous state",
};

const TONE: Record<Execution["state"], string> = {
  logged: "pass",
  applied: "pass",
  refused: "fail",
  rolled_back: "fail",
  rollback_failed: "fail",
};

export default function ExecutionOutcome({ execution }: { execution: Execution }) {
  return (
    <div className="pane" style={{ marginBottom: 16 }}>
      <h2>What happened after approval</h2>
      <div className={`verdict ${TONE[execution.state] ?? "fail"}`}>
        <strong>{HEADLINE[execution.state] ?? execution.state}</strong>
        {execution.state === "rollback_failed" ? (
          <p>
            Someone has to look at this device now. The commands below were sent; the ones
            that failed are marked.
          </p>
        ) : null}
        <ul>
          {execution.lines.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>

      {execution.commands.length ? (
        <pre className="diff">{execution.commands.join("\n")}</pre>
      ) : null}

      {execution.errors.length ? (
        <div className="verdict fail">
          <strong>Errors reported by the device</strong>
          <ul>
            {execution.errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {execution.verification.length ? (
        <>
          <h3 className="muted">Read back from the device</h3>
          <ul className="mono">
            {execution.verification.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </>
      ) : null}

      <p className="muted">Mode: {execution.mode}</p>
    </div>
  );
}
