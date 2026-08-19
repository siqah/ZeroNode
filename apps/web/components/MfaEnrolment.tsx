"use client";

import { useState } from "react";
import { activateMfa, enrolMfa, type Enrolment, type Session } from "@/lib/api";

/**
 * Shown to anyone who may approve but has no second factor yet. Approvals are
 * refused until this is done, so the prompt states that rather than hiding it.
 */
export default function MfaEnrolment({ session }: { session?: Session }) {
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null);
  const [code, setCode] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const needed =
    session &&
    session.kind === "user" &&
    session.mfa_required_to_approve &&
    !session.mfa &&
    ["approver", "admin"].includes(session.role);

  if (!needed || done) return null;

  const start = async () => {
    setBusy(true);
    setError("");
    try {
      setEnrolment(await enrolMfa());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start enrolment");
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);
    setError("");
    try {
      await activateMfa(code);
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "That code was not accepted");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="pane notice">
      <h3>Second factor required to approve</h3>
      <p className="muted">
        Your role can approve changes, but this account has no authenticator enrolled. Approvals
        are refused until it does.
      </p>
      {enrolment ? (
        <>
          <p className="muted">
            Add this key to your authenticator app, then enter the code it shows.
          </p>
          <pre className="diff">{enrolment.secret}</pre>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button className="btn-approve" disabled={busy} onClick={confirm}>
            Confirm code
          </button>
          <p className="muted">You will be asked for a code the next time you sign in.</p>
        </>
      ) : (
        <button className="btn-approve" disabled={busy} onClick={start}>
          {busy ? "Working…" : "Enrol an authenticator"}
        </button>
      )}
      {error ? <p className="error">{error}</p> : null}
    </div>
  );
}
