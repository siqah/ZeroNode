"use client";

import Link from "next/link";
import type { Session } from "@/lib/api";

export default function SessionBar({
  session,
  onSignOut,
}: {
  session?: Session;
  onSignOut: () => void;
}) {
  if (!session) return null;
  return (
    <div className="session">
      <span className="mono">{session.email}</span>
      <span className={`pill ${session.can_approve ? "ok" : ""}`}>{session.role}</span>
      {session.mfa ? <span className="pill ok">2fa</span> : null}
      {session.role === "admin" ? (
        <Link href="/admin/users" className="btn-link">
          Users
        </Link>
      ) : null}
      <button className="btn-link" onClick={onSignOut}>
        Sign out
      </button>
    </div>
  );
}
