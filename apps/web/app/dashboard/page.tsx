"use client";

import Link from "next/link";
import useSWR from "swr";
import { fetchIncidents, type IncidentRow } from "@/lib/api";

function pillClass(status: string) {
  if (status === "awaiting_approval") return "pill wait";
  if (status === "resolved" || status === "completed") return "pill ok";
  if (status === "high" || status === "critical") return "pill hot";
  return "pill";
}

export default function DashboardPage() {
  const { data, error, isLoading } = useSWR<IncidentRow[]>(
    "incidents",
    fetchIncidents,
    { refreshInterval: 4000 }
  );
  const incidents = data ?? [];

  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand">
          ZeroNode<span>NOC triage</span>
        </div>
        <p className="muted">Dry-run HITL · cross-zone lab</p>
      </div>
      <h1>Active threads</h1>
      <p className="lede">Incidents pause at execute_change until an L3 engineer approves.</p>
      {error ? (
        <p className="empty">
          Cannot reach API ({error instanceof Error ? error.message : "error"}). Start the
          FastAPI control plane.
        </p>
      ) : isLoading ? (
        <p className="muted">Loading…</p>
      ) : incidents.length === 0 ? (
        <p className="empty">
          No incidents yet. Trigger <code>POST /api/v1/incidents/trigger</code> with ticket
          INC-1001.
        </p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Thread</th>
              <th>Severity</th>
              <th>State</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((row) => (
              <tr key={row.thread_id}>
                <td>
                  <Link href={`/incidents/${row.thread_id}`} className="mono">
                    {row.thread_id}
                  </Link>
                </td>
                <td>
                  <span className={pillClass(row.severity)}>{row.severity}</span>
                </td>
                <td>
                  <span className={pillClass(row.status)}>{row.status}</span>
                </td>
                <td>{row.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
