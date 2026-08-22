"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import useSWR from "swr";
import SessionBar from "@/components/SessionBar";
import { useSession } from "@/hooks/useSession";
import {
  createUser,
  fetchUsers,
  unlockUser,
  type UserRole,
  type UserRow,
} from "@/lib/api";

const ROLES: UserRole[] = ["viewer", "operator", "approver", "admin"];

function pillClass(user: UserRow) {
  if (user.locked_until) return "pill hot";
  if (user.mfa_enabled) return "pill ok";
  return "pill";
}

export default function AdminUsersPage() {
  const router = useRouter();
  const { session, signOut, isLoading: sessionLoading } = useSession();
  const { data, error, isLoading, mutate } = useSWR<UserRow[]>(
    session?.role === "admin" ? "users" : null,
    fetchUsers,
    { shouldRetryOnError: false }
  );

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("operator");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const [formOk, setFormOk] = useState("");

  useEffect(() => {
    if (!sessionLoading && session && session.role !== "admin") {
      router.replace("/dashboard");
    }
  }, [session, sessionLoading, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setFormError("");
    setFormOk("");
    try {
      const created = await createUser(email, password, role);
      setFormOk(
        `Created ${created.email} (${created.role}). Share the password out of band — ZeroNode does not send email.`
      );
      setEmail("");
      setPassword("");
      setRole("operator");
      await mutate();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create user");
    } finally {
      setBusy(false);
    }
  };

  const unlock = async (target: string) => {
    setFormError("");
    setFormOk("");
    try {
      await unlockUser(target);
      setFormOk(`Unlocked ${target}.`);
      await mutate();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not unlock account");
    }
  };

  if (sessionLoading || !session || session.role !== "admin") {
    return (
      <div className="shell">
        <p className="muted">Loading…</p>
      </div>
    );
  }

  const users = data ?? [];

  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand">
          <Link href="/dashboard">ZeroNode</Link>
          <span>user accounts</span>
        </div>
        <div className="topbar-right">
          <Link href="/dashboard" className="btn-link">
            Dashboard
          </Link>
          <SessionBar session={session} onSignOut={signOut} />
        </div>
      </div>

      <h1>People who can sign in</h1>
      <p className="lede">
        The first admin is created from <code>BOOTSTRAP_ADMIN_EMAIL</code> on startup. After that,
        only an admin can add accounts here. There is no public sign-up page.
      </p>

      <div className="grid">
        <form className="pane login" onSubmit={submit}>
          <h2>Create account</h2>
          <p className="muted">
            Choose a temporary password and send it to the person securely. They sign in at{" "}
            <code>/login</code>.
          </p>
          <label htmlFor="new-email">Email</label>
          <input
            id="new-email"
            type="email"
            autoComplete="off"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <label htmlFor="new-password">Initial password</label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            minLength={12}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <label htmlFor="new-role">Role</label>
          <select
            id="new-role"
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
          >
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          {formError ? <p className="error">{formError}</p> : null}
          {formOk ? <p className="muted">{formOk}</p> : null}
          <button className="btn-approve" type="submit" disabled={busy}>
            {busy ? "Creating…" : "Create user"}
          </button>
        </form>

        <div className="pane">
          <h2>How login works</h2>
          <ol className="steps">
            <li>Admin sets email + password when creating the account.</li>
            <li>User opens <code>/login</code> and enters those credentials.</li>
            <li>
              Approvers and admins may be prompted to enrol MFA before they can approve changes.
            </li>
            <li>
              After five failed attempts, an account locks; unlock it here or wait for the lockout
              window to expire.
            </li>
          </ol>
        </div>
      </div>

      {error ? (
        <p className="empty">
          Cannot load users ({error instanceof Error ? error.message : "error"}).
        </p>
      ) : isLoading ? (
        <p className="muted">Loading users…</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>MFA</th>
              <th>Status</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.email}>
                <td className="mono">{user.email}</td>
                <td>
                  <span className="pill">{user.role}</span>
                </td>
                <td>
                  <span className={pillClass(user)}>{user.mfa_enabled ? "on" : "off"}</span>
                </td>
                <td>
                  {user.locked_until ? (
                    <span className="pill hot">locked</span>
                  ) : user.active ? (
                    <span className="pill ok">active</span>
                  ) : (
                    <span className="pill">inactive</span>
                  )}
                </td>
                <td className="muted">{user.created_at ?? "—"}</td>
                <td>
                  {user.locked_until ? (
                    <button className="btn-link" type="button" onClick={() => unlock(user.email)}>
                      Unlock
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
