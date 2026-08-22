"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { MfaRequired, login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(email, password, code);
      router.replace("/dashboard");
    } catch (err) {
      if (err instanceof MfaRequired) {
        setNeedsCode(true);
        setError("Enter the six-digit code from your authenticator.");
      } else {
        setError(err instanceof Error ? err.message : "Sign-in failed");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="shell">
      <div className="topbar">
        <div className="brand">
          ZeroNode<span>sign in</span>
        </div>
      </div>
      <form className="pane login" onSubmit={submit}>
        <h2>Authenticate</h2>
        <p className="muted">
          Approving a configuration change is a privileged action and is recorded against your
          identity.
        </p>
        <p className="muted">
          There is no public sign-up. Your admin creates your account and sends you the initial
          password. On first deploy, the platform owner signs in with{" "}
          <code>BOOTSTRAP_ADMIN_EMAIL</code> from <code>.env</code>.
        </p>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {needsCode ? (
          <>
            <label htmlFor="code">Authentication code</label>
            <input
              id="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
            />
          </>
        ) : null}
        {error ? <p className="error">{error}</p> : null}
        <button className="btn-approve" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
