"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import useSWR from "swr";
import { AuthError, fetchSession, logout, type Session } from "@/lib/api";

/** Current signed-in principal. Redirects to the login page when there isn't one. */
export function useSession(redirect = true) {
  const router = useRouter();
  const { data, error, isLoading, mutate } = useSWR<Session>("session", fetchSession, {
    shouldRetryOnError: false,
    revalidateOnFocus: false,
  });

  const unauthenticated = error instanceof AuthError || (!isLoading && !data && !!error);

  useEffect(() => {
    if (redirect && unauthenticated) router.replace("/login");
  }, [redirect, unauthenticated, router]);

  const signOut = async () => {
    // The session cookie is httpOnly, so only the server can clear it.
    try {
      await logout();
    } catch {
      /* signing out locally matters more than the response */
    }
    mutate(undefined, { revalidate: false });
    router.replace("/login");
  };

  return { session: data, isLoading, unauthenticated, signOut, mutate };
}
