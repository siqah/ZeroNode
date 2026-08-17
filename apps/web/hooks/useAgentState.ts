"use client";

import useSWR from "swr";
import { fetchStatus, type AgentStatus } from "@/lib/api";

export function useAgentState(threadId: string) {
  const { data, error, isLoading, mutate } = useSWR<AgentStatus>(
    threadId ? ["incident", threadId] : null,
    () => fetchStatus(threadId),
    {
      refreshInterval: (latest) =>
        latest?.status === "awaiting_approval" ||
        latest?.status === "resolved" ||
        latest?.status === "completed"
          ? 0
          : 2000,
    }
  );

  return { agentState: data, isError: error, isLoading, mutate };
}
