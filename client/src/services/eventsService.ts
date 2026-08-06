import type { AgentEvent } from "../types/agentEvent";

const API_URL = import.meta.env.VITE_API_URL;

export async function fetchSessionEvents(token: string, sessionId: string): Promise<AgentEvent[]> {
  const response = await fetch(`${API_URL}/sessions/${sessionId}/events`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("eventsService.fetchSessionEvents: request failed");
  }
  return response.json();
}
