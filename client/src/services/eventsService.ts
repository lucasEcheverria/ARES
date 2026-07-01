import type { AgentEvent } from "../types/agentEvent";

export async function fetchSessionEvents(_sessionId: string): Promise<AgentEvent[]> {
  throw new Error("eventsService.fetchSessionEvents: backend not implemented yet");
}

/**
 * Opens a WebSocket connection for live event streaming of an active session.
 * Returns the socket so the caller can attach listeners and close it.
 */
export function openLiveEventsSocket(_sessionId: string): WebSocket {
  throw new Error("eventsService.openLiveEventsSocket: backend not implemented yet");
}
