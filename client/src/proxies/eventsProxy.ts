import type { AgentEvent } from "../types/agentEvent";
import { mockEventsBySession } from "../mocks/events.mock";

export async function getSessionEvents(sessionId: string): Promise<AgentEvent[]> {
  return mockEventsBySession[sessionId] ?? [];
}
