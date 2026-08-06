import type { AgentEvent } from "../types/agentEvent";
import { getToken } from "../controllers/useAuth";
import * as eventsService from "../services/eventsService";

export async function getSessionEvents(sessionId: string): Promise<AgentEvent[]> {
  const token = getToken();
  if (!token) return [];
  return eventsService.fetchSessionEvents(token, sessionId);
}
