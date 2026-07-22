import type { AgentEvent } from "../types/agentEvent";
import { getToken } from "../controllers/useAuth";
import * as logsService from "../services/logsService";
import type { LogsFilters } from "../services/logsService";

export async function getSessionLogs(
  sessionId: string,
  filters?: LogsFilters,
): Promise<{ total: number; logs: AgentEvent[] }> {
  const token = getToken();
  if (!token) return { total: 0, logs: [] };
  return logsService.fetchSessionLogs(token, sessionId, filters);
}
