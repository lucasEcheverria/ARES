import type { ToolResultLog } from "../types/toolResultLog";
import { getToken } from "../controllers/useAuth";
import * as toolResultLogsService from "../services/toolResultLogsService";
import type { LogsFilters } from "../services/toolResultLogsService";

export async function getSessionLogs(
  sessionId: string,
  filters?: LogsFilters,
): Promise<{ total: number; logs: ToolResultLog[] }> {
  const token = getToken();
  if (!token) return { total: 0, logs: [] };
  return toolResultLogsService.fetchSessionLogs(token, sessionId, filters);
}
