import type { ToolResultLog } from "../types/toolResultLog";

const API_URL = import.meta.env.VITE_API_URL;

export interface LogsFilters {
  phase?: string;
  tool?: string;
  from_dt?: string;
  to_dt?: string;
  limit?: number;
  offset?: number;
}

export interface LogsResponse {
  total: number;
  logs: ToolResultLog[];
}

export async function fetchSessionLogs(
  token: string,
  sessionId: string,
  filters?: LogsFilters,
): Promise<LogsResponse> {
  const params = new URLSearchParams();
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
  }
  const query = params.toString();

  const response = await fetch(
    `${API_URL}/sessions/${sessionId}/logs${query ? `?${query}` : ""}`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (!response.ok) {
    throw new Error("toolResultLogsService.fetchSessionLogs: request failed");
  }
  return response.json();
}
