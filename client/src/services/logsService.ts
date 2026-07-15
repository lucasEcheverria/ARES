import type { AgentEvent } from "../types/agentEvent";

const API_URL = import.meta.env.VITE_API_URL;

export interface LogsFilters {
  phase?: string;
  type?: string;
  tool?: string;
  from_dt?: string;
  to_dt?: string;
  limit?: number;
  offset?: number;
}

export interface LogsResponse {
  total: number;
  logs: AgentEvent[];
}

interface RawLogEntry {
  id: string;
  sessionId: string;
  sequence: number;
  phase: AgentEvent["phase"];
  type: AgentEvent["type"];
  tool?: string;
  content: string;
  createdAt: string;
}

function toAgentEvent(raw: RawLogEntry): AgentEvent {
  return {
    id: raw.id,
    sessionId: raw.sessionId,
    timestamp: raw.createdAt,
    phase: raw.phase,
    type: raw.type,
    tool: raw.tool,
    content: raw.content,
  };
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
    throw new Error("logsService.fetchSessionLogs: request failed");
  }
  const data: { total: number; logs: RawLogEntry[] } = await response.json();
  return { total: data.total, logs: data.logs.map(toAgentEvent) };
}
