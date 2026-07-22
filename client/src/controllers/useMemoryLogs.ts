import { useEffect, useMemo, useState } from "react";
import type { AgentEvent, AgentEventType } from "../types/agentEvent";
import type { AgentPhase } from "../types/session";
import { getSessionLogs } from "../proxies/logsProxy";
import type { LogsFilters } from "../services/logsService";

export interface MemoryLogsFilters {
  type: AgentEventType | "all";
  phase: AgentPhase | "all";
  tool: string | "all";
  from: string; // datetime-local input value, empty = no lower bound
  to: string; // datetime-local input value, empty = no upper bound
}

const EMPTY_FILTERS: MemoryLogsFilters = {
  type: "all",
  phase: "all",
  tool: "all",
  from: "",
  to: "",
};

function toLogsFilters(filters: MemoryLogsFilters): LogsFilters {
  return {
    type: filters.type !== "all" ? filters.type : undefined,
    phase: filters.phase !== "all" ? filters.phase : undefined,
    tool: filters.tool !== "all" ? filters.tool : undefined,
    from_dt: filters.from ? new Date(filters.from).toISOString() : undefined,
    to_dt: filters.to ? new Date(filters.to).toISOString() : undefined,
  };
}

export function useMemoryLogs(sessionId: string) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [filters, setFilters] = useState<MemoryLogsFilters>(EMPTY_FILTERS);

  useEffect(() => {
    let isMounted = true;
    getSessionLogs(sessionId, toLogsFilters(filters)).then((data) => {
      if (isMounted) setEvents(data.logs);
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId, filters]);

  const availableTools = useMemo(() => {
    const tools = new Set<string>();
    events.forEach((event) => event.tool && tools.add(event.tool));
    return Array.from(tools);
  }, [events]);

  function updateFilter<K extends keyof MemoryLogsFilters>(key: K, value: MemoryLogsFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function resetFilters() {
    setFilters(EMPTY_FILTERS);
  }

  return { events, filters, updateFilter, resetFilters, availableTools };
}
