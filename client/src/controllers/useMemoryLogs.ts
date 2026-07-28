import { useEffect, useMemo, useState } from "react";
import type { ToolResultLog } from "../types/toolResultLog";
import type { AgentPhase } from "../types/session";
import { getSessionLogs } from "../proxies/toolResultLogsProxy";
import type { LogsFilters } from "../services/toolResultLogsService";

export interface MemoryLogsFilters {
  phase: AgentPhase | "all";
  tool: string | "all";
  from: string; // datetime-local input value, empty = no lower bound
  to: string; // datetime-local input value, empty = no upper bound
}

const EMPTY_FILTERS: MemoryLogsFilters = {
  phase: "all",
  tool: "all",
  from: "",
  to: "",
};

function toLogsFilters(filters: MemoryLogsFilters): LogsFilters {
  return {
    phase: filters.phase !== "all" ? filters.phase : undefined,
    tool: filters.tool !== "all" ? filters.tool : undefined,
    from_dt: filters.from ? new Date(filters.from).toISOString() : undefined,
    to_dt: filters.to ? new Date(filters.to).toISOString() : undefined,
  };
}

export function useMemoryLogs(sessionId: string) {
  const [logs, setLogs] = useState<ToolResultLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filters, setFilters] = useState<MemoryLogsFilters>(EMPTY_FILTERS);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getSessionLogs(sessionId, toLogsFilters(filters)).then((data) => {
      if (isMounted) {
        setLogs(data.logs);
        setIsLoading(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId, filters]);

  const availableTools = useMemo(() => {
    const tools = new Set<string>();
    logs.forEach((log) => log.tool && tools.add(log.tool));
    return Array.from(tools);
  }, [logs]);

  function updateFilter<K extends keyof MemoryLogsFilters>(key: K, value: MemoryLogsFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function resetFilters() {
    setFilters(EMPTY_FILTERS);
  }

  return { logs, isLoading, filters, updateFilter, resetFilters, availableTools };
}
