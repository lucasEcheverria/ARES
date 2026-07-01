import { useEffect, useMemo, useState } from "react";
import type { AgentEvent, AgentEventType } from "../types/agentEvent";
import type { AgentPhase } from "../types/session";
import { getSessionEvents } from "../proxies/eventsProxy";

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

export function useMemoryLogs(sessionId: string) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [filters, setFilters] = useState<MemoryLogsFilters>(EMPTY_FILTERS);

  useEffect(() => {
    let isMounted = true;
    getSessionEvents(sessionId).then((data) => {
      if (isMounted) setEvents(data);
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId]);

  const availableTools = useMemo(() => {
    const tools = new Set<string>();
    events.forEach((event) => event.tool && tools.add(event.tool));
    return Array.from(tools);
  }, [events]);

  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      if (filters.type !== "all" && event.type !== filters.type) return false;
      if (filters.phase !== "all" && event.phase !== filters.phase) return false;
      if (filters.tool !== "all" && event.tool !== filters.tool) return false;
      const timestamp = new Date(event.timestamp).getTime();
      if (filters.from && timestamp < new Date(filters.from).getTime()) return false;
      if (filters.to && timestamp > new Date(filters.to).getTime()) return false;
      return true;
    });
  }, [events, filters]);

  function updateFilter<K extends keyof MemoryLogsFilters>(key: K, value: MemoryLogsFilters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function resetFilters() {
    setFilters(EMPTY_FILTERS);
  }

  return { events: filteredEvents, filters, updateFilter, resetFilters, availableTools };
}
