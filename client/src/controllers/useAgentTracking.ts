import { useEffect, useState } from "react";
import type { AgentEvent } from "../types/agentEvent";
import { getSessionLogs } from "../proxies/logsProxy";

export function useAgentTracking(sessionId: string) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getSessionLogs(sessionId).then((data) => {
      if (isMounted) {
        setEvents(data.logs);
        setIsLoading(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId]);

  return { events, isLoading };
}
