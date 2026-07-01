import { useEffect, useState } from "react";
import type { AgentEvent } from "../types/agentEvent";
import { getSessionEvents } from "../proxies/eventsProxy";

export function useAgentTracking(sessionId: string) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getSessionEvents(sessionId).then((data) => {
      if (isMounted) {
        setEvents(data);
        setIsLoading(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId]);

  return { events, isLoading };
}
