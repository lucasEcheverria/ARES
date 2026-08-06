import { useEffect, useState } from "react";
import type { AgentEvent } from "../types/agentEvent";
import { getSessionEvents } from "../proxies/eventsProxy";

const POLL_INTERVAL_MS = 5000;

export function useAgentTracking(sessionId: string, isRunning: boolean) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    let intervalId: ReturnType<typeof setInterval> | undefined;

    async function fetchEvents() {
      const data = await getSessionEvents(sessionId);
      if (isMounted) {
        setEvents(data);
        setIsLoading(false);
      }
    }

    fetchEvents();
    if (isRunning) {
      intervalId = setInterval(fetchEvents, POLL_INTERVAL_MS);
    }

    return () => {
      isMounted = false;
      if (intervalId !== undefined) clearInterval(intervalId);
    };
  }, [sessionId, isRunning]);

  return { events, isLoading };
}
