import { useEffect, useState } from "react";
import type { Session } from "../types/session";
import { getSessionById } from "../proxies/sessionsProxy";

const POLL_INTERVAL_MS = 5000;

export function useSessionStatus(sessionId: string, onSettled?: (session: Session) => void) {
  const [session, setSession] = useState<Session | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    let intervalId: ReturnType<typeof setInterval> | undefined;

    async function poll() {
      const data = await getSessionById(sessionId);
      if (!isMounted) return;

      if (data) {
        setSession(data);
        if (data.status !== "running") {
          if (intervalId !== undefined) clearInterval(intervalId);
          onSettled?.(data);
        }
      }
      setIsLoading(false);
    }

    poll();
    intervalId = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      isMounted = false;
      if (intervalId !== undefined) clearInterval(intervalId);
    };
  }, [sessionId, onSettled]);

  return { session, isLoading };
}
