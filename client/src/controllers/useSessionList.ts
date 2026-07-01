import { useEffect, useState } from "react";
import type { Session } from "../types/session";
import { getSessions } from "../proxies/sessionsProxy";

export function useSessionList() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    getSessions().then((data) => {
      if (isMounted) {
        setSessions(data);
        setIsLoading(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, []);

  return { sessions, isLoading };
}
