import { useEffect, useState } from "react";
import type { Session } from "../types/session";
import { getSessions, deleteSession as deleteSessionProxy } from "../proxies/sessionsProxy";

export function useSessionList(isAuthenticated: boolean) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!isAuthenticated) {
      setSessions([]);
      setIsLoading(false);
      return;
    }

    let isMounted = true;
    setIsLoading(true);
    getSessions().then((data) => {
      if (isMounted) {
        setSessions(data);
        setIsLoading(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [isAuthenticated]);

  async function deleteSession(id: string) {
    await deleteSessionProxy(id);
    setSessions((current) => current.filter((session) => session.id !== id));
  }

  return { sessions, isLoading, deleteSession };
}
