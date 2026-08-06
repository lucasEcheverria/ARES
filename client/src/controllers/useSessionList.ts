import { useCallback, useEffect, useRef, useState } from "react";
import type { Session } from "../types/session";
import { getSessions, deleteSession as deleteSessionProxy } from "../proxies/sessionsProxy";

export function useSessionList(isAuthenticated: boolean) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const refetch = useCallback(async () => {
    if (!isAuthenticated) {
      setSessions([]);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    const data = await getSessions();
    if (isMountedRef.current) {
      setSessions(data);
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  async function deleteSession(id: string) {
    await deleteSessionProxy(id);
    setSessions((current) => current.filter((session) => session.id !== id));
  }

  return { sessions, isLoading, refetch, deleteSession };
}
