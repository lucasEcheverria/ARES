import { useEffect, useState } from "react";
import type { Macrosession } from "../types/session";
import { getMacrosessionById } from "../proxies/sessionsProxy";

const POLL_INTERVAL_MS = 5000;

export function useMacrosession(macrosessionId: string) {
  const [macrosession, setMacrosession] = useState<Macrosession | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    let intervalId: ReturnType<typeof setInterval> | undefined;

    async function poll() {
      const data = await getMacrosessionById(macrosessionId);
      if (!isMounted) return;

      if (data) {
        setMacrosession(data);
        if (data.status !== "running" && intervalId !== undefined) {
          clearInterval(intervalId);
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
  }, [macrosessionId]);

  return { macrosession, isLoading };
}
