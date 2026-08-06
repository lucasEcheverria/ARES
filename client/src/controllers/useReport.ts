import { useEffect, useState } from "react";
import type { ReportState, SessionNotes } from "../types/report";
import { getReport, getNotes, saveNotes } from "../proxies/reportsProxy";

export function useReport(sessionId: string, shouldFetchReport: boolean) {
  const [reportState, setReportState] = useState<ReportState>({ kind: "loading" });
  const [notes, setNotes] = useState<SessionNotes | undefined>(undefined);
  const [notesVisible, setNotesVisible] = useState(true);

  useEffect(() => {
    if (!shouldFetchReport) {
      setReportState({ kind: "loading" });
      return;
    }
    let isMounted = true;
    getReport(sessionId).then((result) => {
      if (isMounted) setReportState(result);
    });
    return () => {
      isMounted = false;
    };
  }, [sessionId, shouldFetchReport]);

  useEffect(() => {
    getNotes(sessionId).then(setNotes);
  }, [sessionId]);

  async function updateNotes(content: string) {
    const updated = await saveNotes(sessionId, content);
    setNotes(updated);
  }

  return {
    reportState,
    notes,
    notesVisible,
    toggleNotesVisible: () => setNotesVisible((value) => !value),
    updateNotes,
  };
}
