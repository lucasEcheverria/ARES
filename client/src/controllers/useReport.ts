import { useEffect, useState } from "react";
import type { Report, SessionNotes } from "../types/report";
import { getReport, getNotes, saveNotes } from "../proxies/reportsProxy";

export function useReport(sessionId: string) {
  const [report, setReport] = useState<Report | undefined>(undefined);
  const [notes, setNotes] = useState<SessionNotes | undefined>(undefined);
  const [notesVisible, setNotesVisible] = useState(true);

  useEffect(() => {
    getReport(sessionId).then(setReport);
    getNotes(sessionId).then(setNotes);
  }, [sessionId]);

  async function updateNotes(content: string) {
    const updated = await saveNotes(sessionId, content);
    setNotes(updated);
  }

  return {
    report,
    notes,
    notesVisible,
    toggleNotesVisible: () => setNotesVisible((value) => !value),
    updateNotes,
  };
}
