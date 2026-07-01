import type { Report, SessionNotes } from "../types/report";
import { mockReportsBySession, mockNotesBySession } from "../mocks/reports.mock";

export async function getReport(sessionId: string): Promise<Report | undefined> {
  return mockReportsBySession[sessionId];
}

export async function getNotes(sessionId: string): Promise<SessionNotes | undefined> {
  return mockNotesBySession[sessionId];
}

export async function saveNotes(sessionId: string, content: string): Promise<SessionNotes> {
  const updated: SessionNotes = {
    sessionId,
    content,
    updatedAt: new Date().toISOString(),
  };
  mockNotesBySession[sessionId] = updated;
  return updated;
}
