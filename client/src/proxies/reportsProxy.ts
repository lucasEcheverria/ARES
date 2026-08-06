import type { ReportFetchResult, SessionNotes } from "../types/report";
import { mockNotesBySession } from "../mocks/reports.mock";
import { getToken } from "../controllers/useAuth";
import * as reportsService from "../services/reportsService";

export async function getReport(sessionId: string): Promise<ReportFetchResult> {
  const token = getToken();
  if (!token) return { kind: "error" };
  return reportsService.fetchReport(token, sessionId);
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
