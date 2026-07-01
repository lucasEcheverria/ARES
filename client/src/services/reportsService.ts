import type { Report, SessionNotes } from "../types/report";

export async function fetchReport(_sessionId: string): Promise<Report> {
  throw new Error("reportsService.fetchReport: backend not implemented yet");
}

export async function fetchNotes(_sessionId: string): Promise<SessionNotes> {
  throw new Error("reportsService.fetchNotes: backend not implemented yet");
}

export async function saveNotes(_sessionId: string, _content: string): Promise<SessionNotes> {
  throw new Error("reportsService.saveNotes: backend not implemented yet");
}
