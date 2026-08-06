import type { ReportFetchResult, SessionNotes } from "../types/report";

const API_URL = import.meta.env.VITE_API_URL;

export async function fetchReport(token: string, sessionId: string): Promise<ReportFetchResult> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}/sessions/${sessionId}/report`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    return { kind: "error" };
  }

  if (response.status === 404) {
    return { kind: "not-found" };
  }
  if (!response.ok) {
    return { kind: "error" };
  }

  const markdown = await response.text();
  return { kind: "ready", markdown };
}

export async function fetchNotes(_sessionId: string): Promise<SessionNotes> {
  throw new Error("reportsService.fetchNotes: backend not implemented yet");
}

export async function saveNotes(_sessionId: string, _content: string): Promise<SessionNotes> {
  throw new Error("reportsService.saveNotes: backend not implemented yet");
}
