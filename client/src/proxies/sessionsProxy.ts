import type { Session } from "../types/session";
import { mockSessions } from "../mocks/sessions.mock";

/**
 * Single point of truth for "where do session reads come from".
 * Today: always mock data. Later: will switch to sessionsService (real API)
 * without callers (controllers/components) needing to change.
 */

export async function getSessions(): Promise<Session[]> {
  return mockSessions;
}

export async function getSessionById(id: string): Promise<Session | undefined> {
  return mockSessions.find((session) => session.id === id);
}
