import type { Session } from "../types/session";

/**
 * Real backend access for sessions. Not implemented yet — server/ does not
 * exist as a working API. Calling these throws on purpose so a misused
 * proxy fails loudly instead of silently returning nothing.
 */

export async function fetchSessions(): Promise<Session[]> {
  throw new Error("sessionsService.fetchSessions: backend not implemented yet");
}

export async function createSession(_target: string): Promise<Session> {
  throw new Error("sessionsService.createSession: backend not implemented yet");
}
