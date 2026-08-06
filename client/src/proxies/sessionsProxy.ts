import type { Session } from "../types/session";
import { getToken } from "../controllers/useAuth";
import * as sessionsService from "../services/sessionsService";

export async function getSessions(): Promise<Session[]> {
  const token = getToken();
  if (!token) return [];
  return sessionsService.fetchSessions(token);
}

export async function getSessionById(id: string): Promise<Session | undefined> {
  const token = getToken();
  if (!token) return undefined;
  return sessionsService.fetchSessionById(token, id).catch(() => undefined);
}

export async function deleteSession(id: string): Promise<void> {
  const token = getToken();
  if (!token) return;
  return sessionsService.deleteSession(token, id);
}

export async function createSession(name: string, target: string): Promise<Session | undefined> {
  const token = getToken();
  if (!token) return undefined;
  return sessionsService.createSession(token, name, target);
}
