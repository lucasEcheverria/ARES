import type { Macrosession, Session } from "../types/session";
import { getToken } from "../controllers/useAuth";
import * as sessionsService from "../services/sessionsService";

export async function getSessions(type?: "individual"): Promise<Session[]> {
  const token = getToken();
  if (!token) return [];
  return sessionsService.fetchSessions(token, type);
}

export async function getMacrosessionsList(): Promise<Macrosession[]> {
  const token = getToken();
  if (!token) return [];
  return sessionsService.fetchMacrosessionsList(token);
}

export async function getSessionById(id: string): Promise<Session | undefined> {
  const token = getToken();
  if (!token) return undefined;
  return sessionsService.fetchSessionById(token, id).catch(() => undefined);
}

export async function getMacrosessionById(id: string): Promise<Macrosession | undefined> {
  const token = getToken();
  if (!token) return undefined;
  return sessionsService.fetchMacrosessionById(token, id).catch(() => undefined);
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

export async function createSubnetSession(name: string, cidr: string): Promise<Macrosession | undefined> {
  const token = getToken();
  if (!token) return undefined;
  return sessionsService.createSubnetSession(token, name, cidr);
}
