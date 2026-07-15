import type { Session } from "../types/session";

const API_URL = import.meta.env.VITE_API_URL;

export async function fetchSessions(token: string): Promise<Session[]> {
  const response = await fetch(`${API_URL}/sessions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.fetchSessions: request failed");
  }
  return response.json();
}

export async function fetchSessionById(token: string, sessionId: string): Promise<Session> {
  const response = await fetch(`${API_URL}/sessions/${sessionId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.fetchSessionById: request failed");
  }
  return response.json();
}

export async function createSession(token: string, target: string): Promise<Session> {
  const response = await fetch(`${API_URL}/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ target }),
  });
  if (!response.ok) {
    throw new Error("sessionsService.createSession: request failed");
  }
  return response.json();
}

export async function deleteSession(token: string, sessionId: string): Promise<void> {
  const response = await fetch(`${API_URL}/sessions/${sessionId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.deleteSession: request failed");
  }
}
