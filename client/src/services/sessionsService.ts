import type { Macrosession, Session } from "../types/session";

const API_URL = import.meta.env.VITE_API_URL;

export async function fetchSessions(token: string, type?: "individual"): Promise<Session[]> {
  const url = type ? `${API_URL}/sessions?type=${type}` : `${API_URL}/sessions`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.fetchSessions: request failed");
  }
  return response.json();
}

export async function fetchMacrosessionsList(token: string): Promise<Macrosession[]> {
  const response = await fetch(`${API_URL}/sessions?type=macro`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.fetchMacrosessionsList: request failed");
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

export async function fetchMacrosessionById(token: string, macrosessionId: string): Promise<Macrosession> {
  const response = await fetch(`${API_URL}/sessions/${macrosessionId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error("sessionsService.fetchMacrosessionById: request failed");
  }
  return response.json();
}

export async function createSession(token: string, name: string, target: string): Promise<Session> {
  const response = await fetch(`${API_URL}/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ mode: "single", name, target }),
  });
  if (!response.ok) {
    throw new Error("sessionsService.createSession: request failed");
  }
  return response.json();
}

export async function createSubnetSession(
  token: string,
  name: string,
  cidr: string,
): Promise<Macrosession> {
  const response = await fetch(`${API_URL}/sessions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ mode: "subnet", name, cidr }),
  });
  if (!response.ok) {
    throw new Error("sessionsService.createSubnetSession: request failed");
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
