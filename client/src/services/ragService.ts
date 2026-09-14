import type { RagQueryResponse } from "../types/rag";

const API_URL = import.meta.env.VITE_API_URL;

export async function postSessionQuery(
  token: string,
  sessionId: string,
  question: string,
): Promise<RagQueryResponse> {
  const response = await fetch(`${API_URL}/sessions/${sessionId}/query`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    throw new Error("ragService.postSessionQuery: request failed");
  }
  return response.json();
}
