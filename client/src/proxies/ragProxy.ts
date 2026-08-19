import type { RagQueryResponse } from "../types/rag";
import { getToken } from "../controllers/useAuth";
import * as ragService from "../services/ragService";

export async function querySession(sessionId: string, question: string): Promise<RagQueryResponse> {
  const token = getToken();
  if (!token) {
    throw new Error("ragProxy.querySession: not authenticated");
  }
  return ragService.postSessionQuery(token, sessionId, question);
}
