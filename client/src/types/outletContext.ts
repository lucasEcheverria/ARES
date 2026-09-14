import type { RagSource } from "./rag";

export type { RagSource };

export interface RagConversation {
  question: string;
  answer: string | null;
  sources: RagSource[];
  status: "idle" | "loading" | "ready" | "error";
}

export interface AppOutletContext {
  refetchSessions: () => void;
  ragConversations: Record<string, RagConversation>;
  updateRagConversation: (sessionId: string, partial: Partial<RagConversation>) => void;
}
