import type { AgentPhase } from "./session";

export interface RagSource {
  phase: AgentPhase;
  sequence: number;
  tool?: string | null;
  snippet: string;
}

export interface RagQueryResponse {
  answer: string;
  sources: RagSource[];
}
