import type { AgentPhase } from "./session";

export type AgentEventType = "thought" | "tool_call" | "phase_change";

export interface AgentEvent {
  id: string;
  sessionId: string;
  sequence: number;
  phase: AgentPhase;
  type: AgentEventType;
  tool?: string;
  content: string;
  createdAt: string;
}
