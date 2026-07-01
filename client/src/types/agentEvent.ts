import type { AgentPhase } from "./session";

export type AgentEventType = "thought" | "tool_call" | "tool_result" | "phase_change";

export interface AgentEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  phase: AgentPhase;
  type: AgentEventType;
  tool?: string;
  content: string;
}
