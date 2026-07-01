export type SessionStatus = "running" | "completed" | "failed";

export interface Session {
  id: string;
  userId: string;
  target: string;
  status: SessionStatus;
  currentPhase: AgentPhase | null;
  createdAt: string;
  updatedAt: string;
}

export type AgentPhase = "RECON" | "ENUMERATION" | "VULN_SCAN" | "REPORT";
