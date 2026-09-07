export type SessionStatus = "running" | "completed" | "failed";

export type HostStatus = "pending" | "running" | "complete" | "failed";

export interface DiscoveryMetadata {
  ip: string;
  mac: string | null;
  serviceTypes: string[];
  responsePort: number | null;
}

export interface Session {
  id: string;
  userId: string;
  name: string;
  target: string;
  status: SessionStatus;
  currentPhase: AgentPhase | null;
  parentSessionId: string | null;
  hostStatus: HostStatus | null;
  failureReason: string | null;
  deviceType: string | null;
  discoveryMetadata: DiscoveryMetadata | null;
  createdAt: string;
  updatedAt: string;
}

export type AgentPhase = "RECON" | "ENUMERATION" | "VULN_SCAN" | "REPORT";

export interface Macrosession extends Session {
  children: Session[];
  hostStatusSummary: Record<string, number>;
}
