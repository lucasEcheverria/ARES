import { useSessionStatus } from "../controllers/useSessionStatus";
import { useAgentTracking } from "../controllers/useAgentTracking";
import { AgentGraph } from "./AgentGraph";

interface SessionTrackingViewProps {
  sessionId: string;
}

export function SessionTrackingView({ sessionId }: SessionTrackingViewProps) {
  const { session } = useSessionStatus(sessionId);
  const isRunning = session === undefined || session.status === "running";
  const { events, isLoading } = useAgentTracking(sessionId, isRunning);

  if (isLoading) return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Loading...</p>;
  return <AgentGraph events={events} />;
}
