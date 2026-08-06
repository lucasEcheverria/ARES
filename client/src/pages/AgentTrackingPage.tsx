import { useParams } from "react-router-dom";
import { useSessionStatus } from "../controllers/useSessionStatus";
import { useAgentTracking } from "../controllers/useAgentTracking";
import { AgentGraph } from "../components/AgentGraph";

export function AgentTrackingPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { session } = useSessionStatus(sessionId ?? "");
  const isRunning = session === undefined || session.status === "running";
  const { events, isLoading } = useAgentTracking(sessionId ?? "", isRunning);

  if (isLoading) return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Loading...</p>;
  return <AgentGraph events={events} />;
}
