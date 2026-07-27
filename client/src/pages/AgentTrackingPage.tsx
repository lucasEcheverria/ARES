import { useParams } from "react-router-dom";
import { useAgentTracking } from "../controllers/useAgentTracking";
import { AgentGraph } from "../components/AgentGraph";

export function AgentTrackingPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { events, isLoading } = useAgentTracking(sessionId ?? "");
  if (isLoading) return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Loading...</p>;
  return <AgentGraph events={events} />;
}
