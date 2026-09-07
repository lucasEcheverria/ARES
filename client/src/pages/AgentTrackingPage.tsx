import { useParams } from "react-router-dom";
import { SessionTrackingView } from "../components/SessionTrackingView";

export function AgentTrackingPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  return <SessionTrackingView sessionId={sessionId ?? ""} />;
}
