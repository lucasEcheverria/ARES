import { useParams } from "react-router-dom";
import { useSessionStatus } from "../controllers/useSessionStatus";
import { GraphRagPanel } from "../components/GraphRagPanel";
import { SessionTrackingView } from "../components/SessionTrackingView";

export function AgentTrackingPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const currentSessionId = sessionId ?? "";
  const { session } = useSessionStatus(currentSessionId);
  const isRunning = session === undefined || session.status === "running";

  return (
    <>
      <SessionTrackingView sessionId={currentSessionId} />
      {sessionId && <GraphRagPanel sessionId={sessionId} isRunning={isRunning} />}
    </>
  );
}
