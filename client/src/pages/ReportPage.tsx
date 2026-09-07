import { useParams, useOutletContext } from "react-router-dom";
import { SessionReportView } from "../components/SessionReportView";
import type { AppOutletContext } from "../types/outletContext";

export function ReportPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { refetchSessions } = useOutletContext<AppOutletContext>();
  return <SessionReportView sessionId={sessionId ?? ""} onSessionSettled={refetchSessions} />;
}
