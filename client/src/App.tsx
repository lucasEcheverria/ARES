import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./controllers/useAuth";
import { useSessionList } from "./controllers/useSessionList";
import { AppLayout } from "./templates/AppLayout";
import { LoginPage } from "./pages/LoginPage";
import { NewSessionPage } from "./pages/NewSessionPage";
import { AgentTrackingPage } from "./pages/AgentTrackingPage";
import { ReportPage } from "./pages/ReportPage";
import { MacrosessionTopologyPage } from "./pages/MacrosessionTopologyPage";

function App() {
  const { isAuthenticated, loginWithGoogle } = useAuth();
  const { individualSessions, macrosessions, deleteSession, refetch: refetchSessions } = useSessionList(isAuthenticated);

  if (!isAuthenticated) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="*" element={<LoginPage onLogin={loginWithGoogle} />} />
        </Routes>
      </BrowserRouter>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppLayout individualSessions={individualSessions} macrosessions={macrosessions} onDeleteSession={deleteSession} onRefetchSessions={refetchSessions} />}>
          <Route index element={<Navigate to="/new-session" replace />} />
          <Route path="new-session" element={<NewSessionPage />} />
          <Route path="session/:sessionId/tracking" element={<AgentTrackingPage />} />
          <Route path="session/:sessionId/report" element={<ReportPage />} />
          <Route path="session/:sessionId/topology" element={<MacrosessionTopologyPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;