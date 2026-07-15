import { Outlet, useParams } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { SectionSwitcher } from "../components/SectionSwitcher";
import { BottomNav } from "../components/BottomNav";
import type { Session } from "../types/session";

interface AppLayoutProps {
  sessions: Session[];
  onDeleteSession: (id: string) => Promise<void>;
}

export function AppLayout({ sessions, onDeleteSession }: AppLayoutProps) {
  const { sessionId } = useParams();

  return (
    <div style={{ display: "flex", height: "100vh", background: "var(--ares-bg)" }}>
      <div className="hidden md:block">
        <Sidebar sessions={sessions} onDeleteSession={onDeleteSession} />
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {sessionId && (
          <div className="hidden md:block" style={{ padding: "20px 24px 0" }}>
            <SectionSwitcher />
          </div>
        )}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
          <Outlet />
        </div>
        <div className="md:hidden">
          <BottomNav />
        </div>
      </div>
    </div>
  );
}
