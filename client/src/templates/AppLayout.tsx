import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { SectionSwitcher } from "../components/SectionSwitcher";
import { BottomNav } from "../components/BottomNav";
import type { Macrosession, Session } from "../types/session";
import type { AppOutletContext } from "../types/outletContext";

interface AppLayoutProps {
  individualSessions: Session[];
  macrosessions: Macrosession[];
  onDeleteSession: (id: string) => Promise<void>;
  onRefetchSessions: () => void;
}

export function AppLayout({ individualSessions, macrosessions, onDeleteSession, onRefetchSessions }: AppLayoutProps) {
  const location = useLocation();
  const showSectionSwitcher = /^\/session\/[^/]+\/(tracking|report)$/.test(location.pathname);

  return (
    <div style={{ display: "flex", height: "100vh", background: "var(--ares-bg)" }}>
      <div className="hidden md:block">
        <Sidebar individualSessions={individualSessions} macrosessions={macrosessions} onDeleteSession={onDeleteSession} />
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        {showSectionSwitcher && (
          <div className="hidden md:block" style={{ padding: "20px 24px 0" }}>
            <SectionSwitcher />
          </div>
        )}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 24px" }}>
          <Outlet context={{ refetchSessions: onRefetchSessions } satisfies AppOutletContext} />
        </div>
        <div className="md:hidden">
          <BottomNav />
        </div>
      </div>
    </div>
  );
}
