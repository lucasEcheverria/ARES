import { useState } from "react";
import { Outlet, useParams } from "react-router-dom";
import { Sidebar } from "../components/Sidebar";
import { SectionSwitcher } from "../components/SectionSwitcher";
import { BottomNav } from "../components/BottomNav";
import type { Session } from "../types/session";
import type { AppOutletContext, RagConversation } from "../types/outletContext";

interface AppLayoutProps {
  sessions: Session[];
  onDeleteSession: (id: string) => Promise<void>;
  onRefetchSessions: () => void;
}

const IDLE_RAG_CONVERSATION: RagConversation = {
  question: "",
  answer: null,
  sources: [],
  status: "idle",
};

export function AppLayout({ sessions, onDeleteSession, onRefetchSessions }: AppLayoutProps) {
  const { sessionId } = useParams();
  const [ragConversations, setRagConversations] = useState<Record<string, RagConversation>>({});

  function updateRagConversation(sessionId: string, partial: Partial<RagConversation>) {
    setRagConversations((prev) => ({
      ...prev,
      [sessionId]: { ...(prev[sessionId] ?? IDLE_RAG_CONVERSATION), ...partial },
    }));
  }

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
          <Outlet
            context={{
              refetchSessions: onRefetchSessions,
              ragConversations,
              updateRagConversation,
            } satisfies AppOutletContext}
          />
        </div>
        <div className="md:hidden">
          <BottomNav />
        </div>
      </div>
    </div>
  );
}
