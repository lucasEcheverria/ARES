import { useNavigate, useParams } from "react-router-dom";
import type { Session } from "../types/session";

interface SidebarProps {
  sessions: Session[];
}

function dotColor(status: Session["status"]) {
  if (status === "running") return "var(--ares-blue)";
  if (status === "failed") return "var(--ares-red)";
  return "var(--ares-border-strong)";
}

function statusLabel(status: Session["status"]) {
  if (status === "running") return "En curso";
  if (status === "failed") return "Fallida";
  return "Completada";
}

export function Sidebar({ sessions }: SidebarProps) {
  const navigate = useNavigate();
  const { sessionId: activeId } = useParams();

  return (
    <aside style={{
      width: 224, flexShrink: 0, height: "100%", display: "flex", flexDirection: "column",
      background: "var(--ares-surface)", borderRight: "1px solid var(--ares-border)",
    }}>
      <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--ares-border)" }}>
        <span style={{ fontSize: 15, fontWeight: 600, color: "var(--ares-blue)" }}>ARES</span>
      </div>

      <div style={{ padding: "10px 12px" }}>
        <button
          onClick={() => navigate("/new-session")}
          style={{
            width: "100%", padding: "8px 12px", fontSize: 13, fontWeight: 500,
            border: "1px solid var(--ares-blue-border)", borderRadius: 6,
            background: "var(--ares-blue-dim)", color: "var(--ares-blue-text)", cursor: "pointer",
          }}
        >+ Nueva sesión</button>
      </div>

      <nav style={{ flex: 1, overflowY: "auto", padding: "0 8px" }}>
        {sessions.map((session) => {
          const isActive = session.id === activeId;
          return (
            <button
              key={session.id}
              onClick={() => navigate(`/session/${session.id}/report`)}
              style={{
                width: "100%", display: "flex", alignItems: "center", gap: 8,
                padding: "8px 10px", textAlign: "left", cursor: "pointer",
                border: "1px solid transparent",
                borderRadius: 6, marginBottom: 2,
                background: isActive ? "var(--ares-blue-dim)" : "transparent",
                borderColor: isActive ? "var(--ares-blue-border)" : "transparent",
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: dotColor(session.status) }} />
              <span style={{ display: "flex", flexDirection: "column" }}>
                <span style={{ fontSize: 13, fontWeight: 500, color: "var(--ares-text)", fontFamily: "JetBrains Mono, monospace" }}>
                  {session.target}
                </span>
                <span style={{ fontSize: 11, color: "var(--ares-text-muted)" }}>
                  {statusLabel(session.status)}
                </span>
              </span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
