import { useNavigate, useParams } from "react-router-dom";
import type { Session } from "../types/session";

interface SidebarProps {
  sessions: Session[];
  onDeleteSession: (id: string) => Promise<void>;
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

export function Sidebar({ sessions, onDeleteSession }: SidebarProps) {
  const navigate = useNavigate();
  const { sessionId: activeId } = useParams();

  async function handleDelete(session: Session) {
    if (!confirm(`¿Eliminar la sesión contra "${session.target}"? Esta acción no se puede deshacer.`)) {
      return;
    }
    await onDeleteSession(session.id);
    if (session.id === activeId) {
      navigate("/new-session");
    }
  }

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
        {sessions.length === 0 && (
          <p style={{ padding: "8px 10px", fontSize: 12, color: "var(--ares-text-dim)" }}>
            No hay sesiones aún
          </p>
        )}
        {sessions.map((session) => {
          const isActive = session.id === activeId;
          return (
            <div
              key={session.id}
              style={{
                display: "flex", alignItems: "center", gap: 4,
                borderRadius: 6, marginBottom: 2,
                border: "1px solid transparent",
                background: isActive ? "var(--ares-blue-dim)" : "transparent",
                borderColor: isActive ? "var(--ares-blue-border)" : "transparent",
              }}
            >
              <button
                onClick={() => navigate(`/session/${session.id}/report`)}
                style={{
                  flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 8,
                  padding: "8px 10px", textAlign: "left", cursor: "pointer",
                  border: "none", background: "transparent",
                }}
              >
                <span style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: dotColor(session.status) }} />
                <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                  <span style={{
                    fontSize: 13, fontWeight: 500, color: "var(--ares-text)", fontFamily: "JetBrains Mono, monospace",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {session.target}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--ares-text-muted)" }}>
                    {statusLabel(session.status)}
                  </span>
                </span>
              </button>
              <button
                onClick={() => handleDelete(session)}
                aria-label={`Eliminar sesión ${session.target}`}
                title="Eliminar sesión"
                style={{
                  flexShrink: 0, width: 22, height: 22, marginRight: 6, padding: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  border: "none", borderRadius: 4, background: "transparent",
                  color: "var(--ares-text-dim)", cursor: "pointer", fontSize: 14, lineHeight: 1,
                }}
              >&times;</button>
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
