import { useNavigate, useParams } from "react-router-dom";
import type { Macrosession, Session } from "../types/session";

interface SidebarProps {
  individualSessions: Session[];
  macrosessions: Macrosession[];
  onDeleteSession: (id: string) => Promise<void>;
}

function dotColor(status: Session["status"]) {
  if (status === "running") return "var(--ares-blue)";
  if (status === "failed") return "var(--ares-red)";
  return "var(--ares-border-strong)";
}

function statusLabel(status: Session["status"]) {
  if (status === "running") return "Running";
  if (status === "failed") return "Failed";
  return "Completed";
}

function progressLabel(session: Macrosession): string {
  const summary = session.hostStatusSummary;
  const total = Object.values(summary).reduce((sum, count) => sum + count, 0);
  const done = summary.complete ?? 0;
  const failed = summary.failed ?? 0;
  return failed > 0 ? `${done}/${total} completed, ${failed} failed` : `${done}/${total} completed`;
}

export function Sidebar({ individualSessions, macrosessions, onDeleteSession }: SidebarProps) {
  const navigate = useNavigate();
  const { sessionId: activeId } = useParams();

  async function handleDelete(session: Session) {
    if (!confirm(`Delete session "${session.name}"? This action cannot be undone.`)) {
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
        >+ New session</button>
      </div>

      <nav style={{ flex: 1, overflowY: "auto", padding: "0 8px", display: "flex", flexDirection: "column" }}>
        <div style={{ flex: 1 }}>
          {individualSessions.length === 0 && (
            <p style={{ padding: "8px 10px", fontSize: 12, color: "var(--ares-text-dim)" }}>
              No sessions yet
            </p>
          )}
          {individualSessions.map((session) => (
            <SessionRow
              key={session.id}
              session={session}
              isActive={session.id === activeId}
              subtitle={`${session.target} · ${statusLabel(session.status)}`}
              onNavigate={() => navigate(`/session/${session.id}/report`)}
              onDelete={() => handleDelete(session)}
            />
          ))}
        </div>

        <div style={{ borderTop: "1px solid var(--ares-border)", marginTop: 8, paddingTop: 8 }}>
          <p style={{
            padding: "4px 10px", fontSize: 11, fontWeight: 600, color: "var(--ares-text-dim)",
            textTransform: "uppercase", letterSpacing: "0.05em",
          }}>
            Subnet scans
          </p>
          {macrosessions.length === 0 && (
            <p style={{ padding: "8px 10px", fontSize: 12, color: "var(--ares-text-dim)" }}>
              No subnet scans yet
            </p>
          )}
          {macrosessions.map((session) => (
            <SessionRow
              key={session.id}
              session={session}
              isActive={session.id === activeId}
              subtitle={`${session.target} · ${progressLabel(session)}`}
              onNavigate={() => navigate(`/session/${session.id}/topology`)}
              onDelete={() => handleDelete(session)}
            />
          ))}
        </div>
      </nav>
    </aside>
  );
}

interface SessionRowProps {
  session: Session;
  isActive: boolean;
  subtitle: string;
  onNavigate: () => void;
  onDelete: () => void;
}

function SessionRow({ session, isActive, subtitle, onNavigate, onDelete }: SessionRowProps) {
  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 4,
        borderRadius: 6, marginBottom: 2,
        border: "1px solid transparent",
        background: isActive ? "var(--ares-blue-dim)" : "transparent",
        borderColor: isActive ? "var(--ares-blue-border)" : "transparent",
      }}
    >
      <button
        onClick={onNavigate}
        style={{
          flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 8,
          padding: "8px 10px", textAlign: "left", cursor: "pointer",
          border: "none", background: "transparent",
        }}
      >
        <span style={{ width: 7, height: 7, borderRadius: "50%", flexShrink: 0, background: dotColor(session.status) }} />
        <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
          <span style={{
            fontSize: 13, fontWeight: 500, color: "var(--ares-text)",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {session.name}
          </span>
          <span style={{
            fontSize: 11, color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {subtitle}
          </span>
        </span>
      </button>
      <button
        onClick={onDelete}
        aria-label={`Delete session ${session.name}`}
        title="Delete session"
        style={{
          flexShrink: 0, width: 22, height: 22, marginRight: 6, padding: 0,
          display: "flex", alignItems: "center", justifyContent: "center",
          border: "none", borderRadius: 4, background: "transparent",
          color: "var(--ares-text-dim)", cursor: "pointer", fontSize: 14, lineHeight: 1,
        }}
      >&times;</button>
    </div>
  );
}
