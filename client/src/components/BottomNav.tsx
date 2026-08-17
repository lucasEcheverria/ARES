import { useNavigate, useLocation, useParams } from "react-router-dom";

export function BottomNav() {
  const navigate = useNavigate();
  const location = useLocation();
  const { sessionId } = useParams();

  const items = [
    { key: "history",  label: "History",  path: "/new-session" },
    { key: "tracking", label: "Tracking", path: sessionId ? `/session/${sessionId}/tracking` : null },
    { key: "report",   label: "Report",   path: sessionId ? `/session/${sessionId}/report`   : null },
  ];

  return (
    <nav style={{ borderTop: "1px solid var(--ares-border)", background: "var(--ares-surface)", display: "flex" }}>
      {items.map((item) => {
        const disabled = item.path === null && item.key !== "history";
        const isActive = item.path !== null && location.pathname === item.path;
        return (
          <button
            key={item.key}
            disabled={disabled}
            onClick={() => item.path && navigate(item.path)}
            style={{
              flex: 1, padding: "12px 0", fontSize: 12, fontWeight: 500, cursor: disabled ? "default" : "pointer",
              border: "none", background: "transparent",
              color: isActive ? "var(--ares-blue-text)" : "var(--ares-text-muted)",
              opacity: disabled ? 0.4 : 1,
              borderTop: isActive ? "2px solid var(--ares-blue)" : "2px solid transparent",
            }}
          >{item.label}</button>
        );
      })}
    </nav>
  );
}
