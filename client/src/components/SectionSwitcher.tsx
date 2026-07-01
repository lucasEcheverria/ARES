import { useNavigate, useLocation, useParams } from "react-router-dom";

const SECTIONS = [
  { key: "tracking", label: "Seguimiento del agente" },
  { key: "report",   label: "Reporte" },
];

export function SectionSwitcher() {
  const navigate = useNavigate();
  const location = useLocation();
  const { sessionId } = useParams();

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 20 }}>
      {SECTIONS.map((section) => {
        const path = `/session/${sessionId}/${section.key}`;
        const isActive = location.pathname === path;
        return (
          <button
            key={section.key}
            onClick={() => navigate(path)}
            style={{
              textAlign: "left", padding: "12px 16px", cursor: "pointer",
              border: `1px solid ${isActive ? "var(--ares-blue-border)" : "var(--ares-border)"}`,
              background: isActive ? "var(--ares-blue-dim)" : "var(--ares-surface)",
              borderRadius: 8,
              transition: "border-color 0.15s, background 0.15s",
            }}
          >
            <p style={{
              margin: 0, fontSize: 13, fontWeight: 500,
              color: isActive ? "var(--ares-blue-text)" : "var(--ares-text)",
            }}>
              {section.label}
            </p>
          </button>
        );
      })}
    </div>
  );
}
