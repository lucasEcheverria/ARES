import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { getToken } from "../controllers/useAuth";
import { createSession } from "../services/sessionsService";

export function NewSessionPage() {
  const [target, setTarget] = useState("");
  const navigate = useNavigate();

  async function handleStart() {
    const token = getToken();
    if (!token || !target) return;
    const session = await createSession(token, target);
    navigate(`/session/${session.id}/report`);
  }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
      <div style={{ width: 360 }}>
        <h2 style={{ margin: "0 0 20px", fontSize: 18, fontWeight: 600, color: "var(--ares-text)" }}>Nueva sesión</h2>
        <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: "var(--ares-text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Target
        </label>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="localhost:8080"
          style={{
            width: "100%", padding: "9px 12px", fontSize: 13, marginBottom: 16,
            border: "1px solid var(--ares-border)", borderRadius: 6,
            background: "var(--ares-surface)", color: "var(--ares-text)",
            outline: "none", fontFamily: "JetBrains Mono, monospace", boxSizing: "border-box",
          }}
        />
        <button
          disabled={!target}
          onClick={handleStart}
          style={{
            width: "100%", padding: "10px 16px", fontSize: 14, fontWeight: 500, cursor: target ? "pointer" : "default",
            border: "none", borderRadius: 6,
            background: target ? "var(--ares-blue)" : "var(--ares-border-strong)",
            color: "#fff", opacity: target ? 1 : 0.5,
          }}
        >Start</button>
      </div>
    </div>
  );
}
