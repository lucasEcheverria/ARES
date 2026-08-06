import { useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import { createSession } from "../proxies/sessionsProxy";
import type { AppOutletContext } from "../types/outletContext";

export function NewSessionPage() {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const navigate = useNavigate();
  const { refetchSessions } = useOutletContext<AppOutletContext>();
  const canStart = Boolean(name && target);

  async function handleStart() {
    if (!canStart) return;
    const session = await createSession(name, target);
    if (!session) return;
    refetchSessions();
    navigate(`/session/${session.id}/report`);
  }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
      <div style={{ width: 360 }}>
        <h2 style={{ margin: "0 0 20px", fontSize: 18, fontWeight: 600, color: "var(--ares-text)" }}>New session</h2>
        <label style={{ display: "block", fontSize: 12, fontWeight: 500, color: "var(--ares-text-muted)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Name
        </label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My session"
          style={{
            width: "100%", padding: "9px 12px", fontSize: 13, marginBottom: 16,
            border: "1px solid var(--ares-border)", borderRadius: 6,
            background: "var(--ares-surface)", color: "var(--ares-text)",
            outline: "none", fontFamily: "JetBrains Mono, monospace", boxSizing: "border-box",
          }}
        />
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
          disabled={!canStart}
          onClick={handleStart}
          style={{
            width: "100%", padding: "10px 16px", fontSize: 14, fontWeight: 500, cursor: canStart ? "pointer" : "default",
            border: "none", borderRadius: 6,
            background: canStart ? "var(--ares-blue)" : "var(--ares-border-strong)",
            color: "#fff", opacity: canStart ? 1 : 0.5,
          }}
        >Start</button>
      </div>
    </div>
  );
}
