import { useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import { createSession, createSubnetSession } from "../proxies/sessionsProxy";
import type { AppOutletContext } from "../types/outletContext";

const inputStyle = {
  width: "100%", padding: "9px 12px", fontSize: 13, marginBottom: 16,
  border: "1px solid var(--ares-border)", borderRadius: 6,
  background: "var(--ares-surface)", color: "var(--ares-text)",
  outline: "none", fontFamily: "JetBrains Mono, monospace", boxSizing: "border-box" as const,
};

const labelStyle = {
  display: "block", fontSize: 12, fontWeight: 500, color: "var(--ares-text-muted)",
  marginBottom: 6, textTransform: "uppercase" as const, letterSpacing: "0.05em",
};

export function NewSessionPage() {
  const [mode, setMode] = useState<"single" | "subnet">("single");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [cidr, setCidr] = useState("");
  const navigate = useNavigate();
  const { refetchSessions } = useOutletContext<AppOutletContext>();
  const canStart = mode === "single" ? Boolean(name && target) : Boolean(name && cidr);

  async function handleStart() {
    if (!canStart) return;
    if (mode === "single") {
      const session = await createSession(name, target);
      if (!session) return;
      refetchSessions();
      navigate(`/session/${session.id}/report`);
    } else {
      const macrosession = await createSubnetSession(name, cidr);
      if (!macrosession) return;
      refetchSessions();
      navigate(`/session/${macrosession.id}/topology`);
    }
  }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%" }}>
      <div style={{ width: 360 }}>
        <h2 style={{ margin: "0 0 20px", fontSize: 18, fontWeight: 600, color: "var(--ares-text)" }}>New session</h2>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 20 }}>
          <button
            onClick={() => setMode("single")}
            style={{
              padding: "8px 12px", fontSize: 13, fontWeight: 500, cursor: "pointer",
              border: `1px solid ${mode === "single" ? "var(--ares-blue-border)" : "var(--ares-border)"}`,
              background: mode === "single" ? "var(--ares-blue-dim)" : "var(--ares-surface)",
              color: mode === "single" ? "var(--ares-blue-text)" : "var(--ares-text)",
              borderRadius: 6,
            }}
          >Target</button>
          <button
            onClick={() => setMode("subnet")}
            style={{
              padding: "8px 12px", fontSize: 13, fontWeight: 500, cursor: "pointer",
              border: `1px solid ${mode === "subnet" ? "var(--ares-blue-border)" : "var(--ares-border)"}`,
              background: mode === "subnet" ? "var(--ares-blue-dim)" : "var(--ares-surface)",
              color: mode === "subnet" ? "var(--ares-blue-text)" : "var(--ares-text)",
              borderRadius: 6,
            }}
          >Subnet</button>
        </div>

        <label style={labelStyle}>Name</label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My session"
          style={inputStyle}
        />

        {mode === "single" ? (
          <>
            <label style={labelStyle}>Target</label>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="localhost:8080"
              style={inputStyle}
            />
          </>
        ) : (
          <>
            <label style={labelStyle}>Subnet (CIDR, /24 max)</label>
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="192.168.1.0/24"
              style={inputStyle}
            />
          </>
        )}

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
