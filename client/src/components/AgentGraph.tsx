import { useState } from "react";
import type { CSSProperties } from "react";
import type { AgentEvent } from "../types/agentEvent";
import type { AgentPhase } from "../types/session";
import { useZoomPan } from "../controllers/useZoomPan";

interface AgentGraphProps {
  events: AgentEvent[];
}

function firstParamValue(content: string): string {
  const match = content.match(/=(\S+)/);
  return match ? match[1] : content;
}

function nodeLabel(event: AgentEvent): string {
  if (event.type === "thought") {
    const words = event.content.trim().split(/\s+/).slice(0, 6);
    return `${words.join(" ")}...`;
  }
  if (event.type === "tool_call") {
    return `${event.tool ?? "tool"} → ${firstParamValue(event.content)}`;
  }
  if (event.type === "phase_change") {
    const destination = event.content.split(" to ").pop() ?? event.content;
    return `→ ${destination}`;
  }
  return event.content;
}

const PHASE_VARS: Record<AgentPhase, { text: string; dim: string; border: string }> = {
  RECON:       { text: "var(--ares-green)",  dim: "var(--ares-green-dim)",  border: "var(--ares-green-border)"  },
  ENUMERATION: { text: "var(--ares-purple)", dim: "var(--ares-purple-dim)", border: "var(--ares-purple-border)" },
  VULN_SCAN:   { text: "var(--ares-red)",    dim: "var(--ares-red-dim)",    border: "var(--ares-red-border)"    },
  REPORT:      { text: "var(--ares-amber)",  dim: "var(--ares-amber-dim)",  border: "var(--ares-amber-border)"  },
};

const btn: CSSProperties = {
  border: "1px solid var(--ares-border-strong)",
  background: "var(--ares-surface)",
  color: "var(--ares-text-muted)",
  cursor: "pointer",
  borderRadius: 6,
};

export function AgentGraph({ events }: AgentGraphProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const { scale, offset, zoomIn, zoomOut, reset, canZoomIn, canZoomOut, dragHandlers } = useZoomPan();

  if (events.length === 0) {
    return <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>No graph data available yet</p>;
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 4, marginBottom: 12 }}>
        <button onClick={zoomOut} disabled={!canZoomOut} aria-label="Zoom out"
          style={{ ...btn, width: 32, height: 32, fontSize: 18, opacity: canZoomOut ? 1 : 0.35 }}
        >&minus;</button>
        <button onClick={reset}
          style={{ ...btn, padding: "0 12px", height: 32, fontSize: 12 }}
        >{Math.round(scale * 100)}%</button>
        <button onClick={zoomIn} disabled={!canZoomIn} aria-label="Zoom in"
          style={{ ...btn, width: 32, height: 32, fontSize: 18, opacity: canZoomIn ? 1 : 0.35 }}
        >+</button>
      </div>

      <div
        style={{
          position: "relative", overflow: "hidden", height: 520,
          border: "1px solid var(--ares-border)", borderRadius: 8,
          background: "var(--ares-bg)", cursor: "grab",
        }}
        {...dragHandlers}
      >
        <div style={{
          position: "absolute", top: "50%", left: "50%",
          display: "flex", alignItems: "flex-start", gap: 8,
          transform: `translate(-50%,-50%) translate(${offset.x}px,${offset.y}px) scale(${scale})`,
          transformOrigin: "center center",
        }}>
          {events.map((event, index) => {
            const isExpanded = expandedId === event.id;
            const phase = PHASE_VARS[event.phase];
            const delay: CSSProperties = { animationDelay: `${index * 0.045}s` };
            return (
              <div key={event.id} style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                <div style={{ display: "flex", flexDirection: "column" }}>
                  <div className="ares-node-enter" style={delay}>
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : event.id)}
                      onMouseDown={(e) => e.stopPropagation()}
                      style={{
                        minWidth: 148, padding: "10px 14px", textAlign: "left",
                        border: `1px solid ${isExpanded ? phase.border : "var(--ares-border)"}`,
                        background: isExpanded ? phase.dim : "var(--ares-surface)",
                        borderRadius: 8, cursor: "pointer",
                        transition: "border-color 0.15s, background 0.15s",
                        display: "block",
                      }}
                    >
                      <p style={{ margin: 0, fontSize: 12, fontWeight: 500, color: "var(--ares-text)", fontFamily: "JetBrains Mono, monospace" }}>
                        {nodeLabel(event)}
                      </p>
                      <p style={{ margin: "3px 0 0", fontSize: 11, color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace" }}>
                        {new Date(event.createdAt).toLocaleTimeString()}
                      </p>
                    </button>
                  </div>

                  {isExpanded && (
                    <div
                      onMouseDown={(e) => e.stopPropagation()}
                      className="ares-node-enter"
                      style={{
                        marginTop: 6, padding: 12, maxWidth: 260,
                        border: `1px solid ${phase.border}`,
                        background: "var(--ares-surface)", borderRadius: 8,
                      }}
                    >
                      <p style={{ margin: "0 0 6px", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.05em", color: phase.text, fontFamily: "JetBrains Mono, monospace" }}>
                        {event.phase}
                      </p>
                      <p style={{ margin: 0, fontSize: 13, color: "var(--ares-text)", lineHeight: 1.5 }}>
                        {event.content}
                      </p>
                    </div>
                  )}
                </div>

                {index < events.length - 1 && (
                  <span style={{ color: "var(--ares-border-strong)", marginTop: 18, flexShrink: 0 }}>→</span>
                )}
              </div>
            );
          })}
        </div>
      </div>
      <p style={{ fontSize: 11, color: "var(--ares-text-dim)", marginTop: 6, fontFamily: "JetBrains Mono, monospace" }}>
        Drag to pan · Ctrl/Cmd + scroll to zoom
      </p>
    </div>
  );
}
