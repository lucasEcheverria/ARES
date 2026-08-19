import type { FormEvent } from "react";
import { useOutletContext } from "react-router-dom";
import type { AppOutletContext, RagConversation } from "../types/outletContext";
import { querySession } from "../proxies/ragProxy";
import { PHASE_VARS } from "./AgentGraph";

interface GraphRagPanelProps {
  sessionId: string;
  isRunning: boolean;
}

const IDLE_CONVERSATION: RagConversation = {
  question: "",
  answer: null,
  sources: [],
  status: "idle",
};

export function GraphRagPanel({ sessionId, isRunning }: GraphRagPanelProps) {
  const { ragConversations, updateRagConversation } = useOutletContext<AppOutletContext>();
  const conversation = ragConversations[sessionId] ?? IDLE_CONVERSATION;
  const loading = conversation.status === "loading";

  if (isRunning) {
    return (
      <div
        style={{
          border: "1px solid var(--ares-border)", borderRadius: 8,
          background: "var(--ares-surface)", padding: 24, marginTop: 16,
          textAlign: "center",
        }}
      >
        <div
          style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            padding: "5px 12px", borderRadius: 999,
            background: "var(--ares-green-dim)", border: "1px solid var(--ares-green-border)",
            marginBottom: 14,
          }}
        >
          <span className="ares-live-dot" />
          <span style={{
            fontSize: 11, fontWeight: 600, color: "var(--ares-green-text)",
            textTransform: "uppercase", letterSpacing: "0.05em",
          }}>
            Scan in progress
          </span>
        </div>
        <p style={{ margin: "0 0 6px", fontSize: 14, fontWeight: 500, color: "var(--ares-text)" }}>
          Ask about this exploration
        </p>
        <p style={{
          margin: "0 auto", maxWidth: 420, fontSize: 13,
          color: "var(--ares-text-muted)", lineHeight: 1.6,
        }}>
          The RAG needs a finished exploration to answer from. It'll unlock automatically
          the moment this scan completes.
        </p>
      </div>
    );
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const trimmed = conversation.question.trim();
    if (!trimmed || loading) return;

    updateRagConversation(sessionId, { status: "loading", question: trimmed });
    try {
      const result = await querySession(sessionId, trimmed);
      updateRagConversation(sessionId, {
        status: "ready",
        answer: result.answer,
        sources: result.sources,
      });
    } catch {
      updateRagConversation(sessionId, { status: "error" });
    }
  }

  return (
    <div
      style={{
        border: "1px solid var(--ares-border)", borderRadius: 8,
        background: "var(--ares-surface)", padding: 16, marginTop: 16,
      }}
    >
      <p style={{ margin: "0 0 12px", fontSize: 13, fontWeight: 500, color: "var(--ares-text)" }}>
        Ask about this exploration
      </p>

      <form onSubmit={handleSubmit} style={{ display: "flex", gap: 8 }}>
        <input
          value={conversation.question}
          onChange={(e) => updateRagConversation(sessionId, { question: e.target.value })}
          placeholder="e.g. What vulnerabilities were found?"
          disabled={loading}
          style={{
            flex: 1, padding: "8px 12px", fontSize: 13, color: "var(--ares-text)",
            background: "var(--ares-bg)", border: "1px solid var(--ares-border)",
            borderRadius: 8, outline: "none", fontFamily: "JetBrains Mono, monospace",
          }}
        />
        <button
          type="submit"
          disabled={loading || !conversation.question.trim()}
          style={{
            padding: "8px 16px", fontSize: 13, fontWeight: 500,
            color: "var(--ares-blue-text)", background: "var(--ares-blue-dim)",
            border: "1px solid var(--ares-blue-border)", borderRadius: 8,
            cursor: loading || !conversation.question.trim() ? "default" : "pointer",
            opacity: loading || !conversation.question.trim() ? 0.6 : 1,
          }}
        >
          Ask
        </button>
      </form>

      {loading && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14 }}>
          <span style={{ fontSize: 12, color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace" }}>
            Analyzing the exploration
          </span>
          <span style={{ display: "flex", gap: 3 }}>
            <span className="ares-typing-dot" style={{ animationDelay: "0s" }} />
            <span className="ares-typing-dot" style={{ animationDelay: "0.2s" }} />
            <span className="ares-typing-dot" style={{ animationDelay: "0.4s" }} />
          </span>
        </div>
      )}

      {conversation.status === "error" && (
        <p style={{ margin: "14px 0 0", fontSize: 13, color: "var(--ares-red-text)" }}>
          Could not get an answer. Please try again.
        </p>
      )}

      {conversation.status === "ready" && conversation.answer && (
        <div className="ares-node-enter" style={{ marginTop: 14 }}>
          <p style={{
            margin: "0 0 10px", fontSize: 13, color: "var(--ares-text)",
            lineHeight: 1.6, whiteSpace: "pre-wrap",
          }}>
            {conversation.answer}
          </p>

          {conversation.sources.length > 0 && (
            <div>
              <p style={{
                margin: "0 0 6px", fontSize: 11, textTransform: "uppercase",
                letterSpacing: "0.05em", color: "var(--ares-text-dim)",
              }}>
                Sources
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {conversation.sources.map((source, index) => {
                  const phase = PHASE_VARS[source.phase];
                  return (
                    <div
                      key={index}
                      style={{
                        padding: "8px 10px", border: `1px solid ${phase.border}`,
                        borderLeft: `3px solid ${phase.border}`, background: phase.dim,
                        borderRadius: 8,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                        <span style={{
                          fontSize: 10, textTransform: "uppercase", letterSpacing: "0.05em",
                          color: phase.text, fontFamily: "JetBrains Mono, monospace",
                        }}>
                          {source.phase}
                        </span>
                        {source.tool && (
                          <span style={{ fontSize: 11, color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace" }}>
                            {source.tool}
                          </span>
                        )}
                      </div>
                      <p style={{
                        margin: 0, fontSize: 12, color: "var(--ares-text)",
                        fontFamily: "JetBrains Mono, monospace", whiteSpace: "pre-wrap",
                      }}>
                        {source.snippet}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
