import { Fragment, useState } from "react";
import type { ReactNode } from "react";
import type { ToolResultLog } from "../types/toolResultLog";
import type { MemoryLogsFilters } from "../controllers/useMemoryLogs";
import type { AgentPhase } from "../types/session";

interface LogsTableProps {
  logs: ToolResultLog[];
  isLoading: boolean;
  isLive: boolean;
  filters: MemoryLogsFilters;
  availableTools: string[];
  onFilterChange: <K extends keyof MemoryLogsFilters>(key: K, value: MemoryLogsFilters[K]) => void;
  onReset: () => void;
}

const PHASE_OPTIONS: Array<AgentPhase | "all"> = ["all", "RECON", "ENUMERATION", "VULN_SCAN", "REPORT"];

const controlStyle = {
  width: "100%", padding: "7px 10px", fontSize: 13,
  border: "1px solid var(--ares-border)", borderRadius: 6,
  background: "var(--ares-surface)", color: "var(--ares-text)",
  outline: "none", fontFamily: "JetBrains Mono, monospace",
};

function FilterField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <label style={{ display: "block", fontSize: 11, fontWeight: 500, color: "var(--ares-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
        {label}
      </label>
      {children}
    </div>
  );
}

function phaseColors(phase: string) {
  return {
    background: phase === "RECON" ? "var(--ares-green-dim)" : phase === "ENUMERATION" ? "var(--ares-blue-dim)" : phase === "VULN_SCAN" ? "var(--ares-red-dim)" : "var(--ares-amber-dim)",
    color: phase === "RECON" ? "var(--ares-green)" : phase === "ENUMERATION" ? "var(--ares-blue-text)" : phase === "VULN_SCAN" ? "var(--ares-red)" : "var(--ares-amber)",
  };
}

const TABLE_COLUMNS = ["Timestamp", "Phase", "Tool", "Exit Code", "Preview"];

export function LogsTable({ logs, isLoading, isLive, filters, availableTools, onFilterChange, onReset }: LogsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const hasActive = filters.phase !== "all" || filters.tool !== "all" || filters.from !== "" || filters.to !== "";

  return (
    <div>
      {isLive && (
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
          <span className="ares-live-dot" />
          <span style={{ fontSize: 11, fontWeight: 600, color: "var(--ares-green)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Live
          </span>
        </div>
      )}
      <div style={{ background: "var(--ares-surface-raised)", border: "1px solid var(--ares-border)", borderRadius: 8, padding: 14, marginBottom: 16 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
          <FilterField label="Phase">
            <select value={filters.phase} onChange={(e) => onFilterChange("phase", e.target.value as MemoryLogsFilters["phase"])} style={controlStyle}>
              {PHASE_OPTIONS.map((p) => <option key={p} value={p}>{p === "all" ? "All" : p}</option>)}
            </select>
          </FilterField>
          <FilterField label="Tool">
            <select value={filters.tool} onChange={(e) => onFilterChange("tool", e.target.value)} style={controlStyle}>
              <option value="all">All</option>
              {availableTools.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </FilterField>
          <FilterField label="From">
            <input type="datetime-local" value={filters.from} onChange={(e) => onFilterChange("from", e.target.value)} style={controlStyle} />
          </FilterField>
          <FilterField label="To">
            <input type="datetime-local" value={filters.to} onChange={(e) => onFilterChange("to", e.target.value)} style={controlStyle} />
          </FilterField>
        </div>
        {hasActive && (
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
            <button onClick={onReset} style={{ fontSize: 12, color: "var(--ares-blue)", background: "none", border: "none", cursor: "pointer" }}>
              Clear filters
            </button>
          </div>
        )}
      </div>

      <div style={{ overflowX: "auto", border: "1px solid var(--ares-border)", borderRadius: 8 }}>
        <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "var(--ares-surface-raised)", borderBottom: "1px solid var(--ares-border)" }}>
              {TABLE_COLUMNS.map((h) => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, fontWeight: 600, color: "var(--ares-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={TABLE_COLUMNS.length} style={{ padding: 32, textAlign: "center", color: "var(--ares-text-dim)" }}>
                  Loading logs…
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={TABLE_COLUMNS.length} style={{ padding: 32, textAlign: "center", color: "var(--ares-text-dim)" }}>
                  No logs available for this session yet
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const isExpanded = expandedId === log.id;
                const colors = phaseColors(log.phase);
                return (
                  <Fragment key={log.id}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : log.id)}
                      style={{ borderBottom: "1px solid var(--ares-border)", cursor: "pointer" }}
                    >
                      <td style={{ padding: "9px 12px", color: "var(--ares-text-muted)", whiteSpace: "nowrap", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
                        {new Date(log.createdAt).toLocaleString()}
                      </td>
                      <td style={{ padding: "9px 12px" }}>
                        <span style={{ display: "inline-block", padding: "2px 8px", borderRadius: 99, fontSize: 11, fontFamily: "JetBrains Mono, monospace", ...colors }}>
                          {log.phase}
                        </span>
                      </td>
                      <td style={{ padding: "9px 12px", color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>{log.tool}</td>
                      <td style={{ padding: "9px 12px", fontFamily: "JetBrains Mono, monospace", fontSize: 12, color: log.exitCode === 0 ? "var(--ares-green)" : "var(--ares-red)" }}>
                        {log.exitCode}
                      </td>
                      <td style={{ padding: "9px 12px", color: "var(--ares-text)", fontFamily: "JetBrains Mono, monospace", fontSize: 12, whiteSpace: "pre-wrap" }}>
                        {log.lines.slice(0, 3).join("\n")}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr style={{ borderBottom: "1px solid var(--ares-border)", background: "var(--ares-surface-raised)" }}>
                        <td colSpan={TABLE_COLUMNS.length} style={{ padding: "12px 16px" }}>
                          <div style={{ marginBottom: 10 }}>
                            <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 600, color: "var(--ares-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Output</p>
                            <pre style={{ margin: 0, padding: 10, background: "var(--ares-bg)", border: "1px solid var(--ares-border)", borderRadius: 6, fontSize: 12, fontFamily: "JetBrains Mono, monospace", whiteSpace: "pre-wrap", color: "var(--ares-text)", maxHeight: 320, overflowY: "auto" }}>
                              {log.lines.join("\n")}
                            </pre>
                          </div>
                          <div>
                            <p style={{ margin: "0 0 6px", fontSize: 11, fontWeight: 600, color: "var(--ares-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Metadata</p>
                            <pre style={{ margin: 0, padding: 10, background: "var(--ares-bg)", border: "1px solid var(--ares-border)", borderRadius: 6, fontSize: 12, fontFamily: "JetBrains Mono, monospace", whiteSpace: "pre-wrap", color: "var(--ares-text)" }}>
                              {JSON.stringify(log.metadata, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
