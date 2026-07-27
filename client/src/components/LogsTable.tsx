import type { ReactNode } from "react";
import type { AgentEvent } from "../types/agentEvent";
import type { MemoryLogsFilters } from "../controllers/useMemoryLogs";
import type { AgentPhase } from "../types/session";

interface LogsTableProps {
  events: AgentEvent[];
  filters: MemoryLogsFilters;
  availableTools: string[];
  onFilterChange: <K extends keyof MemoryLogsFilters>(key: K, value: MemoryLogsFilters[K]) => void;
  onReset: () => void;
}

const TYPE_OPTIONS: Array<{ value: MemoryLogsFilters["type"]; label: string }> = [
  { value: "all", label: "All" },
  { value: "thought", label: "Thoughts" },
  { value: "tool_call", label: "Tool calls" },
  { value: "tool_result", label: "Results" },
  { value: "phase_change", label: "Phase changes" },
];

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

export function LogsTable({ events, filters, availableTools, onFilterChange, onReset }: LogsTableProps) {
  const hasActive = filters.type !== "all" || filters.phase !== "all" || filters.tool !== "all" || filters.from !== "" || filters.to !== "";

  return (
    <div>
      <div style={{ background: "var(--ares-surface-raised)", border: "1px solid var(--ares-border)", borderRadius: 8, padding: 14, marginBottom: 16 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
          <FilterField label="Type">
            <select value={filters.type} onChange={(e) => onFilterChange("type", e.target.value as MemoryLogsFilters["type"])} style={controlStyle}>
              {TYPE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </FilterField>
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
              {["Timestamp", "Phase", "Type", "Tool", "Log"].map((h) => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, fontWeight: 600, color: "var(--ares-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} style={{ borderBottom: "1px solid var(--ares-border)" }}>
                <td style={{ padding: "9px 12px", color: "var(--ares-text-muted)", whiteSpace: "nowrap", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>
                  {new Date(event.timestamp).toLocaleString()}
                </td>
                <td style={{ padding: "9px 12px" }}>
                  <span style={{
                    display: "inline-block", padding: "2px 8px", borderRadius: 99, fontSize: 11, fontFamily: "JetBrains Mono, monospace",
                    background: event.phase === "RECON" ? "var(--ares-green-dim)" : event.phase === "ENUMERATION" ? "var(--ares-blue-dim)" : event.phase === "VULN_SCAN" ? "var(--ares-red-dim)" : "var(--ares-amber-dim)",
                    color: event.phase === "RECON" ? "var(--ares-green)" : event.phase === "ENUMERATION" ? "var(--ares-blue-text)" : event.phase === "VULN_SCAN" ? "var(--ares-red)" : "var(--ares-amber)",
                  }}>{event.phase}</span>
                </td>
                <td style={{ padding: "9px 12px", color: "var(--ares-text)" }}>{event.type}</td>
                <td style={{ padding: "9px 12px", color: "var(--ares-text-muted)", fontFamily: "JetBrains Mono, monospace", fontSize: 12 }}>{event.tool ?? "—"}</td>
                <td style={{ padding: "9px 12px", color: "var(--ares-text)" }}>{event.content}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} style={{ padding: 32, textAlign: "center", color: "var(--ares-text-dim)" }}>
                  No logs for these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
