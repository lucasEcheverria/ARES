import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useReport } from "../controllers/useReport";
import { useMemoryLogs } from "../controllers/useMemoryLogs";
import { useSessionStatus } from "../controllers/useSessionStatus";
import { NotesEditor } from "./NotesEditor";
import { LogsTable } from "./LogsTable";
import type { Session } from "../types/session";

interface SessionReportViewProps {
  sessionId: string;
  onSessionSettled?: (session: Session) => void;
}

export function SessionReportView({ sessionId, onSessionSettled }: SessionReportViewProps) {
  const { session } = useSessionStatus(sessionId, onSessionSettled);
  const shouldFetchReport = session !== undefined && session.status !== "running";
  const isSessionRunning = session === undefined || session.status === "running";
  const { reportState, notes, notesVisible, toggleNotesVisible, updateNotes } = useReport(sessionId, shouldFetchReport);
  const { logs, isLoading: logsLoading, filters, updateFilter, resetFilters, availableTools } = useMemoryLogs(sessionId, isSessionRunning);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {/* Bloque 1: Reporte generado */}
      <section>
        <div style={{
          border: "1px solid var(--ares-border)", borderRadius: 8,
          background: "var(--ares-surface)", padding: 24,
        }}>
          <div className="prose prose-sm max-w-none" style={{ color: "var(--ares-text)" }}>
            {!shouldFetchReport || reportState.kind === "loading" ? (
              <p style={{ color: "var(--ares-text-dim)", fontSize: 14, margin: 0 }}>
                Agent is running...
              </p>
            ) : reportState.kind === "ready" ? (
              <Markdown remarkPlugins={[remarkGfm]}>{reportState.markdown}</Markdown>
            ) : reportState.kind === "not-found" ? (
              <p style={{ color: "var(--ares-text-dim)", fontSize: 14, margin: 0 }}>
                Report not available yet.
              </p>
            ) : (
              <p style={{ color: "var(--ares-red)", fontSize: 14, margin: 0 }}>
                Failed to load the report. Please try again later.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* Bloque 2: Logs en memoria */}
      <section>
        <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 600, color: "var(--ares-text)" }}>
          Memory logs
        </h3>
        <LogsTable
          logs={logs}
          isLoading={logsLoading}
          isLive={isSessionRunning}
          filters={filters}
          availableTools={availableTools}
          onFilterChange={updateFilter}
          onReset={resetFilters}
        />
      </section>

      {/* Bloque 3: Notas */}
      <section>
        <NotesEditor
          content={notes?.content ?? ""}
          visible={notesVisible}
          onToggleVisible={toggleNotesVisible}
          onChange={updateNotes}
        />
      </section>

    </div>
  );
}
