import { useParams, useOutletContext } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useReport } from "../controllers/useReport";
import { useMemoryLogs } from "../controllers/useMemoryLogs";
import { useSessionStatus } from "../controllers/useSessionStatus";
import { NotesEditor } from "../components/NotesEditor";
import { LogsTable } from "../components/LogsTable";
import type { AppOutletContext } from "../types/outletContext";

export function ReportPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { refetchSessions } = useOutletContext<AppOutletContext>();
  const { session, isLoading: isSessionLoading } = useSessionStatus(sessionId ?? "", refetchSessions);
  const { report, notes, notesVisible, toggleNotesVisible, updateNotes } = useReport(sessionId ?? "");
  const { events, filters, updateFilter, resetFilters, availableTools } = useMemoryLogs(sessionId ?? "");

  if (isSessionLoading || session?.status === "running") {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: 48 }}>
        <p style={{ color: "var(--ares-text-dim)", fontSize: 14 }}>Agent is running...</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {session?.status === "failed" && (
        <p style={{ color: "var(--ares-red)", fontSize: 13, margin: 0 }}>Session failed.</p>
      )}

      {/* Bloque 1: Reporte generado */}
      <section>
        <div style={{
          border: "1px solid var(--ares-border)", borderRadius: 8,
          background: "var(--ares-surface)", padding: 24,
        }}>
          <div className="prose prose-sm max-w-none" style={{ color: "var(--ares-text)" }}>
            {report ? (
              <Markdown remarkPlugins={[remarkGfm]}>{report.markdown}</Markdown>
            ) : (
              <p style={{ color: "var(--ares-text-dim)", fontSize: 14, margin: 0 }}>
                Report not available yet.
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
          events={events}
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
