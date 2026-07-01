import { useParams } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useReport } from "../controllers/useReport";
import { useMemoryLogs } from "../controllers/useMemoryLogs";
import { NotesEditor } from "../components/NotesEditor";
import { LogsTable } from "../components/LogsTable";

export function ReportPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { report, notes, notesVisible, toggleNotesVisible, updateNotes } = useReport(sessionId ?? "");
  const { events, filters, updateFilter, resetFilters, availableTools } = useMemoryLogs(sessionId ?? "");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

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
                Aún no hay informe generado para esta sesión.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* Bloque 2: Logs en memoria */}
      <section>
        <h3 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 600, color: "var(--ares-text)" }}>
          Logs en memoria
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
