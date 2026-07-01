import { useParams } from "react-router-dom";
import { useMemoryLogs } from "../controllers/useMemoryLogs";
import { LogsTable } from "../components/LogsTable";

export function MemoryLogsPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { events, filters, updateFilter, resetFilters, availableTools } = useMemoryLogs(sessionId ?? "");

  return (
    <LogsTable
      events={events}
      filters={filters}
      availableTools={availableTools}
      onFilterChange={updateFilter}
      onReset={resetFilters}
    />
  );
}
