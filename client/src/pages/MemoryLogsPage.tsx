import { useParams } from "react-router-dom";
import { useMemoryLogs } from "../controllers/useMemoryLogs";
import { LogsTable } from "../components/LogsTable";

export function MemoryLogsPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const { logs, isLoading, filters, updateFilter, resetFilters, availableTools } = useMemoryLogs(sessionId ?? "", false);

  return (
    <LogsTable
      logs={logs}
      isLoading={isLoading}
      isLive={false}
      filters={filters}
      availableTools={availableTools}
      onFilterChange={updateFilter}
      onReset={resetFilters}
    />
  );
}
