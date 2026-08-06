export interface ToolResultLog {
  id: string;
  sessionId: string;
  phase: string;
  tool: string;
  createdAt: string;
  exitCode: number;
  lines: string[];
  metadata: Record<string, unknown>;
}
