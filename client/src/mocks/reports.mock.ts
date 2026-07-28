import type { SessionNotes } from "../types/report";

export const mockNotesBySession: Record<string, SessionNotes> = {
  "session-2": {
    sessionId: "session-2",
    content: "Manually review the TLS certificate, it looks self-signed.",
    updatedAt: "2026-06-25T11:00:00Z",
  },
};
