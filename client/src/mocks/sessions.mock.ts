import type { Session } from "../types/session";

export const mockSessions: Session[] = [
  {
    id: "session-1",
    userId: "user-1",
    target: "localhost:8080",
    status: "running",
    currentPhase: "ENUMERATION",
    createdAt: "2026-06-26T08:10:00Z",
    updatedAt: "2026-06-26T08:32:00Z",
  },
  {
    id: "session-2",
    userId: "user-1",
    target: "alud.es",
    status: "completed",
    currentPhase: "REPORT",
    createdAt: "2026-06-25T10:00:00Z",
    updatedAt: "2026-06-25T10:48:00Z",
  },
  {
    id: "session-3",
    userId: "user-1",
    target: "192.168.1.40",
    status: "completed",
    currentPhase: "REPORT",
    createdAt: "2026-06-24T09:00:00Z",
    updatedAt: "2026-06-24T09:55:00Z",
  },
];
