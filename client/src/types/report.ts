export interface SessionNotes {
  sessionId: string;
  content: string;
  updatedAt: string;
}

export type ReportFetchResult =
  | { kind: "ready"; markdown: string }
  | { kind: "not-found" }
  | { kind: "error" };

export type ReportState = { kind: "loading" } | ReportFetchResult;
