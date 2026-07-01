export interface Report {
  sessionId: string;
  markdown: string;
  generatedAt: string;
}

export interface SessionNotes {
  sessionId: string;
  content: string;
  updatedAt: string;
}
