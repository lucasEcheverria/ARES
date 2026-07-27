import type { Report, SessionNotes } from "../types/report";

export const mockReportsBySession: Record<string, Report> = {
  "session-2": {
    sessionId: "session-2",
    generatedAt: "2026-06-25T10:48:00Z",
    markdown: `# Pentesting report: alud.es

## Summary

A reconnaissance and enumeration scan was performed against the target **alud.es**.

## Findings

| Port | Service | State |
|--------|----------|--------|
| 80/tcp | http     | Open |
| 443/tcp | https   | Open |

- Server: nginx
- TLS certificate detected, pending manual review

## Conclusion

No critical vulnerabilities were detected during the automated scan.`,
  },
};

export const mockNotesBySession: Record<string, SessionNotes> = {
  "session-2": {
    sessionId: "session-2",
    content: "Manually review the TLS certificate, it looks self-signed.",
    updatedAt: "2026-06-25T11:00:00Z",
  },
};
