import type { Report, SessionNotes } from "../types/report";

export const mockReportsBySession: Record<string, Report> = {
  "session-2": {
    sessionId: "session-2",
    generatedAt: "2026-06-25T10:48:00Z",
    markdown: `# Informe de pentesting: alud.es

## Resumen

Se realizó un escaneo de reconocimiento y enumeración contra el objetivo **alud.es**.

## Hallazgos

| Puerto | Servicio | Estado |
|--------|----------|--------|
| 80/tcp | http     | Abierto |
| 443/tcp | https   | Abierto |

- Servidor: nginx
- Certificado TLS detectado, pendiente de revisión manual

## Conclusión

No se detectaron vulnerabilidades críticas durante el escaneo automatizado.`,
  },
};

export const mockNotesBySession: Record<string, SessionNotes> = {
  "session-2": {
    sessionId: "session-2",
    content: "Revisar manualmente el certificado TLS, parece autofirmado.",
    updatedAt: "2026-06-25T11:00:00Z",
  },
};
