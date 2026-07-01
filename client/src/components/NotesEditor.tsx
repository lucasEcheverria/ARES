interface NotesEditorProps {
  content: string;
  visible: boolean;
  onToggleVisible: () => void;
  onChange: (content: string) => void;
}

export function NotesEditor({ content, visible, onToggleVisible, onChange }: NotesEditorProps) {
  return (
    <div style={{ border: "1px solid var(--ares-border)", borderRadius: 8, background: "var(--ares-surface)", overflow: "hidden" }}>
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 14px", borderBottom: visible ? "1px solid var(--ares-border)" : "none",
      }}>
        <span style={{ fontSize: 13, fontWeight: 500, color: "var(--ares-text)" }}>Notas</span>
        <button
          onClick={onToggleVisible}
          style={{ fontSize: 12, color: "var(--ares-text-dim)", background: "none", border: "none", cursor: "pointer", padding: "2px 4px" }}
        >{visible ? "esconder" : "mostrar"}</button>
      </div>
      {visible && (
        <textarea
          value={content}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Escribe tus notas sobre esta sesión..."
          style={{
            width: "100%", height: 112, resize: "none", padding: "12px 14px",
            fontSize: 13, color: "var(--ares-text)", background: "transparent",
            border: "none", outline: "none", fontFamily: "inherit", lineHeight: 1.6,
            boxSizing: "border-box",
          }}
        />
      )}
    </div>
  );
}
