import { useNavigate } from "react-router-dom";

interface LoginPageProps {
  onLogin: () => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const navigate = useNavigate();
  function handleLogin() { onLogin(); navigate("/new-session"); }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "var(--ares-bg)" }}>
      <div style={{ width: 360, border: "1px solid var(--ares-border)", borderRadius: 12, background: "var(--ares-surface)", padding: 40, textAlign: "center" }}>
        <h1 style={{ margin: "0 0 6px", fontSize: 22, fontWeight: 600, color: "var(--ares-blue)" }}>ARES</h1>
        <p style={{ margin: "0 0 28px", fontSize: 14, color: "var(--ares-text-muted)" }}>
          Autonomous Red-teaming &amp; Exploitation System
        </p>
        <button
          onClick={handleLogin}
          style={{
            width: "100%", padding: "10px 16px", fontSize: 14, fontWeight: 500, cursor: "pointer",
            border: "1px solid var(--ares-border-strong)", borderRadius: 6,
            background: "var(--ares-surface)", color: "var(--ares-text)",
          }}
        >Continuar con Google</button>
      </div>
    </div>
  );
}
