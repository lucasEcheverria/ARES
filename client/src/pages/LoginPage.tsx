import { useNavigate } from "react-router-dom";
import { GoogleLogin } from "@react-oauth/google";

interface LoginPageProps {
  onLogin: (idToken: string) => Promise<void>;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const navigate = useNavigate();

  async function handleSuccess(credentialResponse: { credential?: string }) {
    if (!credentialResponse.credential) return;
    try {
      await onLogin(credentialResponse.credential);
      navigate("/new-session");
    } catch {
      alert("Error signing in with Google");
    }
  }

  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "var(--ares-bg)" }}>
      <div style={{ width: 360, border: "1px solid var(--ares-border)", borderRadius: 12, background: "var(--ares-surface)", padding: 40, textAlign: "center" }}>
        <h1 style={{ margin: "0 0 6px", fontSize: 22, fontWeight: 600, color: "var(--ares-blue)" }}>ARES</h1>
        <p style={{ margin: "0 0 28px", fontSize: 14, color: "var(--ares-text-muted)" }}>
          Autonomous Red-teaming &amp; Exploitation System
        </p>
        <div style={{ display: "flex", justifyContent: "center" }}>
          <GoogleLogin
            onSuccess={handleSuccess}
            onError={() => alert("Error signing in with Google")}
          />
        </div>
      </div>
    </div>
  );
}