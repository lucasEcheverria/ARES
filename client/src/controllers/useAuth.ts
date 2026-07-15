import { useState } from "react";
import type { User } from "../types/user";

const API_URL = "http://localhost:8000";

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);

  async function loginWithGoogle(idToken: string) {
    const response = await fetch(`${API_URL}/auth/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id_token: idToken }),
    });

    if (!response.ok) {
      throw new Error("Error al autenticar con Google");
    }

    const data = await response.json();
    setToken(data.access_token);

    // Decodificamos el JWT para extraer los datos del usuario
    const payload = JSON.parse(atob(data.access_token.split(".")[1]));
    setUser({ id: payload.sub, email: payload.email, name: payload.name ?? payload.email });
  }

  function logout() {
    setUser(null);
    setToken(null);
  }

  return { user, token, isAuthenticated: user !== null, loginWithGoogle, logout };
}