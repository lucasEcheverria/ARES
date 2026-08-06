import { useState } from "react";
import type { User } from "../types/user";

const API_URL = import.meta.env.VITE_API_URL;
const TOKEN_KEY = "ares_token";

function decodeUser(token: string): User {
  const payload = JSON.parse(atob(token.split(".")[1]));
  return { id: payload.sub, email: payload.email, name: payload.name ?? payload.email };
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

function initialUser(): User | null {
  const token = getToken();
  if (!token) return null;
  try {
    return decodeUser(token);
  } catch {
    sessionStorage.removeItem(TOKEN_KEY);
    return null;
  }
}

export function useAuth() {
  const [user, setUser] = useState<User | null>(initialUser);

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
    sessionStorage.setItem(TOKEN_KEY, data.access_token);
    setUser(decodeUser(data.access_token));
  }

  function logout() {
    sessionStorage.removeItem(TOKEN_KEY);
    setUser(null);
  }

  return { user, isAuthenticated: user !== null, loginWithGoogle, logout };
}
