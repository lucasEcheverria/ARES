import { useState } from "react";
import type { User } from "../types/user";
import { mockUser } from "../mocks/user.mock";

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);

  function loginWithGoogle() {
    // Mock: no real OAuth yet. Simulates a successful Google login.
    setUser(mockUser);
  }

  function logout() {
    setUser(null);
  }

  return { user, isAuthenticated: user !== null, loginWithGoogle, logout };
}
