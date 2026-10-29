import { useContext, useEffect, useState, createContext, type ReactNode } from 'react'
import { api, getToken, setToken } from './api'

export interface User {
  id: string
  email: string
  role: string
  organization_id: string
}

interface AuthState {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, organization: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!getToken()) {
      setLoading(false)
      return
    }
    api
      .get<User>('/api/auth/me')
      .then(setUser)
      .catch(() => setToken(''))
      .finally(() => setLoading(false))
  }, [])

  const login = async (email: string, password: string) => {
    const res = await api.post<{ access_token: string; role: string }>('/api/auth/login', { email, password })
    setToken(res.access_token)
    setUser(await api.get<User>('/api/auth/me'))
  }

  const register = async (email: string, password: string, organization: string) => {
    await api.post('/api/auth/register', { email, password, organization_name: organization })
    await login(email, password)
  }

  const logout = () => {
    setToken('')
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth outside AuthProvider')
  return ctx
}