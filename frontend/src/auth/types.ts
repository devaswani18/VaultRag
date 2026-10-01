export interface User {
  email: string
  tenant_id: string
  roles: string[]
  role: string
  sub: string
}

export interface AuthContextType {
  user: User | null
  idToken: string | null
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  signUp: (email: string, password: string, tenantId: string) => Promise<{ userConfirmed: boolean }>
  confirmSignUp: (email: string, code: string) => Promise<void>
  logout: () => void
  getIdToken: () => string | null
}
