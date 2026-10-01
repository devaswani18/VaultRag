import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'
import { setTokenGetter, setUnauthorizedHandler } from '../api/client'
import {
  authenticateUser,
  refreshIdToken,
  userFromIdToken,
} from './cognito'
import { AuthContext } from './context'
import { User } from './types'

const REFRESH_TOKEN_KEY = 'vaultrag_refresh_token'

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // ID token is kept STRICTLY IN-MEMORY in React state. Never in localStorage or sessionStorage.
  const [idToken, setIdToken] = useState<string | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)

  const idTokenRef = useRef<string | null>(null)
  idTokenRef.current = idToken

  const refreshTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isRefreshingRef = useRef<boolean>(false)

  // Configure global API client token getter
  useEffect(() => {
    setTokenGetter(() => idTokenRef.current)
  }, [])

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimeoutRef.current) {
      clearTimeout(refreshTimeoutRef.current)
      refreshTimeoutRef.current = null
    }
  }, [])

  const logout = useCallback(() => {
    clearRefreshTimer()
    setIdToken(null)
    setUser(null)
    // Clear refresh token from sessionStorage
    try {
      sessionStorage.removeItem(REFRESH_TOKEN_KEY)
    } catch {
      // Ignore sessionStorage errors
    }
  }, [clearRefreshTimer])

  // Schedule auto-refresh before token expires
  const scheduleAutoRefresh = useCallback(
    (expiresInSeconds: number, refreshToken: string) => {
      clearRefreshTimer()
      // Refresh 60 seconds before expiration, minimum 10 seconds
      const leadTime = 60
      const delayMs = Math.max((expiresInSeconds - leadTime) * 1000, 10000)

      refreshTimeoutRef.current = setTimeout(async () => {
        try {
          const result = await refreshIdToken(refreshToken)
          setIdToken(result.idToken)
          const newUser = userFromIdToken(result.idToken)
          if (newUser) {
            setUser(newUser)
          }
          if (result.refreshToken) {
            sessionStorage.setItem(REFRESH_TOKEN_KEY, result.refreshToken)
          }
          if (result.expiresIn) {
            scheduleAutoRefresh(result.expiresIn, result.refreshToken || refreshToken)
          }
        } catch {
          // If auto-refresh fails, perform clean logout
          logout()
        }
      }, delayMs)
    },
    [clearRefreshTimer, logout]
  )

  // Handle 401 unauthorized: try one refresh, then log out if that fails
  const handleUnauthorized = useCallback(async () => {
    if (isRefreshingRef.current) return
    isRefreshingRef.current = true

    try {
      const storedRefreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY)
      if (!storedRefreshToken) {
        logout()
        return
      }

      const result = await refreshIdToken(storedRefreshToken)
      setIdToken(result.idToken)
      const newUser = userFromIdToken(result.idToken)
      if (newUser) {
        setUser(newUser)
      }
      if (result.refreshToken) {
        sessionStorage.setItem(REFRESH_TOKEN_KEY, result.refreshToken)
      }
      if (result.expiresIn) {
        scheduleAutoRefresh(result.expiresIn, result.refreshToken || storedRefreshToken)
      }
    } catch {
      logout()
    } finally {
      isRefreshingRef.current = false
    }
  }, [logout, scheduleAutoRefresh])

  useEffect(() => {
    setUnauthorizedHandler(handleUnauthorized)
  }, [handleUnauthorized])

  // Attempt session restoration on initial mount via sessionStorage refresh token
  useEffect(() => {
    let isMounted = true

    const restoreSession = async () => {
      try {
        const storedRefreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY)
        if (!storedRefreshToken) {
          if (isMounted) setIsLoading(false)
          return
        }

        const result = await refreshIdToken(storedRefreshToken)
        if (!isMounted) return

        setIdToken(result.idToken)
        const parsedUser = userFromIdToken(result.idToken)
        if (parsedUser) {
          setUser(parsedUser)
        }
        if (result.refreshToken) {
          sessionStorage.setItem(REFRESH_TOKEN_KEY, result.refreshToken)
        }
        if (result.expiresIn) {
          scheduleAutoRefresh(result.expiresIn, result.refreshToken || storedRefreshToken)
        }
      } catch {
        if (isMounted) {
          try {
            sessionStorage.removeItem(REFRESH_TOKEN_KEY)
          } catch {
            // Ignore
          }
        }
      } finally {
        if (isMounted) {
          setIsLoading(false)
        }
      }
    }

    restoreSession()

    return () => {
      isMounted = false
      clearRefreshTimer()
    }
  }, [clearRefreshTimer, scheduleAutoRefresh])

  const login = useCallback(
    async (username: string, password: string): Promise<void> => {
      const tokens = await authenticateUser(username, password)
      setIdToken(tokens.idToken)

      const parsedUser = userFromIdToken(tokens.idToken)
      if (!parsedUser) {
        throw new Error('Unable to parse user claims from ID token.')
      }
      setUser(parsedUser)

      // Refresh token goes to sessionStorage (never localStorage!)
      if (tokens.refreshToken) {
        sessionStorage.setItem(REFRESH_TOKEN_KEY, tokens.refreshToken)
      }

      if (tokens.expiresIn && tokens.refreshToken) {
        scheduleAutoRefresh(tokens.expiresIn, tokens.refreshToken)
      }
    },
    [scheduleAutoRefresh]
  )

  const getIdToken = useCallback(() => idTokenRef.current, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        idToken,
        isLoading,
        login,
        logout,
        getIdToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}
