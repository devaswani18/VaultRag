import React from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, ProtectedRoute } from './auth'
import { Layout } from './components/Layout'
import { ChatPage, DocumentsPage, LoginPage } from './pages'

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          {/* Protected Application Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/chat" replace />} />
            <Route path="chat" element={<ChatPage />} />
            <Route path="documents" element={<DocumentsPage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/chat" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
