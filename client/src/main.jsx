/* eslint-disable react-refresh/only-export-components */
import React from 'react'
import ReactDOM from 'react-dom/client'
import { ClerkProvider } from '@clerk/react'
import App from './App.jsx'
import './index.css'

const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY

if (!PUBLISHABLE_KEY) {
  console.error('[Clerk] VITE_CLERK_PUBLISHABLE_KEY is not set. Auth will not work.')
}

function Root() {
  if (!PUBLISHABLE_KEY) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', fontFamily: 'system-ui', color: '#e9d5ff', background: '#0f0a1e' }}>
        <div style={{ textAlign: 'center', maxWidth: 420, padding: '2rem' }}>
          <h1 style={{ fontSize: '1.5rem', marginBottom: '0.75rem' }}>Authentication not configured</h1>
          <p style={{ color: '#a78bfa', lineHeight: 1.6 }}>
            Set <code style={{ background: '#1e1538', padding: '0.15em 0.4em', borderRadius: 4 }}>VITE_CLERK_PUBLISHABLE_KEY</code> in your <code style={{ background: '#1e1538', padding: '0.15em 0.4em', borderRadius: 4 }}>.env</code> file and restart the dev server.
          </p>
        </div>
      </div>
    )
  }

  return (
    <ClerkProvider
      publishableKey={PUBLISHABLE_KEY}
      signInUrl="/sign-in"
      signUpUrl="/sign-up"
    >
      <App />
    </ClerkProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
