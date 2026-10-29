import { useState } from 'react'
import { useAuth } from '../lib/auth'
import { Button, Field, Input } from '../components/ui'

export default function Login() {
  const { login, register } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [organization, setOrganization] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setError('')
    setBusy(true)
    try {
      if (mode === 'login') await login(email, password)
      else await register(email, password, organization)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Authentication failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 dark:bg-slate-950">
      <div className="w-96 rounded-lg border border-slate-200 bg-white p-6 shadow dark:border-slate-800 dark:bg-slate-900">
        <h1 className="mb-1 text-xl font-bold text-slate-900 dark:text-slate-100">Sentinel DAST</h1>
        <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">
          Authorized dynamic application security testing only.
        </p>
        <div className="space-y-3">
          {mode === 'register' && (
            <Field label="Organization name">
              <Input value={organization} onChange={(e) => setOrganization(e.target.value)} />
            </Field>
          )}
          <Field label="Email">
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Password" hint={mode === 'register' ? 'Minimum 10 characters' : undefined}>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <Button onClick={submit} disabled={busy || !email || !password} type="button">
            {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </Button>
          <button
            className="block text-xs text-blue-600 hover:underline"
            onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
          >
            {mode === 'login' ? 'No account yet? Register the first administrator.' : 'Back to sign in'}
          </button>
        </div>
      </div>
    </div>
  )
}