import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { Button, Card } from '../components/ui'
import { useAuth } from '../lib/auth'

interface IntegrationStatus {
  engine: string
  available: boolean
  state: string
  reason: string
}

export default function Settings() {
  const { user } = useAuth()
  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([])
  const [killSwitch, setKillSwitch] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get<{ integrations: IntegrationStatus[] }>('/api/health/integrations')
      .then((r) => setIntegrations(r.integrations))
      .catch(() => {})
  }, [])

  const toggleKillSwitch = async () => {
    setError('')
    try {
      const res = await api.post<{ kill_switch: boolean }>('/api/admin/kill-switch?enabled=' + (!killSwitch))
      setKillSwitch(res.kill_switch)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to toggle kill switch')
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Settings</h1>

      <Card title="Integrations">
        {integrations.map((i) => (
          <div key={i.engine} className="mb-3 rounded border border-slate-200 p-3 text-sm dark:border-slate-700">
            <div className="font-semibold text-slate-800 dark:text-slate-200">
              {i.engine} — {i.state}
            </div>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{i.reason}</p>
          </div>
        ))}
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Unconfigured integrations are shown honestly. No external engine capability is claimed
          until it is implemented and tested.
        </p>
      </Card>

      {user?.role === 'admin' && (
        <Card title="Global kill switch">
          <p className="mb-2 text-sm text-slate-600 dark:text-slate-400">
            The kill switch immediately stops all scan requests across all workers. Scans in
            flight are marked cancelled. Check between every request before any traffic is sent.
          </p>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <Button variant={killSwitch ? 'secondary' : 'danger'} onClick={toggleKillSwitch}>
            {killSwitch ? 'Release kill switch' : 'Engage kill switch'}
          </Button>
        </Card>
      )}
    </div>
  )
}