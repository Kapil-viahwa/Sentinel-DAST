import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { Badge, Card, EmptyState } from '../components/ui'

interface Application {
  id: string
  name: string
  base_url: string
  environment: string
  description: string
  allowed_hosts: string[]
  excluded_paths: string[]
  created_at: string
}

export default function Applications() {
  const [apps, setApps] = useState<Application[] | null>(null)

  useEffect(() => {
    api.get<Application[]>('/api/applications').then(setApps).catch(() => setApps([]))
  }, [])

  if (apps === null) return <p className="text-slate-500">Loading…</p>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Applications</h1>
        <Link
          to="/scans/new"
          className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
        >
          Register application / new scan
        </Link>
      </div>
      {apps.length === 0 && (
        <EmptyState message="No applications registered yet. Register one with its approved scope and authorization record to begin." />
      )}
      <div className="grid gap-3 md:grid-cols-2">
        {apps.map((app) => (
          <Card key={app.id}>
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-slate-900 dark:text-slate-100">{app.name}</h2>
              <Badge tone="blue">{app.environment}</Badge>
            </div>
            <p className="mt-1 break-all text-sm text-slate-600 dark:text-slate-400">{app.base_url}</p>
            {app.description && <p className="mt-1 text-sm text-slate-500">{app.description}</p>}
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Approved hosts: {app.allowed_hosts.length ? app.allowed_hosts.join(', ') : 'base URL only'} ·
              Excluded paths: {app.excluded_paths.length ? app.excluded_paths.join(', ') : 'none'}
            </p>
            <div className="mt-3 flex gap-2">
              <Link to={`/scans/new?application=${app.id}`} className="text-sm text-blue-600 hover:underline">
                New scan
              </Link>
              <Link to={`/scans?application=${app.id}`} className="text-sm text-blue-600 hover:underline">
                Scan history
              </Link>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}