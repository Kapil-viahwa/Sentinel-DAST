import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'
import { Card, EmptyState, Stat } from '../components/ui'

interface DashboardData {
  applications: number
  scans: { active: number; completed: number; total: number }
  endpoints: number
  findings: {
    total: number
    by_severity: Record<string, number>
    by_owasp: Record<string, number>
    confirmed: number
    suspected: number
    open: number
    closed: number
    false_positive_rate: number
    aging: Record<string, number>
    average_time_to_remediate_days: number | null
  }
  recurring_applications: number
  recent_scans: {
    id: string
    application_id: string
    status: string
    phase: string
    requests_sent: number
    endpoints_discovered: number
    created_at: string
  }[]
  empty: boolean
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational']
const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-900', high: 'bg-red-600', medium: 'bg-amber-500',
  low: 'bg-blue-500', informational: 'bg-slate-400',
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get<DashboardData>('/api/dashboard').then(setData).catch((e) => setError(e.message))
  }, [])

  if (error) return <p className="text-red-600">{error}</p>
  if (!data) return <p className="text-slate-500">Loading…</p>
  if (data.empty)
    return (
      <EmptyState message="No scan data yet. Register an application and launch your first scan to populate this dashboard." />
    )

  const maxSev = Math.max(1, ...SEV_ORDER.map((s) => data.findings.by_severity[s] || 0))

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Security Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="Applications" value={data.applications} />
        <Stat label="Active scans" value={data.scans.active} />
        <Stat label="Completed scans" value={data.scans.completed} />
        <Stat label="Endpoints" value={data.endpoints} />
        <Stat label="Findings" value={data.findings.total} />
        <Stat label="Open / Closed" value={`${data.findings.open} / ${data.findings.closed}`} />
        <Stat label="Confirmed" value={data.findings.confirmed} sub="evidence observed or validated" />
        <Stat label="Suspected" value={data.findings.suspected} sub="require manual validation" />
        <Stat label="False-positive rate" value={`${Math.round(data.findings.false_positive_rate * 100)}%`} />
        <Stat label="Avg. time to remediate" value={data.findings.average_time_to_remediate_days !== null ? `${data.findings.average_time_to_remediate_days}d` : '—'} />
        <Stat label="Apps with recurring findings" value={data.recurring_applications} />
        <Stat label="Total scans" value={data.scans.total} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Findings by severity">
          {SEV_ORDER.map((sev) => (
            <div key={sev} className="mb-2 flex items-center gap-2 text-sm">
              <span className="w-24 capitalize text-slate-600 dark:text-slate-300">{sev}</span>
              <div className="h-3 flex-1 rounded bg-slate-200 dark:bg-slate-800">
                <div
                  className={`h-3 rounded ${SEV_COLORS[sev]}`}
                  style={{ width: `${((data.findings.by_severity[sev] || 0) / maxSev) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right text-slate-600 dark:text-slate-300">{data.findings.by_severity[sev] || 0}</span>
            </div>
          ))}
        </Card>
        <Card title="Findings by OWASP Top 10:2025 category">
          {Object.keys(data.findings.by_owasp).length === 0 && (
            <p className="text-sm text-slate-500">No findings yet.</p>
          )}
          <ul className="space-y-1 text-sm">
            {Object.entries(data.findings.by_owasp).map(([cat, count]) => (
              <li key={cat} className="flex justify-between text-slate-700 dark:text-slate-300">
                <span>{cat}</span>
                <span className="font-semibold">{count}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Vulnerability aging (open findings)">
          <ul className="space-y-1 text-sm">
            {Object.entries(data.findings.aging).map(([bucket, count]) => (
              <li key={bucket} className="flex justify-between text-slate-700 dark:text-slate-300">
                <span>{bucket}</span>
                <span className="font-semibold">{count}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Latest scan activity">
          {data.recent_scans.length === 0 ? (
            <p className="text-sm text-slate-500">No scans yet.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {data.recent_scans.map((s) => (
                <li key={s.id}>
                  <Link to={`/scans/${s.id}`} className="text-blue-600 hover:underline">
                    {s.id.slice(0, 8)}
                  </Link>{' '}
                  <span className="text-slate-500 dark:text-slate-400">
                    · {s.status} · {s.phase} · {s.requests_sent} requests · {s.endpoints_discovered} endpoints
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  )
}