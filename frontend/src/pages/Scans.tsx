import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../lib/api'
import { Badge, EmptyState } from '../components/ui'

interface ScanRow {
  id: string
  application_id: string
  status: string
  phase: string
  is_retest: boolean
  requests_sent: number
  endpoints_discovered: number
  tests_run: number
  created_at: string
}

const STATUS_TONE: Record<string, string> = {
  running: 'blue', completed: 'green', failed: 'high',
  cancelled: 'informational', pending: 'slate', queued: 'slate',
}

export default function Scans() {
  const [params] = useSearchParams()
  const [scans, setScans] = useState<ScanRow[] | null>(null)

  useEffect(() => {
    const appId = params.get('application')
    const qs = appId ? `?application_id=${appId}` : ''
    api.get<ScanRow[]>(`/api/scans${qs}`).then(setScans).catch(() => setScans([]))
  }, [params])

  if (scans === null) return <p className="text-slate-500">Loading…</p>
  if (scans.length === 0)
    return <EmptyState message="No scans yet. Launch one from the Applications page." />

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Scans</h1>
      <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
            <tr>
              <th className="px-4 py-2">Scan</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Phase</th>
              <th className="px-4 py-2">Requests</th>
              <th className="px-4 py-2">Endpoints</th>
              <th className="px-4 py-2">Tests</th>
              <th className="px-4 py-2">Type</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-t border-slate-200 dark:border-slate-800">
                <td className="px-4 py-2">
                  <Link to={`/scans/${s.id}`} className="font-mono text-blue-600 hover:underline">
                    {s.id.slice(0, 8)}
                  </Link>
                </td>
                <td className="px-4 py-2"><Badge tone={STATUS_TONE[s.status] || 'slate'}>{s.status}</Badge></td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{s.phase}</td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{s.requests_sent}</td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{s.endpoints_discovered}</td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{s.tests_run}</td>
                <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{s.is_retest ? 'retest' : 'scan'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}