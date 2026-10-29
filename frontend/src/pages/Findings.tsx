import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../lib/api'
import { Badge, EmptyState, Select } from '../components/ui'

interface FindingRow {
  id: string
  title: string
  severity: string
  owasp_category: string
  verification_status: string
  status: string
  url: string
}

export default function Findings() {
  const [params, setParams] = useSearchParams()
  const [findings, setFindings] = useState<FindingRow[] | null>(null)
  const [q, setQ] = useState(params.get('q') || '')

  const load = () => {
    const qs = new URLSearchParams()
    const appId = params.get('application')
    const severity = params.get('severity')
    const status = params.get('status')
    if (appId) qs.set('application_id', appId)
    if (severity) qs.set('severity', severity)
    if (status) qs.set('status', status)
    if (q) qs.set('q', q)
    api.get<FindingRow[]>(`/api/findings?${qs}`).then(setFindings).catch(() => setFindings([]))
  }

  useEffect(load, [params]) // eslint-disable-line react-hooks/exhaustive-deps

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next)
  }

  if (findings === null) return <p className="text-slate-500">Loading…</p>

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Findings</h1>
      <div className="flex flex-wrap gap-2">
        <input
          className="w-64 rounded border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
          placeholder="Search titles…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && load()}
        />
        <Select value={params.get('severity') || ''} onChange={(e) => updateParam('severity', e.target.value)} className="!w-40">
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'informational'].map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={params.get('status') || ''} onChange={(e) => updateParam('status', e.target.value)} className="!w-44">
          <option value="">All statuses</option>
          {['open', 'confirmed', 'fixed', 'false_positive', 'risk_accepted'].map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      </div>

      {findings.length === 0 ? (
        <EmptyState message="No findings match. Clean scans, filters that exclude everything, and unscanned applications all look like this." />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              <tr>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Title</th>
                <th className="px-4 py-2">OWASP</th>
                <th className="px-4 py-2">Verification</th>
                <th className="px-4 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} className="border-t border-slate-200 dark:border-slate-800">
                  <td className="px-4 py-2"><Badge tone={f.severity}>{f.severity}</Badge></td>
                  <td className="px-4 py-2">
                    <Link to={`/findings/${f.id}`} className="text-blue-600 hover:underline">{f.title}</Link>
                    <div className="text-xs text-slate-500">{f.url}</div>
                  </td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{f.owasp_category}</td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{f.verification_status}</td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{f.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}