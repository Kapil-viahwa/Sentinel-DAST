import { useEffect, useState } from 'react'
import { API_BASE, api, getToken } from '../lib/api'
import { Button, Card, EmptyState, Field, Select } from '../components/ui'

interface ReportRow {
  id: string
  kind: string
  format: string
  scan_id: string | null
  generated_at: string
}

export default function Reports() {
  const [reports, setReports] = useState<ReportRow[] | null>(null)
  const [kind, setKind] = useState('technical')
  const [format, setFormat] = useState('html')
  const [scanId, setScanId] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => api.get<{ reports: ReportRow[] }>('/api/reports').then((r) => setReports(r.reports)).catch(() => setReports([]))

  useEffect(load, [])

  const generate = async () => {
    setError('')
    setBusy(true)
    try {
      await api.post('/api/reports/generate', {
        kind,
        format,
        scan_id: kind === 'portfolio' ? null : scanId || null,
      })
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Generation failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Reports</h1>

      <Card title="Generate a report">
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="Kind">
            <Select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="technical">Technical (scan)</option>
              <option value="executive">Executive (scan)</option>
              <option value="portfolio">Portfolio (all applications)</option>
            </Select>
          </Field>
          <Field label="Format">
            <Select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="html">HTML</option>
              <option value="json">JSON</option>
            </Select>
          </Field>
          {kind !== 'portfolio' && (
            <Field label="Scan ID" hint="From the Scans page">
              <input
                className="w-full rounded border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                value={scanId}
                onChange={(e) => setScanId(e.target.value)}
              />
            </Field>
          )}
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button onClick={generate} disabled={busy || (kind !== 'portfolio' && !scanId)}>
            {busy ? 'Generating…' : 'Generate'}
          </Button>
          {error && <span className="text-sm text-red-600">{error}</span>}
        </div>
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          PDF: use your browser's print-to-PDF on the generated HTML report (server-side PDF generation is not implemented).
        </p>
      </Card>

      {reports === null ? (
        <p className="text-slate-500">Loading…</p>
      ) : reports.length === 0 ? (
        <EmptyState message="No reports generated yet." />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500">
            <tr><th className="py-1">Kind</th><th className="py-1">Format</th><th className="py-1">Scan</th><th className="py-1">Generated</th><th className="py-1"></th></tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-1 text-slate-700 dark:text-slate-300">{r.kind}</td>
                <td className="py-1 text-slate-600 dark:text-slate-400">{r.format}</td>
                <td className="py-1 font-mono text-slate-600 dark:text-slate-400">{r.scan_id?.slice(0, 8) ?? '—'}</td>
                <td className="py-1 text-slate-600 dark:text-slate-400">{r.generated_at}</td>
                <td className="py-1 text-right">
                  <a
                    href={`${API_BASE}/api/reports/${r.id}/download?token=${getToken()}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-600 hover:underline"
                    onClick={(e) => {
                      // download endpoint requires the Authorization header; open a
                      // fetch-backed download instead
                      e.preventDefault()
                      fetch(`${API_BASE}/api/reports/${r.id}/download`, {
                        headers: { Authorization: `Bearer ${getToken()}` },
                      })
                        .then((res) => res.blob())
                        .then((blob) => {
                          const url = URL.createObjectURL(blob)
                          const a = document.createElement('a')
                          a.href = url
                          a.download = `sentinel-${r.kind}.${r.format}`
                          a.click()
                          URL.revokeObjectURL(url)
                        })
                    }}
                  >
                    Download
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}