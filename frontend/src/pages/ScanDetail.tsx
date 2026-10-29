import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { API_BASE, api, getToken } from '../lib/api'
import { Badge, Button, Card, EmptyState } from '../components/ui'

interface LiveStatus {
  status: string
  phase: string
  requests_sent: number
  endpoints_discovered: number
  tests_run: number
  progress: Record<string, unknown>
  error_message: string | null
}

interface EndpointRow {
  id: string
  url: string
  method: string
  status_code: number | null
  content_type: string | null
}

interface ExecutionRow {
  id: string
  module_id: string
  status: string
  detail: string
}

const STATUS_TONE: Record<string, string> = {
  running: 'blue', completed: 'green', failed: 'high',
  cancelled: 'informational', pending: 'slate', queued: 'slate',
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [live, setLive] = useState<LiveStatus | null>(null)
  const [endpoints, setEndpoints] = useState<EndpointRow[]>([])
  const [executions, setExecutions] = useState<ExecutionRow[]>([])
  const [showAttackOnly, setShowAttackOnly] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const refreshLists = (attackOnly: boolean) => {
    if (!id) return
    api.get<{ endpoints: EndpointRow[] }>(`/api/scans/${id}/endpoints?limit=200`).then((r) => setEndpoints(r.endpoints)).catch(() => {})
    api.get<{ executions: ExecutionRow[] }>(`/api/scans/${id}/executions?limit=300`).then((r) => setExecutions(r.executions)).catch(() => {})
    api.get(`/api/scans/${id}/exchanges?limit=20${attackOnly ? '&attack_only=true' : ''}`).catch(() => {})
  }

  useEffect(() => {
    if (!id) return
    const es = new EventSource(`${API_BASE}/api/scans/${id}/stream?token=${getToken()}`)
    esRef.current = es
    es.onmessage = (event) => {
      const data: LiveStatus = JSON.parse(event.data)
      setLive(data)
      refreshLists(showAttackOnly)
      if (['completed', 'failed', 'cancelled'].includes(data.status)) es.close()
    }
    es.onerror = () => es.close()
    refreshLists(false)
    return () => es.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id])

  const control = async (action: 'cancel' | 'pause' | 'resume') => {
    if (!id) return
    try {
      const updated = await api.post<{ status: string; phase: string; error_message: string | null }>(
        `/api/scans/${id}/${action}`)
      // reflect the change immediately instead of waiting for the next SSE tick
      setLive((prev) => prev && { ...prev, status: updated.status, phase: updated.phase,
                                  error_message: updated.error_message })
      refreshLists(showAttackOnly)
    } catch { /* errors also surface via the SSE error_message field */ }
  }

  if (!live) return <p className="text-slate-500">Loading scan…</p>

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Scan {id?.slice(0, 8)}</h1>
        <Badge tone={STATUS_TONE[live.status] || 'slate'}>{live.status}</Badge>
        <span className="text-sm text-slate-500">phase: {live.phase}</span>
        {['pending', 'queued', 'running'].includes(live.status) && (
          <div className="ml-auto flex gap-2">
            <Button variant="secondary" onClick={() => control('pause')}>Pause</Button>
            <Button variant="secondary" onClick={() => control('resume')}>Resume</Button>
            <Button variant="danger" onClick={() => control('cancel')}>Cancel</Button>
          </div>
        )}
      </div>

      {live.error_message && (
        <p className="rounded bg-red-100 p-3 text-sm text-red-700 dark:bg-red-900/40 dark:text-red-300">
          {live.error_message}
        </p>
      )}

      <div className="grid grid-cols-3 gap-4">
        <Card><div className="text-xs uppercase text-slate-500">Requests sent</div>
          <div className="text-2xl font-bold text-slate-900 dark:text-slate-100">{live.requests_sent}</div></Card>
        <Card><div className="text-xs uppercase text-slate-500">Endpoints discovered</div>
          <div className="text-2xl font-bold text-slate-900 dark:text-slate-100">{live.endpoints_discovered}</div></Card>
        <Card><div className="text-xs uppercase text-slate-500">Tests run</div>
          <div className="text-2xl font-bold text-slate-900 dark:text-slate-100">{live.tests_run}</div></Card>
      </div>

      <Card title={`Endpoint inventory (${endpoints.length})`}>
        {endpoints.length === 0 ? (
          <EmptyState message="No endpoints discovered yet." />
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500">
              <tr><th className="py-1">Method</th><th className="py-1">URL</th><th className="py-1">Status</th><th className="py-1">Content type</th></tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.id} className="border-t border-slate-200 dark:border-slate-800">
                  <td className="py-1 pr-2 font-mono text-slate-600 dark:text-slate-400">{e.method}</td>
                  <td className="py-1 pr-2 break-all text-slate-700 dark:text-slate-300">{e.url}</td>
                  <td className="py-1 pr-2 text-slate-600 dark:text-slate-400">{e.status_code ?? '—'}</td>
                  <td className="py-1 text-slate-600 dark:text-slate-400">{e.content_type ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Test execution history">
        {executions.length === 0 ? (
          <EmptyState message="No test executions yet." />
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500">
              <tr><th className="py-1">Module</th><th className="py-1">Status</th><th className="py-1">Detail</th></tr>
            </thead>
            <tbody>
              {executions.slice(0, 100).map((t) => (
                <tr key={t.id} className="border-t border-slate-200 dark:border-slate-800">
                  <td className="py-1 pr-2 font-mono text-slate-600 dark:text-slate-400">{t.module_id}</td>
                  <td className="py-1 pr-2">
                    <Badge tone={t.status === 'finding' ? 'high' : t.status === 'failed' ? 'medium' : 'slate'}>
                      {t.status}
                    </Badge>
                  </td>
                  <td className="py-1 text-slate-600 dark:text-slate-400">{t.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
        <input type="checkbox" checked={showAttackOnly} onChange={(e) => { setShowAttackOnly(e.target.checked); refreshLists(e.target.checked) }} />
        Show attack requests only
      </label>
    </div>
  )
}