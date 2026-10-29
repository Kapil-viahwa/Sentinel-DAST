import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../lib/api'
import { Badge, Button, Card, Select } from '../components/ui'
import { useAuth } from '../lib/auth'

interface Finding {
  id: string
  title: string
  owasp_category: string
  cwe_ids: string[]
  severity: string
  confidence: string
  verification_status: string
  url: string
  method: string
  parameter: string | null
  role: string | null
  description: string
  preconditions: string
  reproduction_steps: string[]
  impact: string
  root_cause_hypothesis: string
  remediation: string
  references: string[]
  cvss_vector: string | null
  cvss_score: number | null
  status: string
  retest_status: string
  override_rationale: string | null
  ticket_reference: string | null
}

interface EvidenceRow {
  id: string
  kind: string
  redacted_request: Record<string, unknown>
  redacted_response: Record<string, unknown>
  notes: string
}

interface AuditRow {
  action: string
  user_email: string | null
  detail: Record<string, unknown>
  created_at: string
}

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const { user } = useAuth()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [evidence, setEvidence] = useState<EvidenceRow[]>([])
  const [audit, setAudit] = useState<AuditRow[]>([])
  const [newStatus, setNewStatus] = useState('')
  const [rationale, setRationale] = useState('')
  const [error, setError] = useState('')

  const load = () => {
    if (!id) return
    api.get<Finding>(`/api/findings/${id}`).then((f) => { setFinding(f); setNewStatus(f.status) }).catch(() => {})
    api.get<{ evidence: EvidenceRow[] }>(`/api/findings/${id}/evidence`).then((r) => setEvidence(r.evidence)).catch(() => {})
    api.get<{ audit: AuditRow[] }>(`/api/findings/${id}/audit`).then((r) => setAudit(r.audit)).catch(() => {})
  }

  useEffect(load, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  const saveOverride = async () => {
    setError('')
    try {
      await api.patch(`/api/findings/${id}`, { status: newStatus, override_rationale: rationale })
      setRationale('')
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed')
    }
  }

  if (!finding) return <p className="text-slate-500">Loading…</p>

  const canEdit = user?.role === 'admin' || user?.role === 'analyst'

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">{finding.title}</h1>
        <Badge tone={finding.severity}>{finding.severity}</Badge>
        <Badge tone="slate">{finding.verification_status}</Badge>
      </div>
      <p className="text-sm text-slate-600 dark:text-slate-400">
        {finding.owasp_category} · {finding.cwe_ids.join(', ')} · confidence {finding.confidence}
        {finding.cvss_score !== null && ` · CVSS ${finding.cvss_score} (${finding.cvss_vector})`}
      </p>
      <p className="break-all font-mono text-sm text-slate-700 dark:text-slate-300">
        {finding.method} {finding.url}{finding.parameter ? ` · param: ${finding.parameter}` : ''}
      </p>

      <Card title="Description">
        <p className="text-sm text-slate-700 dark:text-slate-300">{finding.description}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400"><b>Preconditions:</b> {finding.preconditions}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400"><b>Impact:</b> {finding.impact}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400"><b>Root cause hypothesis:</b> {finding.root_cause_hypothesis}</p>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400"><b>Remediation:</b> {finding.remediation}</p>
      </Card>

      <Card title="Reproduction steps">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-700 dark:text-slate-300">
          {finding.reproduction_steps.map((s, i) => <li key={i}>{s}</li>)}
        </ol>
      </Card>

      <Card title={`Evidence (${evidence.length}) — secrets redacted`}>
        {evidence.length === 0 ? (
          <p className="text-sm text-slate-500">No evidence rows.</p>
        ) : (
          evidence.map((e) => (
            <div key={e.id} className="mb-3 rounded border border-slate-200 p-3 text-xs dark:border-slate-700">
              <div className="mb-1 font-semibold text-slate-700 dark:text-slate-300">{e.kind} {e.notes && `· ${e.notes}`}</div>
              <pre className="overflow-x-auto whitespace-pre-wrap text-slate-600 dark:text-slate-400">
                {JSON.stringify({ request: e.redacted_request, response: e.redacted_response }, null, 2)}
              </pre>
            </div>
          ))
        )}
      </Card>

      {canEdit && (
        <Card title="Analyst override">
          <div className="space-y-2">
            <Select value={newStatus} onChange={(e) => setNewStatus(e.target.value)}>
              {['open', 'confirmed', 'fixed', 'false_positive', 'risk_accepted'].map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
            <textarea
              className="w-full rounded border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              rows={2}
              placeholder="Mandatory rationale for this override (min 10 characters)"
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
            />
            {error && <p className="text-sm text-red-600">{error}</p>}
            <Button onClick={saveOverride} disabled={rationale.trim().length < 10}>Save override</Button>
            {finding.override_rationale && (
              <p className="text-xs text-slate-500">Previous rationale: {finding.override_rationale}</p>
            )}
          </div>
        </Card>
      )}

      {audit.length > 0 && (
        <Card title="Audit history">
          <ul className="space-y-1 text-xs text-slate-600 dark:text-slate-400">
            {audit.map((a, i) => (
              <li key={i}>{a.created_at} · {a.action} · {a.user_email} · {JSON.stringify(a.detail)}</li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}