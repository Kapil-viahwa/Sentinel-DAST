import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../lib/api'
import { Button, Card, Field, Input, Select } from '../components/ui'

interface AppOut {
  id: string
  name: string
  base_url: string
  environment: string
  allowed_hosts: string[]
}

const PROFILES: Record<string, { desc: string; risk: string }> = {
  passive: { desc: 'Analyze observed traffic only. No attack payloads are sent.', risk: 'Minimal impact.' },
  baseline: { desc: 'Passive analysis plus conservative active tests (safe payloads, read-only GET probes).', risk: 'Low impact.' },
  standard: { desc: 'Broader active tests with bounded verification, including CORS, redirect and replay checks.', risk: 'Moderate: harmless probes on all discovered parameters.' },
  comprehensive: { desc: 'Extended context-aware tests with higher request budgets and explicit safety controls.', risk: 'Higher request volume; use only on non-production or properly isolated environments.' },
}

const AUTH_TYPES = [
  { value: 'anonymous', label: 'Anonymous (no authentication)' },
  { value: 'form', label: 'Form-based login' },
  { value: 'cookie', label: 'Cookie session (paste session cookie)' },
  { value: 'bearer', label: 'Bearer token' },
]

const CSV = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

export default function NewScan() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [step, setStep] = useState(1)
  const [apps, setApps] = useState<AppOut[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // Step 1 — target
  const [appId, setAppId] = useState(params.get('application') || 'new')
  const [name, setName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [environment, setEnvironment] = useState('qa')
  const [allowedHosts, setAllowedHosts] = useState('')
  const [includedPaths, setIncludedPaths] = useState('')
  const [excludedPaths, setExcludedPaths] = useState('')
  const [authorizedBy, setAuthorizedBy] = useState('')
  const [authorizationRef, setAuthorizationRef] = useState('')
  const [confirmationText, setConfirmationText] = useState('')

  // Step 2 — authentication
  const [authType, setAuthType] = useState('anonymous')
  const [loginUrl, setLoginUrl] = useState('')
  const [usernameField, setUsernameField] = useState('username')
  const [passwordField, setPasswordField] = useState('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('authenticated')
  const [token, setToken] = useState('')
  const [cookieHeader, setCookieHeader] = useState('')

  // Step 3 — crawl configuration
  const [maxDepth, setMaxDepth] = useState(3)
  const [maxUrls, setMaxUrls] = useState(200)
  const [maxRequests, setMaxRequests] = useState(500)
  const [rateLimit, setRateLimit] = useState(1)
  const [renderJs, setRenderJs] = useState(false)
  const [sitemapUrl, setSitemapUrl] = useState('')
  const [openapiJson, setOpenapiJson] = useState('')

  // Step 4 — profile
  const [profile, setProfile] = useState('baseline')

  // Retest
  const [retestOf, setRetestOf] = useState('')

  useEffect(() => {
    api.get<AppOut[]>('/api/applications').then(setApps).catch(() => {})
  }, [])

  const createApp = async (): Promise<string> => {
    const app = await api.post<AppOut>('/api/applications', {
      name,
      base_url: baseUrl,
      environment,
      description: '',
      allowed_hosts: CSV(allowedHosts),
      included_paths: CSV(includedPaths),
      excluded_paths: CSV(excludedPaths),
      approved_origins: [],
      authorization: {
        authorized_by: authorizedBy,
        authorization_reference: authorizationRef,
        confirmation_text: confirmationText,
      },
    })
    return app.id
  }

  const launch = async () => {
    setError('')
    setBusy(true)
    try {
      let targetId = appId
      if (targetId === 'new') targetId = await createApp()

      const authConfig: Record<string, unknown> =
        authType === 'form'
          ? { login_url: loginUrl, username_field: usernameField, password_field: passwordField, username, password, role }
          : authType === 'bearer'
            ? { token, role }
            : authType === 'cookie'
              ? { cookie_header: cookieHeader, role }
              : {}

      let openapiSpec: unknown = null
      if (openapiJson.trim()) openapiSpec = JSON.parse(openapiJson)

      const scan = await api.post<{ id: string }>(
        `/api/scans?application_id=${targetId}`,
        {
          config: {
            profile,
            auth_type: authType,
            auth_config: authType === 'anonymous' ? null : authConfig,
            max_depth: Number(maxDepth),
            max_urls: Number(maxUrls),
            max_requests: Number(maxRequests),
            max_duration_seconds: 1800,
            rate_limit_rps: Number(rateLimit),
            concurrency_limit: 2,
            allowed_methods: ['GET', 'HEAD'],
            render_js: renderJs,
            openapi_spec: openapiSpec,
            sitemap_url: sitemapUrl || null,
            proxy_url: null,
          },
          authorization_confirmation: confirmationText,
          retest_of: retestOf || null,
        },
      )
      navigate(`/scans/${scan.id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan creation failed')
    } finally {
      setBusy(false)
    }
  }

  const step1Valid = appId !== 'new' || (name && baseUrl && authorizedBy && confirmationText.length >= 20)

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">New scan</h1>
      <div className="flex gap-2 text-xs">
        {['Target', 'Authentication', 'Crawl', 'Profile', 'Review & launch'].map((label, i) => (
          <span
            key={label}
            className={`rounded-full px-3 py-1 ${step === i + 1 ? 'bg-blue-600 text-white' : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}
          >
            {i + 1}. {label}
          </span>
        ))}
      </div>

      {error && <p className="rounded bg-red-100 p-3 text-sm text-red-700">{error}</p>}

      {step === 1 && (
        <Card title="Step 1 — Target and approved scope">
          <div className="space-y-3">
            <Field label="Application">
              <Select value={appId} onChange={(e) => setAppId(e.target.value)}>
                <option value="new">Register a new application…</option>
                {apps.map((a) => (
                  <option key={a.id} value={a.id}>{a.name} — {a.base_url}</option>
                ))}
              </Select>
            </Field>
            {appId === 'new' && (
              <>
                <Field label="Application name"><Input value={name} onChange={(e) => setName(e.target.value)} /></Field>
                <Field label="Base URL" hint="http:// or https:// URL of the authorized target">
                  <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://staging.example.com" />
                </Field>
                <Field label="Environment">
                  <Select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                    {['development', 'qa', 'uat', 'staging', 'production'].map((e) => (
                      <option key={e} value={e}>{e}</option>
                    ))}
                  </Select>
                </Field>
                <Field label="Additional approved hosts (comma-separated)" hint="Only these hosts plus the base URL host may be contacted. Use *.example.com for a subdomain wildcard.">
                  <Input value={allowedHosts} onChange={(e) => setAllowedHosts(e.target.value)} />
                </Field>
                <Field label="Included paths (comma-separated, optional)">
                  <Input value={includedPaths} onChange={(e) => setIncludedPaths(e.target.value)} placeholder="/app, /api" />
                </Field>
                <Field label="Excluded paths (comma-separated)">
                  <Input value={excludedPaths} onChange={(e) => setExcludedPaths(e.target.value)} placeholder="/logout, /admin/users/delete" />
                </Field>
                <Field label="Authorized by (authorizer name/contact)"><Input value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} /></Field>
                <Field label="Authorization reference (ticket, contract)"><Input value={authorizationRef} onChange={(e) => setAuthorizationRef(e.target.value)} /></Field>
                <Field label="Authorization confirmation statement" hint="Record the exact written authorization (minimum 20 characters — e.g. 'I, <name>, own this application and authorize security scanning of it.'). You will re-enter it verbatim to launch scans.">
                  <textarea
                    className="w-full rounded border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                    rows={3}
                    value={confirmationText}
                    onChange={(e) => setConfirmationText(e.target.value)}
                  />
                </Field>
              </>
            )}
          </div>
        </Card>
      )}

      {step === 2 && (
        <Card title="Step 2 — Authentication">
          <div className="space-y-3">
            <Field label="Authentication method">
              <Select value={authType} onChange={(e) => setAuthType(e.target.value)}>
                {AUTH_TYPES.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
              </Select>
            </Field>
            {authType === 'form' && (
              <>
                <Field label="Login URL" hint="Must be inside the approved scope"><Input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} /></Field>
                <Field label="Username field name"><Input value={usernameField} onChange={(e) => setUsernameField(e.target.value)} /></Field>
                <Field label="Test username"><Input value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
                <Field label="Password field name"><Input value={passwordField} onChange={(e) => setPasswordField(e.target.value)} /></Field>
                <Field label="Test password" hint="Encrypted at rest; never logged or included in reports"><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
                <Field label="Role label for this session"><Input value={role} onChange={(e) => setRole(e.target.value)} /></Field>
              </>
            )}
            {authType === 'bearer' && (
              <Field label="Bearer token" hint="Encrypted at rest; sent as Authorization: Bearer"><Input value={token} onChange={(e) => setToken(e.target.value)} /></Field>
            )}
            {authType === 'cookie' && (
              <Field label="Cookie header" hint="Example: sessionid=abc123; other=cookie"><Input value={cookieHeader} onChange={(e) => setCookieHeader(e.target.value)} /></Field>
            )}
            <p className="text-xs text-slate-500 dark:text-slate-400">
              To test role-based access control, configure additional roles via the API (auth_config.roles list).
              Credentials are encrypted and redacted from all logs, evidence and reports.
            </p>
          </div>
        </Card>
      )}

      {step === 3 && (
        <Card title="Step 3 — Crawl configuration">
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Max crawl depth"><Input type="number" min={1} max={8} value={maxDepth} onChange={(e) => setMaxDepth(+e.target.value)} /></Field>
            <Field label="Max discovered URLs"><Input type="number" min={1} value={maxUrls} onChange={(e) => setMaxUrls(+e.target.value)} /></Field>
            <Field label="Max requests" hint="Hard server-side cap applies"><Input type="number" min={1} value={maxRequests} onChange={(e) => setMaxRequests(+e.target.value)} /></Field>
            <Field label="Request rate (requests/second)" hint="Server caps at 10 rps. Default 1 rps is safest."><Input type="number" step="0.5" min={0.5} max={10} value={rateLimit} onChange={(e) => setRateLimit(+e.target.value)} /></Field>
            <Field label="Sitemap URL (optional)"><Input value={sitemapUrl} onChange={(e) => setSitemapUrl(e.target.value)} /></Field>
            <Field label="OpenAPI spec (JSON, optional)" hint="Paths are used as crawl seeds">
              <textarea
                className="w-full rounded border border-slate-300 px-3 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                rows={4}
                value={openapiJson}
                onChange={(e) => setOpenapiJson(e.target.value)}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input type="checkbox" checked={renderJs} onChange={(e) => setRenderJs(e.target.checked)} />
              JavaScript rendering (browser crawler; requires Playwright — reported as unconfigured if absent)
            </label>
          </div>
        </Card>
      )}

      {step === 4 && (
        <Card title="Step 4 — Scan profile">
          <div className="space-y-2">
            {Object.entries(PROFILES).map(([value, info]) => (
              <label key={value} className={`flex cursor-pointer gap-3 rounded border p-3 ${profile === value ? 'border-blue-600 bg-blue-50 dark:bg-slate-800' : 'border-slate-200 dark:border-slate-700'}`}>
                <input type="radio" name="profile" checked={profile === value} onChange={() => setProfile(value)} />
                <span>
                  <span className="block text-sm font-semibold capitalize text-slate-900 dark:text-slate-100">{value}</span>
                  <span className="block text-xs text-slate-600 dark:text-slate-400">{info.desc}</span>
                  <span className="block text-xs text-slate-500">{info.risk}</span>
                </span>
              </label>
            ))}
            <p className="text-xs text-slate-500 dark:text-slate-400">
              No profile guarantees complete OWASP Top 10 coverage. Only tests that actually run are reflected in results.
            </p>
          </div>
        </Card>
      )}

      {step === 5 && (
        <Card title="Step 5 — Review and launch">
          <div className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
            <p><b>Target:</b> {appId === 'new' ? baseUrl : apps.find((a) => a.id === appId)?.base_url}</p>
            <p><b>Environment:</b> {appId === 'new' ? environment : apps.find((a) => a.id === appId)?.environment}</p>
            <p><b>Approved hosts:</b> {appId === 'new' ? [CSV(allowedHosts).join(', ') || 'base URL only'] : apps.find((a) => a.id === appId)?.allowed_hosts.join(', ') || 'base URL only'}</p>
            <p><b>Excluded paths:</b> {appId === 'new' ? CSV(excludedPaths).join(', ') || 'none' : 'as configured on the application'}</p>
            <p><b>Authentication:</b> {authType}</p>
            <p><b>Crawl limits:</b> depth {maxDepth} · {maxUrls} URLs · {maxRequests} requests · {rateLimit} rps · JS rendering {renderJs ? 'on' : 'off'}</p>
            <p><b>Profile:</b> {profile} — {PROFILES[profile].desc}</p>
            <Field label="Authorization confirmation" hint="Re-enter the recorded authorization statement verbatim. The backend rejects scans without an exact match.">
              <textarea
                className="w-full rounded border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                rows={3}
                value={confirmationText}
                onChange={(e) => setConfirmationText(e.target.value)}
              />
            </Field>
            <Field label="Retest of scan ID (optional)" hint="Runs as a retest and reconciles reproduced vs fixed findings">
              <Input value={retestOf} onChange={(e) => setRetestOf(e.target.value)} />
            </Field>
          </div>
        </Card>
      )}

      <div className="flex justify-between">
        <Button variant="secondary" onClick={() => setStep(Math.max(1, step - 1))} disabled={step === 1}>
          Back
        </Button>
        {step < 5 ? (
          <Button onClick={() => setStep(step + 1)} disabled={step === 1 && !step1Valid}>
            Continue
          </Button>
        ) : (
          <Button onClick={launch} disabled={busy || !confirmationText}>
            {busy ? 'Launching…' : 'Launch scan'}
          </Button>
        )}
      </div>
    </div>
  )
}