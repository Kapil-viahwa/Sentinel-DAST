const API_BASE = (import.meta as any).env?.VITE_API_BASE || 'http://localhost:8000'

export function getToken(): string {
  return localStorage.getItem('sentinel_token') || ''
}

export function setToken(token: string) {
  if (token) localStorage.setItem('sentinel_token', token)
  else localStorage.removeItem('sentinel_token')
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(0,
      `Cannot reach the Sentinel API at ${API_BASE}. Is the backend running? ` +
      `(start it with: uvicorn app.main:app --port 8000)`)
  }
  if (!res.ok) {
    const isJson = (res.headers.get('content-type') || '').includes('application/json')
    if (!isJson) {
      // A non-JSON error here usually means something other than the Sentinel API
      // is listening on the API base (e.g. the Vite dev server answering 404).
      throw new ApiError(res.status,
        `The API base ${API_BASE} answered ${res.status} ${res.statusText} — it is not the ` +
        `Sentinel backend. Rebuild/launch the frontend with VITE_API_BASE=http://<api-host>:8000 ` +
        `and make sure uvicorn is running.`)
    }
    const detail = await res.json().catch(() => null)
    throw new ApiError(res.status, typeof detail?.detail === 'string' ? detail.detail : 'Request failed')
  }
  return res.json()
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
}

export { API_BASE }