const API_BASE = import.meta.env.VITE_API_BASE || ''

export async function api(path, options = {}) {
  const token = localStorage.getItem('signalguard.access')
  const headers = new Headers(options.headers || {})
  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }
  if (token) headers.set('Authorization', `Bearer ${token}`)

  let response = await fetch(`${API_BASE}/api${path}`, { ...options, headers })
  if (response.status === 401 && token && !path.startsWith('/auth/')) {
    const refresh = localStorage.getItem('signalguard.refresh')
    if (refresh) {
      const renewed = await fetch(`${API_BASE}/api/auth/token/refresh/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh }),
      })
      if (renewed.ok) {
        const tokens = await renewed.json()
        localStorage.setItem('signalguard.access', tokens.access)
        headers.set('Authorization', `Bearer ${tokens.access}`)
        response = await fetch(`${API_BASE}/api${path}`, { ...options, headers })
      } else {
        localStorage.removeItem('signalguard.access')
        localStorage.removeItem('signalguard.refresh')
      }
    }
  }
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message = data.error || Object.values(data).flat().join(' ') || 'Request failed. Try again.'
    throw new Error(message)
  }
  return data
}

export const postJson = (path, body) => api(path, {
  method: 'POST',
  body: JSON.stringify(body),
})