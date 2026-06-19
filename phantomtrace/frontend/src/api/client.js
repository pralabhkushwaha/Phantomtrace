import axios from 'axios'

// In production set VITE_API_URL to your Render backend URL
// e.g. https://phantomtrace-backend.onrender.com
const BASE_URL = import.meta.env.VITE_API_URL || ''

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
})

// ── Email Forensics ───────────────────────────────────────────────────────

export async function analyzeEmailFile(file) {
  const fd = new FormData()
  fd.append('file', file)
  const { data } = await api.post('/api/email/analyze', fd, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function analyzeEmailRaw(rawHeaders) {
  const fd = new FormData()
  fd.append('raw_headers', rawHeaders)
  const { data } = await api.post('/api/email/analyze', fd)
  return data
}

// ── Homograph / Domain ────────────────────────────────────────────────────

export async function analyzeDomain(domain) {
  const { data } = await api.post('/api/homograph/analyze', { domain })
  return data
}

export async function analyzeBulkDomains(domains) {
  const { data } = await api.post('/api/homograph/bulk', { domains })
  return data
}

// ── URL Intelligence ──────────────────────────────────────────────────────

export async function analyzeURL(url, follow_redirects = true) {
  const { data } = await api.post('/api/url/analyze', { url, follow_redirects })
  return data
}

// ── Fraud / Content Detection ─────────────────────────────────────────────

export async function analyzeContent(text, subject = '') {
  const { data } = await api.post('/api/content/analyze', { text, subject })
  return data
}

// ── History ───────────────────────────────────────────────────────────────

export async function getHistory(limit = 20) {
  const { data } = await api.get(`/api/history/?limit=${limit}`)
  return data
}

export async function getInvestigation(id) {
  const { data } = await api.get(`/api/history/${id}`)
  return data
}

export async function deleteInvestigation(id) {
  const { data } = await api.delete(`/api/history/${id}`)
  return data
}

export default api
