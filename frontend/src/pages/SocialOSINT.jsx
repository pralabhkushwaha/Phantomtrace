import { useState } from 'react'
import { Users, Search, CheckCircle, XCircle, AlertTriangle, ExternalLink, Info, Shield } from 'lucide-react'
import { RiskBadge, LoadingSpinner } from '../components/UI'
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || ''

async function socialLookup(username) {
  const { data } = await axios.post(`${BASE_URL}/api/social/lookup`, { username })
  return data
}

const REL_COLOR = {
  High:   'text-green-400 border-green-800 bg-green-950/30',
  Medium: 'text-yellow-400 border-yellow-800 bg-yellow-950/20',
  Low:    'text-red-400 border-red-800 bg-red-950/20',
}

const CAT_ICON = {
  'Developer': '💻', 'Forum': '💬', 'Social': '📱',
  'Video': '🎬', 'Professional': '💼', 'Messaging': '✉️',
  'Code/Data Leak': '⚠️',
}

export default function SocialOSINT() {
  const [username, setUsername] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleSearch() {
    const val = username.trim().replace(/^@/, '')
    if (!val) return
    setLoading(true); setError(null); setResult(null)
    try {
      setResult(await socialLookup(val))
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Lookup failed.')
    } finally {
      setLoading(false)
    }
  }

  const found    = result?.results?.filter(r => r.found) || []
  const notFound = result?.results?.filter(r => !r.found && !r.error) || []
  const blocked  = result?.results?.filter(r => r.error) || []

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Users className="w-6 h-6 text-cyber-400" />
          Social Media <span className="text-cyber-400">OSINT</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Username intelligence across 12 platforms — GitHub & Reddit via official APIs (high accuracy)
        </p>
      </div>

      {/* Input */}
      <div className="card flex gap-3">
        <div className="relative flex-1">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-mono text-sm">@</span>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Enter username to investigate"
            className="input-field w-full pl-7 font-mono"
          />
        </div>
        <button onClick={handleSearch} disabled={!username.trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40 shrink-0">
          <Search className="w-4 h-4" />
          Search
        </button>
      </div>

      {loading && <LoadingSpinner message="Querying GitHub API, Reddit API, and 10 more platforms…" />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm p-4">{error}</div>}

      {result && (
        <div className="space-y-5">
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Risk Level</p>
              <RiskBadge level={result.risk?.level} score={result.risk?.score} />
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Found On</p>
              <p className="text-3xl font-bold font-mono text-green-400">{result.summary?.found_on}</p>
              <p className="text-xs text-gray-600">platforms</p>
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Confirmed</p>
              <p className="text-3xl font-bold font-mono text-cyber-400">{result.summary?.confirmed_found}</p>
              <p className="text-xs text-gray-600">via official API</p>
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Blocked</p>
              <p className="text-3xl font-bold font-mono text-yellow-400">{result.summary?.blocked_or_error}</p>
              <p className="text-xs text-gray-600">manual check needed</p>
            </div>
          </div>

          {/* Investigation note */}
          <div className="card border-blue-900/40 bg-blue-950/10 flex gap-3">
            <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <p className="text-xs text-blue-300">{result.investigation_note}</p>
          </div>

          {/* Found profiles */}
          {found.length > 0 && (
            <div>
              <h2 className="section-title flex items-center gap-2 mb-3">
                <CheckCircle className="w-4 h-4 text-green-400" />
                Found Profiles ({found.length})
              </h2>
              <div className="grid md:grid-cols-2 gap-3">
                {found.map(r => (
                  <div key={r.platform} className={`card border ${REL_COLOR[r.reliability] || 'border-dark-600'}`}>
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{CAT_ICON[r.category] || '🔍'}</span>
                        <div>
                          <p className="text-sm font-bold text-white">{r.platform}</p>
                          <p className="text-xs text-gray-500">{r.category}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${REL_COLOR[r.reliability]}`}>
                          {r.reliability} accuracy
                        </span>
                        <a href={r.profile_url} target="_blank" rel="noreferrer"
                          className="text-cyber-400 hover:text-cyber-300">
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      </div>
                    </div>

                    {/* GitHub / Reddit enriched data */}
                    {r.data && Object.keys(r.data).length > 0 && (
                      <div className="border-t border-current/20 pt-2 mt-2 space-y-1">
                        {r.data.display_name && r.data.display_name !== result.username && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Name</span>
                            <span className="text-gray-200 font-semibold">{r.data.display_name}</span>
                          </div>
                        )}
                        {r.data.bio && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Bio</span>
                            <span className="text-gray-300 break-all">{r.data.bio.slice(0, 120)}</span>
                          </div>
                        )}
                        {r.data.location && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Location</span>
                            <span className="text-green-300 font-mono">{r.data.location}</span>
                          </div>
                        )}
                        {r.data.email && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Email</span>
                            <span className="text-cyber-300 font-mono">{r.data.email}</span>
                          </div>
                        )}
                        {r.data.company && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Company</span>
                            <span className="text-gray-300">{r.data.company}</span>
                          </div>
                        )}
                        {r.data.blog && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Website</span>
                            <span className="text-cyber-400 font-mono break-all">{r.data.blog}</span>
                          </div>
                        )}
                        {r.data.public_repos !== undefined && (
                          <div className="flex gap-3 text-xs pt-1">
                            <span className="text-gray-400">{r.data.public_repos} repos</span>
                            <span className="text-gray-400">{r.data.followers} followers</span>
                            <span className="text-gray-400">{r.data.following} following</span>
                          </div>
                        )}
                        {r.data.karma !== undefined && (
                          <div className="flex gap-3 text-xs pt-1">
                            <span className="text-gray-400">Karma: {r.data.karma?.toLocaleString()}</span>
                            {r.data.verified && <span className="text-green-400">✓ Verified</span>}
                          </div>
                        )}
                        {r.data.created_at && (
                          <div className="flex gap-2 text-xs">
                            <span className="text-gray-500 w-20 shrink-0">Joined</span>
                            <span className="text-gray-400">{new Date(r.data.created_at).toLocaleDateString()}</span>
                          </div>
                        )}
                      </div>
                    )}

                    <a href={r.profile_url} target="_blank" rel="noreferrer"
                      className="mt-2 text-xs font-mono text-gray-500 hover:text-cyber-400 block truncate">
                      {r.profile_url}
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Blocked / needs manual check */}
          {blocked.length > 0 && (
            <div>
              <h2 className="section-title flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                Manual Verification Required ({blocked.length})
              </h2>
              <div className="grid md:grid-cols-2 gap-2">
                {blocked.map(r => (
                  <div key={r.platform} className="card border-yellow-900/30 bg-yellow-950/10 flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm text-yellow-300 font-medium">{r.platform}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{r.note || r.error}</p>
                    </div>
                    <a href={r.profile_url} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-cyber-400 hover:text-cyber-300 shrink-0">
                      Open <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Not found */}
          {notFound.length > 0 && (
            <div>
              <h2 className="section-title flex items-center gap-2 mb-3">
                <XCircle className="w-4 h-4 text-gray-500" />
                Not Found ({notFound.length})
              </h2>
              <div className="flex flex-wrap gap-2">
                {notFound.map(r => (
                  <a key={r.platform} href={r.profile_url} target="_blank" rel="noreferrer"
                    className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-dark-700 bg-dark-800 text-gray-500 hover:text-gray-300 hover:border-dark-600 transition-colors">
                    {CAT_ICON[r.category] || '🔍'} {r.platform}
                    <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Legal note */}
          <div className="card border-dark-600 bg-dark-800/40">
            <div className="flex gap-2">
              <Shield className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
              <div className="text-xs text-gray-400 space-y-1">
                <p className="font-semibold text-orange-400">Legal Process Required for Identity Disclosure</p>
                <p>For real identity behind social media accounts: Send legal notice to platform under <strong>IT Act Section 67/79</strong> or file request via <strong>cybercrime.gov.in</strong>. Platforms like Meta, Google, Twitter respond to court orders under <strong>MLAT/Indian court orders</strong>.</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
