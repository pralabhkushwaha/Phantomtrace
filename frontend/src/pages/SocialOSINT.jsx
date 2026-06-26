import { useState } from 'react'
import { Search, Users, CheckCircle, XCircle, AlertCircle, ExternalLink } from 'lucide-react'
import { socialLookup } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const PLATFORM_ICONS = {
  'GitHub':    '🐙',
  'Reddit':    '🤖',
  'Twitter/X': '🐦',
  'Instagram': '📸',
  'Telegram':  '✈️',
  'YouTube':   '▶️',
  'Pinterest': '📌',
  'Quora':     '❓',
  'TikTok':    '🎵',
  'LinkedIn':  '💼',
  'Snapchat':  '👻',
  'Pastebin':  '📋',
}

export default function SocialOSINT() {
  const [username, setUsername] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleLookup() {
    const val = username.trim().replace(/^@/, '')
    if (!val) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await socialLookup(val)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Lookup failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Users className="w-6 h-6 text-purple-400" />
          Social Media <span className="text-purple-400">OSINT</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Check suspect username / handle presence across 12 major platforms in real-time
        </p>
      </div>

      {/* Input */}
      <div className="card flex gap-3">
        <div className="flex-1 relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 font-mono text-sm">@</span>
          <input
            value={username}
            onChange={e => setUsername(e.target.value.replace(/^@/, ''))}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="Enter username or handle"
            className="input-field w-full pl-7 font-mono"
          />
        </div>
        <button onClick={handleLookup} disabled={!username.trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40 shrink-0">
          <Search className="w-4 h-4" />
          {loading ? 'Searching…' : 'Search Platforms'}
        </button>
      </div>

      {loading && <LoadingSpinner message={`Checking @${username} across 12 platforms…`} />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Platforms Checked', value: result.summary.total_checked, color: 'text-cyber-400' },
              { label: 'Found On',           value: result.summary.found_on,      color: 'text-green-400' },
              { label: 'Not Found',          value: result.summary.not_found,     color: 'text-gray-400' },
              { label: 'Risk Level',         value: <RiskBadge level={result.risk.level} score={result.risk.score} />, color: '' },
            ].map(({ label, value, color }) => (
              <div key={label} className="card text-center">
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
                <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Found platforms highlight */}
          {result.found_platforms?.length > 0 && (
            <div className="card border-green-800 bg-green-900/10">
              <p className="text-xs font-bold text-green-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" />
                Profile Found On {result.found_platforms.length} Platform{result.found_platforms.length > 1 ? 's' : ''}
              </p>
              <div className="flex flex-wrap gap-2">
                {result.found_platforms.map(p => (
                  <a key={p.platform} href={p.url} target="_blank" rel="noreferrer"
                    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-900/30 border border-green-800 text-green-300 text-sm hover:bg-green-900/50 transition-colors">
                    <span>{PLATFORM_ICONS[p.platform] || '🌐'}</span>
                    {p.platform}
                    <ExternalLink className="w-3 h-3 opacity-60" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* All results grid */}
          <div>
            <h2 className="section-title">All Platforms</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {result.results.map(r => (
                <div key={r.platform} className={`card flex items-center gap-3 border ${
                  r.error   ? 'border-dark-600 opacity-50' :
                  r.found   ? 'border-green-800 bg-green-900/10' :
                               'border-dark-700'
                }`}>
                  <span className="text-xl shrink-0">{PLATFORM_ICONS[r.platform] || '🌐'}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-200">{r.platform}</p>
                    <p className="text-xs text-gray-500 font-mono truncate">@{result.username}</p>
                  </div>
                  {r.error ? (
                    <AlertCircle className="w-4 h-4 text-dark-400 shrink-0" title={r.error} />
                  ) : r.found ? (
                    <a href={r.url} target="_blank" rel="noreferrer">
                      <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                    </a>
                  ) : (
                    <XCircle className="w-4 h-4 text-dark-500 shrink-0" />
                  )}
                </div>
              ))}
            </div>
          </div>

          <p className="text-xs text-dark-400 text-center font-mono">
            ⚠ Results based on HTTP status codes — verify manually before using in investigation
          </p>
        </div>
      )}
    </div>
  )
}
