import { useState } from 'react'
import { Link2, Search, ExternalLink, ShieldAlert } from 'lucide-react'
import { analyzeURL } from '../api/client'
import {
  LoadingSpinner, ErrorBox, RiskGauge, RiskBadge,
  FlagList, SectionCard, KVRow, RecommendationList,
} from '../components/UI'

const EXAMPLES = [
  'http://amaz0n-secure-login.xyz/kyc-verify',
  'https://bit.ly/3xyz123',
  'http://paypal-account-update.ru/login',
  'https://google.com',
]

export default function URLIntelligence() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  async function handleAnalyze() {
    if (!url.trim()) return
    setError(null); setResult(null); setLoading(true)
    try {
      const res = await analyzeURL(url.trim())
      setResult(res)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const ua = result?.url_analysis || {}
  const rep = ua.reputation || {}

  const verdictColor = {
    'Malicious': 'text-red-400',
    'Suspicious': 'text-orange-400',
    'Potentially Suspicious': 'text-yellow-400',
    'Likely Safe': 'text-green-400',
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">URL Intelligence</h1>
        <p className="text-sm text-gray-400 mt-1">
          Analyze URLs for malicious indicators, reputation, domain age, redirects, and homograph attacks.
        </p>
      </div>

      <div className="card space-y-4">
        <div className="flex gap-3">
          <input
            className="input-cyber flex-1"
            placeholder="Enter URL to analyze, e.g. https://paypal-account-update.ru/login"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          />
          <button onClick={handleAnalyze} disabled={loading} className="btn-primary shrink-0">
            <Search className="w-4 h-4" /> Analyze
          </button>
        </div>
        <div>
          <p className="text-xs text-gray-500 mb-2">Examples:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map(u => (
              <button key={u} onClick={() => setUrl(u)}
                className="text-xs font-mono bg-dark-800 hover:bg-dark-700 border border-dark-600 px-3 py-1 rounded text-cyber-300 transition-colors truncate max-w-[240px]">
                {u}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && <LoadingSpinner message="Fetching URL intelligence…" />}
      {error && <ErrorBox message={error} />}

      {result && (
        <div className="space-y-4 animate-slide-up">
          {/* Summary */}
          <div className="card-glow grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
            <div className="flex flex-col items-center">
              <RiskGauge score={result.risk?.total_score ?? 0} />
              <RiskBadge level={result.risk?.risk_level} score={result.risk?.total_score} />
            </div>
            <div className="sm:col-span-2 space-y-3">
              <div>
                <p className="text-xs text-gray-500 mb-1">Final Verdict</p>
                <p className={`text-lg font-bold ${verdictColor[ua.verdict] || 'text-gray-300'}`}>
                  {ua.verdict}
                </p>
              </div>
              <div className="font-mono text-xs text-gray-400 bg-dark-800 rounded p-3 break-all">
                {ua.url}
              </div>
            </div>
          </div>

          {/* URL breakdown */}
          <SectionCard title="URL Structure" icon={Link2}>
            <div className="space-y-0.5">
              <KVRow label="Scheme" value={ua.scheme?.toUpperCase()} mono />
              <KVRow label="Host" value={ua.host} mono />
              <KVRow label="Domain" value={ua.domain} mono />
              <KVRow label="TLD" value={ua.tld ? `.${ua.tld}` : '—'} mono />
              <KVRow label="Path" value={ua.path || '/'} mono />
              <KVRow label="Query" value={ua.query || '—'} mono />
              <KVRow label="IP Literal" value={ua.ip_literal || 'No'} mono />
              <KVRow label="URL Shortened" value={ua.is_shortened ? 'Yes ⚠️' : 'No'} />
              <KVRow label="Path Entropy" value={ua.path_entropy > 0 ? ua.path_entropy.toFixed(2) : '—'} />
            </div>
          </SectionCard>

          {/* Reputation feeds */}
          <SectionCard title="Threat Intelligence Feeds" icon={ShieldAlert}>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { name: 'VirusTotal', data: rep.virustotal },
                { name: 'URLHaus', data: rep.urlhaus },
                { name: 'PhishTank', data: rep.phishtank },
                { name: 'Google Safe Browsing', data: rep.google_safe_browsing },
                { name: 'AlienVault OTX', data: rep.alienvault_otx },
                { name: 'AbuseIPDB', data: rep.abuseipdb },
              ].map(({ name, data }) => {
                const available = data?.available
                const verdict = data?.verdict || 'N/A'
                const isClean = verdict === 'Clean'
                const isDanger = ['Malicious', 'Flagged', 'Phish'].includes(verdict)
                const extra = data?.pulses != null ? ` (${data.pulses} pulses)` : data?.score != null ? ` (${data.score}%)` : ''
                return (
                  <div key={name} className={`rounded-lg p-3 border text-center ${
                    !available ? 'bg-dark-800 border-dark-600 opacity-60'
                    : isDanger ? 'bg-red-900/30 border-red-700'
                    : 'bg-green-900/20 border-green-800'
                  }`}>
                    <p className="text-xs font-bold text-gray-300 mb-1">{name}</p>
                    <p className={`text-xs font-semibold ${
                      !available ? 'text-gray-500'
                      : isDanger ? 'text-red-400'
                      : isClean ? 'text-green-400'
                      : 'text-gray-300'
                    }`}>
                      {available ? verdict + extra : 'No API Key'}
                    </p>
                  </div>
                )
              })}
            </div>
            <p className="text-xs text-gray-500 mt-3">
              * Add API keys in Render environment variables for VirusTotal, Google Safe Browsing, AlienVault OTX, AbuseIPDB.
              URLHaus and PhishTank are always key-free.
            </p>
          </SectionCard>

          {/* Redirect chain */}
          {ua.redirect?.chain?.length > 0 && (
            <SectionCard title="Redirect Chain">
              <div className="space-y-2">
                {ua.redirect.chain.map((hop, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <span className="text-gray-500 font-mono w-4">{i + 1}</span>
                    <span className={`font-semibold ${hop.status === 200 ? 'text-green-400' : 'text-yellow-400'}`}>{hop.status}</span>
                    <span className="font-mono text-gray-300 truncate">{hop.url}</span>
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          {/* Homograph on the URL's domain */}
          {ua.homograph?.likely_impersonating && (
            <SectionCard title="Domain Impersonation">
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-3">
                <p className="text-sm font-semibold text-red-300">
                  ⚠️ This domain appears to impersonate {ua.homograph.impersonating_brand_name}
                </p>
                <p className="text-xs text-red-400 mt-1">Confidence: {ua.homograph.confidence}%</p>
                <FlagList flags={ua.homograph.flags || []} />
              </div>
            </SectionCard>
          )}

          {/* Flags */}
          <SectionCard title="Detection Flags">
            <FlagList flags={ua.flags || []} />
          </SectionCard>

          {/* Domain registration */}
          {ua.rdap && !ua.rdap.error && (
            <SectionCard title="Domain Registration">
              <div className="space-y-0.5">
                <KVRow label="Registrar" value={ua.rdap.registrar} />
                <KVRow label="Registered" value={ua.rdap.created} mono />
                <KVRow label="Domain Age" value={ua.rdap.age_days != null ? `${ua.rdap.age_days} days` : '—'} />
              </div>
            </SectionCard>
          )}

          {result.recommendations?.length > 0 && (
            <SectionCard title="Recommendations">
              <RecommendationList recommendations={result.recommendations.slice(0, 5)} />
            </SectionCard>
          )}
        </div>
      )}
    </div>
  )
}
