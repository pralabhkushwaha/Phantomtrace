import { useState } from 'react'
import { Globe2, Search, Plus, X, AlertTriangle, CheckCircle } from 'lucide-react'
import { analyzeDomain, analyzeBulkDomains } from '../api/client'
import {
  LoadingSpinner, ErrorBox, RiskGauge, RiskBadge,
  FlagList, SectionCard, KVRow, RecommendationList,
} from '../components/UI'

const EXAMPLE_DOMAINS = [
  'faceb00k-login.com',
  'linkedln-login.com',
  'micros0ft-security.com',
  'paypaI.com',
  'amaz0n-kyc-verify.ru',
  'sbi-secure-update.in',
]

export default function HomographDetection() {
  const [domain, setDomain] = useState('')
  const [bulkList, setBulkList] = useState([])
  const [bulkInput, setBulkInput] = useState('')
  const [mode, setMode] = useState('single')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [bulkResults, setBulkResults] = useState([])

  async function handleSingle() {
    if (!domain.trim()) return
    setError(null); setResult(null)
    setLoading(true)
    try {
      const res = await analyzeDomain(domain.trim())
      setResult(res)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleBulk() {
    const domains = [...new Set(bulkList.concat(
      bulkInput.split(/[\n,]+/).map(d => d.trim()).filter(Boolean)
    ))]
    if (!domains.length) return
    setError(null); setBulkResults([])
    setLoading(true)
    try {
      const res = await analyzeBulkDomains(domains)
      setBulkResults(res.results || [])
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const hg = result?.homograph

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Homograph &amp; Brand Impersonation Detector</h1>
        <p className="text-sm text-gray-400 mt-1">
          Detect Unicode spoofing, typosquatting, and brand impersonation in domain names.
        </p>
      </div>

      {/* Mode toggle */}
      <div className="card space-y-4">
        <div className="flex gap-2 bg-dark-800 p-1 rounded-lg w-fit">
          {['single', 'bulk'].map(m => (
            <button key={m} onClick={() => setMode(m)}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${mode === m ? 'bg-cyber-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
              {m === 'single' ? '🔍 Single Domain' : '📋 Bulk Analysis'}
            </button>
          ))}
        </div>

        {mode === 'single' ? (
          <div className="flex gap-3">
            <input
              className="input-cyber flex-1"
              placeholder="Enter domain to analyze, e.g. faceb00k-login.com"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSingle()}
            />
            <button onClick={handleSingle} disabled={loading} className="btn-primary shrink-0">
              <Search className="w-4 h-4" /> Analyze
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <textarea
              className="input-cyber h-32 resize-none"
              placeholder="Enter domains, one per line or comma-separated (max 20)…"
              value={bulkInput}
              onChange={e => setBulkInput(e.target.value)}
            />
            <button onClick={handleBulk} disabled={loading} className="btn-primary">
              <Globe2 className="w-4 h-4" /> Analyze All
            </button>
          </div>
        )}

        {/* Examples */}
        <div>
          <p className="text-xs text-gray-500 mb-2">Try an example:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLE_DOMAINS.map(d => (
              <button key={d} onClick={() => { setDomain(d); setMode('single') }}
                className="text-xs font-mono bg-dark-800 hover:bg-dark-700 border border-dark-600 hover:border-dark-500 px-3 py-1 rounded text-cyber-300 transition-colors">
                {d}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && <LoadingSpinner message="Scanning domain for impersonation…" />}
      {error && <ErrorBox message={error} />}

      {/* Single result */}
      {result && hg && (
        <div className="space-y-4 animate-slide-up">
          <div className="card-glow grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
            <div className="flex flex-col items-center">
              <RiskGauge score={result.risk?.total_score ?? 0} />
              <RiskBadge level={result.risk?.risk_level} score={result.risk?.total_score} />
            </div>
            <div className="sm:col-span-2 space-y-3">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Analyzed Domain</p>
                <p className="font-mono text-lg text-white">{hg.domain}</p>
              </div>
              {hg.likely_impersonating ? (
                <div className="bg-red-900/30 border border-red-700 rounded-lg p-3">
                  <p className="text-sm font-semibold text-red-300 mb-1">
                    ⚠️ Likely impersonating {hg.impersonating_brand_name}
                  </p>
                  <p className="text-xs text-red-400">Real domain: <span className="font-mono">{hg.likely_impersonating}</span></p>
                  <p className="text-xs text-red-400 mt-0.5">Confidence: {hg.confidence}%</p>
                </div>
              ) : (
                <div className="bg-green-900/20 border border-green-800 rounded-lg p-3">
                  <p className="text-sm text-green-400 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" /> No brand impersonation detected
                  </p>
                </div>
              )}
            </div>
          </div>

          <SectionCard title="Detection Details" icon={Globe2}>
            <div className="space-y-0.5">
              <KVRow label="Punycode Detected" value={hg.punycode_detected ? 'Yes ⚠️' : 'No'} />
              <KVRow label="Mixed Script" value={hg.mixed_script ? 'Yes ⚠️ (Cyrillic/Greek)' : 'No'} />
              <KVRow label="Digit Substitution" value={hg.digit_substitution ? 'Yes ⚠️ (0→o, 1→l, etc.)' : 'No'} />
              {hg.decoded_unicode && <KVRow label="Unicode Render" value={hg.decoded_unicode} mono />}
              <KVRow label="Edit Distance" value={hg.edit_distance != null ? `${hg.edit_distance} character(s)` : '—'} />
            </div>
          </SectionCard>

          {hg.flags?.length > 0 && (
            <SectionCard title="Flags">
              <FlagList flags={hg.flags} />
            </SectionCard>
          )}

          {result.recommendations?.length > 0 && (
            <SectionCard title="Recommendations">
              <RecommendationList recommendations={result.recommendations.slice(0, 4)} />
            </SectionCard>
          )}
        </div>
      )}

      {/* Bulk results */}
      {bulkResults.length > 0 && (
        <div className="space-y-4 animate-slide-up">
          <h2 className="section-title">Bulk Analysis Results</h2>
          <div className="card overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700 bg-dark-800/50">
                  <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Domain</th>
                  <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Impersonating</th>
                  <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Confidence</th>
                  <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Flags</th>
                </tr>
              </thead>
              <tbody>
                {bulkResults.map((r, i) => (
                  <tr key={i} className="border-b border-dark-800 last:border-0 hover:bg-dark-800/30">
                    <td className="px-4 py-3 font-mono text-xs text-cyber-300">{r.domain}</td>
                    <td className="px-4 py-3 text-xs">
                      {r.impersonating_brand_name
                        ? <span className="text-red-300">{r.impersonating_brand_name}</span>
                        : <span className="text-green-500">None</span>}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono">
                      {r.confidence > 0 ? (
                        <span className={r.confidence >= 80 ? 'text-red-400' : r.confidence >= 60 ? 'text-orange-400' : 'text-yellow-400'}>
                          {r.confidence}%
                        </span>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {r.flags?.length > 0 ? `${r.flags.length} flag(s)` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
