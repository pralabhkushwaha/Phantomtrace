import { useState } from 'react'
import { Globe, Search, MapPin, Wifi, ShieldAlert, ShieldCheck, Server } from 'lucide-react'
import { analyzeIP } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const SAMPLE_IPS = ['8.8.8.8', '1.1.1.1', '45.33.32.156', '103.21.244.0']

function InfoRow({ label, value, mono }) {
  if (!value && value !== false) return null
  return (
    <div className="flex items-start justify-between py-2 border-b border-dark-700 last:border-0">
      <span className="text-xs text-gray-500 uppercase tracking-wider shrink-0 w-36">{label}</span>
      <span className={`text-sm text-gray-200 text-right ${mono ? 'font-mono' : ''}`}>{String(value)}</span>
    </div>
  )
}

function Flag({ code }) {
  if (!code) return null
  const emoji = code.toUpperCase().replace(/./g, c =>
    String.fromCodePoint(c.charCodeAt(0) + 127397)
  )
  return <span className="text-xl">{emoji}</span>
}

export default function IPIntelligence() {
  const [ip, setIp] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleAnalyze() {
    const val = ip.trim()
    if (!val) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeIP(val)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'IP analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-cyber-400" />
          IP <span className="text-cyber-400">Intelligence</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Real-time geolocation, ISP identification, proxy/VPN detection & threat assessment
        </p>
      </div>

      {/* Sample IPs */}
      <div className="flex flex-wrap gap-2">
        <span className="text-xs text-gray-500 self-center">Try:</span>
        {SAMPLE_IPS.map(s => (
          <button key={s} onClick={() => setIp(s)}
            className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 bg-dark-800 text-gray-400 hover:text-cyber-400 hover:border-cyber-800 font-mono transition-colors">
            {s}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="card flex gap-3">
        <input
          value={ip}
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          placeholder="Enter IP address (e.g. 192.168.1.1)"
          className="input-field flex-1 font-mono"
        />
        <button onClick={handleAnalyze} disabled={!ip.trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40 shrink-0">
          <Search className="w-4 h-4" />
          Analyze
        </button>
      </div>

      {loading && <LoadingSpinner message="Querying IP intelligence feeds…" />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Header summary */}
          <div className="card flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-4">
              <Flag code={result.geolocation?.country_code} />
              <div>
                <p className="text-xl font-bold font-mono text-white">{result.ip}</p>
                <p className="text-sm text-gray-400">
                  {[result.geolocation?.city, result.geolocation?.region, result.geolocation?.country].filter(Boolean).join(', ')}
                </p>
              </div>
            </div>
            <RiskBadge level={result.risk?.level} score={result.risk?.score} />
          </div>

          {/* Risk flags */}
          {result.risk?.flags?.length > 0 && (
            <div className="card border-orange-800 bg-orange-900/10 space-y-2">
              <p className="text-xs font-bold text-orange-400 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" /> Threat Indicators
              </p>
              {result.risk.flags.map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-sm text-orange-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" />
                  {f}
                </div>
              ))}
            </div>
          )}

          {result.risk?.flags?.length === 0 && (
            <div className="card border-green-800 bg-green-900/10 flex items-center gap-3 text-green-400 text-sm">
              <ShieldCheck className="w-5 h-5 shrink-0" />
              No threat indicators detected — appears to be a clean residential IP
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Geolocation */}
            <div className="card space-y-0">
              <p className="text-xs font-bold text-cyber-400 uppercase tracking-wider flex items-center gap-2 mb-3">
                <MapPin className="w-4 h-4" /> Geolocation
              </p>
              <InfoRow label="Country"   value={`${result.geolocation?.country} (${result.geolocation?.country_code})`} />
              <InfoRow label="Region"    value={result.geolocation?.region} />
              <InfoRow label="City"      value={result.geolocation?.city} />
              <InfoRow label="ZIP"       value={result.geolocation?.zip} mono />
              <InfoRow label="Timezone"  value={result.geolocation?.timezone} mono />
              <InfoRow label="Currency"  value={result.geolocation?.currency} mono />
              <InfoRow label="Latitude"  value={result.geolocation?.latitude} mono />
              <InfoRow label="Longitude" value={result.geolocation?.longitude} mono />
            </div>

            {/* Network */}
            <div className="card space-y-0">
              <p className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center gap-2 mb-3">
                <Server className="w-4 h-4" /> Network Info
              </p>
              <InfoRow label="ISP"         value={result.network?.isp} />
              <InfoRow label="Org"         value={result.network?.org} />
              <InfoRow label="ASN"         value={result.network?.asn} mono />
              <InfoRow label="ASN Name"    value={result.network?.asn_name} />
              <InfoRow label="Reverse DNS" value={result.network?.reverse_dns} mono />
              <InfoRow label="Is Proxy"    value={result.network?.is_proxy ? '⚠ YES' : 'No'} />
              <InfoRow label="Is Hosting"  value={result.network?.is_hosting ? '⚠ YES' : 'No'} />
              <InfoRow label="Is Mobile"   value={result.network?.is_mobile ? 'Yes' : 'No'} />
              <InfoRow label="Indian ISP"  value={result.network?.is_indian_isp ? '🇮🇳 Yes' : 'No'} />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
