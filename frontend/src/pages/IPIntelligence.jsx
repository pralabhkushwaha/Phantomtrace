import { useState } from 'react'
import { Globe, Search, MapPin, Wifi, ShieldAlert, ShieldCheck, Server, AlertTriangle, Database } from 'lucide-react'
import { analyzeIP } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const SAMPLE_IPS = ['8.8.8.8', '1.1.1.1', '45.33.32.156', '103.21.244.0', '194.165.16.11']

function InfoRow({ label, value, mono }) {
  if (!value && value !== false && value !== 0) return null
  return (
    <div className="flex items-start justify-between py-2 border-b border-dark-700 last:border-0 gap-3">
      <span className="text-xs text-gray-500 uppercase tracking-wider shrink-0 w-32">{label}</span>
      <span className={`text-sm text-gray-200 text-right break-all ${mono ? 'font-mono' : ''}`}>{String(value)}</span>
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

function VerdictBadge({ verdict }) {
  const map = {
    Malicious:  'bg-red-900/40 text-red-300 border-red-800',
    Suspicious: 'bg-yellow-900/40 text-yellow-300 border-yellow-800',
    Clean:      'bg-green-900/40 text-green-300 border-green-800',
    Info:       'bg-blue-900/40 text-blue-300 border-blue-800',
    Unknown:    'bg-dark-700 text-gray-400 border-dark-600',
  }
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${map[verdict] || map.Unknown}`}>
      {verdict}
    </span>
  )
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

  const geo = result?.geolocation
  const net = result?.network
  const ti  = result?.threat_intel
  const risk = result?.risk

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-cyber-400" />
          IP <span className="text-cyber-400">Intelligence</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Real-time geolocation, ISP, proxy/VPN detection, AbuseIPDB, AlienVault OTX & Shodan enrichment
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

      {loading && <LoadingSpinner message="Querying AbuseIPDB, OTX, Shodan & geolocation feeds…" />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm p-4">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Header */}
          <div className="card flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-4">
              <Flag code={geo?.country_code} />
              <div>
                <p className="text-xl font-bold font-mono text-white">{result.ip}</p>
                <p className="text-sm text-gray-400">
                  {[geo?.city, geo?.region, geo?.country].filter(Boolean).join(', ')}
                </p>
              </div>
            </div>
            <RiskBadge level={risk?.level} score={risk?.score} />
          </div>

          {/* Risk flags */}
          {risk?.flags?.length > 0 && (
            <div className="card border-red-900/40 bg-red-950/10">
              <h3 className="text-sm font-semibold text-red-400 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Risk Indicators
              </h3>
              <div className="space-y-1.5">
                {risk.flags.map((f, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm text-red-300">
                    <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-red-500" />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Threat Intel Sources */}
          {ti?.sources?.length > 0 && (
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <Database className="w-4 h-4 text-cyber-400" /> Threat Intelligence Sources
              </h3>
              <div className="space-y-2">
                {ti.sources.map((s, i) => (
                  <div key={i} className="flex items-center justify-between py-2 border-b border-dark-700 last:border-0">
                    <div>
                      <span className="text-sm text-gray-200">{s.source}</span>
                      {s.detail && <span className="text-xs text-gray-500 ml-2">{s.detail}</span>}
                    </div>
                    <VerdictBadge verdict={s.verdict} />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-4">
            {/* Geolocation */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <MapPin className="w-4 h-4 text-cyber-400" /> Geolocation
              </h3>
              <InfoRow label="Country"   value={geo?.country} />
              <InfoRow label="Region"    value={geo?.region} />
              <InfoRow label="City"      value={geo?.city} />
              <InfoRow label="District"  value={geo?.district} />
              <InfoRow label="ZIP"       value={geo?.zip} />
              <InfoRow label="Latitude"  value={geo?.latitude} mono />
              <InfoRow label="Longitude" value={geo?.longitude} mono />
              <InfoRow label="Timezone"  value={geo?.timezone} />
              <InfoRow label="Currency"  value={geo?.currency} />
            </div>

            {/* Network */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <Wifi className="w-4 h-4 text-cyber-400" /> Network Info
              </h3>
              <InfoRow label="ISP"          value={net?.isp} />
              <InfoRow label="Organization" value={net?.org} />
              <InfoRow label="ASN"          value={net?.asn} mono />
              <InfoRow label="ASN Name"     value={net?.asn_name} />
              <InfoRow label="Reverse DNS"  value={net?.reverse_dns} mono />
              <InfoRow label="Mobile"       value={net?.is_mobile ? 'Yes' : 'No'} />
              <InfoRow label="Proxy/VPN"    value={net?.is_proxy ? '⚠ Yes' : 'No'} />
              <InfoRow label="Datacenter"   value={net?.is_hosting ? '⚠ Yes' : 'No'} />
              <InfoRow label="Indian ISP"   value={net?.is_indian_isp ? 'Yes' : 'No'} />
            </div>

            {/* AbuseIPDB */}
            {ti?.abuseipdb?.available && (
              <div className="card">
                <h3 className="section-title flex items-center gap-2 mb-3">
                  <ShieldAlert className="w-4 h-4 text-red-400" /> AbuseIPDB
                </h3>
                <InfoRow label="Abuse Score"   value={`${ti.abuseipdb.abuse_confidence_score}%`} mono />
                <InfoRow label="Total Reports" value={ti.abuseipdb.total_reports} mono />
                <InfoRow label="Distinct Users" value={ti.abuseipdb.num_distinct_users} mono />
                <InfoRow label="Last Reported" value={ti.abuseipdb.last_reported} />
                <InfoRow label="Usage Type"    value={ti.abuseipdb.usage_type} />
                <InfoRow label="ISP"           value={ti.abuseipdb.isp} />
                <InfoRow label="Domain"        value={ti.abuseipdb.domain} mono />
                <InfoRow label="Whitelisted"   value={ti.abuseipdb.is_whitelisted ? 'Yes' : 'No'} />
                <div className="mt-3">
                  <VerdictBadge verdict={ti.abuseipdb.verdict} />
                </div>
              </div>
            )}

            {/* AlienVault OTX */}
            {ti?.alienvault_otx?.available && (
              <div className="card">
                <h3 className="section-title flex items-center gap-2 mb-3">
                  <ShieldCheck className="w-4 h-4 text-purple-400" /> AlienVault OTX
                </h3>
                <InfoRow label="Threat Pulses" value={ti.alienvault_otx.pulse_count} mono />
                <InfoRow label="Reputation"    value={ti.alienvault_otx.reputation} mono />
                <InfoRow label="Country"       value={ti.alienvault_otx.country} />
                <InfoRow label="ASN"           value={ti.alienvault_otx.asn} mono />
                {ti.alienvault_otx.tags?.length > 0 && (
                  <div className="pt-2">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Threat Tags</p>
                    <div className="flex flex-wrap gap-1.5">
                      {ti.alienvault_otx.tags.map((t, i) => (
                        <span key={i} className="text-xs px-2 py-0.5 rounded border border-purple-900 bg-purple-950/30 text-purple-300 font-mono">{t}</span>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mt-3">
                  <VerdictBadge verdict={ti.alienvault_otx.verdict} />
                </div>
              </div>
            )}

            {/* Shodan */}
            {ti?.shodan?.available && ti?.shodan?.found && (
              <div className="card md:col-span-2">
                <h3 className="section-title flex items-center gap-2 mb-3">
                  <Server className="w-4 h-4 text-orange-400" /> Shodan Port & Vulnerability Data
                </h3>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <InfoRow label="OS"          value={ti.shodan.os} />
                    <InfoRow label="Country"     value={ti.shodan.city ? `${ti.shodan.city}, ${ti.shodan.country}` : ti.shodan.country} />
                    <InfoRow label="ISP"         value={ti.shodan.isp} />
                    <InfoRow label="Org"         value={ti.shodan.org} />
                    <InfoRow label="Last Update" value={ti.shodan.last_update} />
                    {ti.shodan.hostnames?.length > 0 && (
                      <div className="pt-2">
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Hostnames</p>
                        {ti.shodan.hostnames.map((h, i) => (
                          <p key={i} className="text-xs font-mono text-gray-400">{h}</p>
                        ))}
                      </div>
                    )}
                  </div>
                  <div>
                    {ti.shodan.open_ports?.length > 0 && (
                      <div className="mb-3">
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Open Ports ({ti.shodan.open_ports.length})</p>
                        <div className="flex flex-wrap gap-1.5">
                          {ti.shodan.open_ports.map(p => (
                            <span key={p} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                              [21,22,23,25,445,1433,3306,3389,5432,6379,27017].includes(p)
                                ? 'border-red-800 bg-red-950/30 text-red-300'
                                : 'border-dark-600 bg-dark-800 text-gray-400'
                            }`}>{p}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {ti.shodan.vulns?.length > 0 && (
                      <div>
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">CVEs ({ti.shodan.vulns.length})</p>
                        <div className="flex flex-wrap gap-1.5">
                          {ti.shodan.vulns.map(v => (
                            <span key={v} className="text-xs font-mono px-2 py-0.5 rounded border border-red-800 bg-red-950/30 text-red-300">{v}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {ti.shodan.services?.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Services</p>
                        {ti.shodan.services.slice(0, 6).map((svc, i) => (
                          <div key={i} className="text-xs font-mono text-gray-400 flex gap-2">
                            <span className="text-cyber-500 w-6 text-right shrink-0">{svc.port}</span>
                            <span>{svc.product} {svc.version}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Shodan — not found or no key */}
            {ti?.shodan?.available && !ti?.shodan?.found && (
              <div className="card">
                <h3 className="section-title flex items-center gap-2 mb-3">
                  <Server className="w-4 h-4 text-orange-400" /> Shodan
                </h3>
                <div className="flex items-center gap-2 text-sm text-green-400">
                  <ShieldCheck className="w-4 h-4" /> IP not indexed in Shodan
                </div>
              </div>
            )}
            {!ti?.shodan?.available && (
              <div className="card">
                <h3 className="section-title flex items-center gap-2 mb-3">
                  <Server className="w-4 h-4 text-gray-600" /> Shodan
                </h3>
                <p className="text-sm text-gray-500">Add SHODAN_API_KEY to .env to enable port & vulnerability scanning.</p>
              </div>
            )}

            {/* OTX / AbuseIPDB not configured */}
            {!ti?.abuseipdb?.available && !ti?.alienvault_otx?.available && (
              <div className="card md:col-span-2 border-dashed border-dark-600">
                <p className="text-sm text-gray-500 text-center py-2">
                  Add <code className="text-cyber-400 font-mono">ABUSEIPDB_API_KEY</code> and <code className="text-cyber-400 font-mono">OTX_API_KEY</code> to your .env for full threat intelligence enrichment.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
