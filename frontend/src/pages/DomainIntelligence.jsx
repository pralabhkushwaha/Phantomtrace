import { useState } from 'react'
import { Globe2, Search, Shield, AlertTriangle, CheckCircle, Server, Lock, Lock as LockIcon, Calendar, Globe, Database } from 'lucide-react'
import { RiskBadge, LoadingSpinner } from '../components/UI'
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || ''

async function analyzeDomain(domain) {
  const { data } = await axios.post(`${BASE_URL}/api/domain/analyze`, { domain })
  return data
}

const SAMPLES = [
  'google.com', 'sbi.co.in', 'phishing-sbi-kyc.xyz', 'hdfc-kyc-update.tk', 'paytm.com'
]

function InfoRow({ label, value, mono, highlight }) {
  if (!value && value !== false && value !== 0) return null
  return (
    <div className="flex items-start justify-between py-2 border-b border-dark-700 last:border-0 gap-4">
      <span className="text-xs text-gray-500 uppercase tracking-wider shrink-0 w-32">{label}</span>
      <span className={`text-sm text-right break-all ${mono ? 'font-mono' : ''} ${highlight ? 'text-cyber-300' : 'text-gray-300'}`}>
        {String(value)}
      </span>
    </div>
  )
}

function SourceBadge({ verdict }) {
  const map = {
    Clean: 'bg-green-900/40 text-green-300 border-green-800',
    Low: 'bg-green-900/40 text-green-300 border-green-800',
    Suspicious: 'bg-yellow-900/40 text-yellow-300 border-yellow-800',
    Medium: 'bg-yellow-900/40 text-yellow-300 border-yellow-800',
    Malicious: 'bg-red-900/40 text-red-300 border-red-800',
    Critical: 'bg-red-900/40 text-red-300 border-red-800',
    High: 'bg-orange-900/40 text-orange-300 border-orange-800',
    Info: 'bg-blue-900/40 text-blue-300 border-blue-800',
    Unknown: 'bg-dark-700 text-gray-400 border-dark-600',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${map[verdict] || map.Unknown}`}>
      {verdict}
    </span>
  )
}

export default function DomainIntelligence() {
  const [domain, setDomain] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleAnalyze() {
    const val = domain.trim()
    if (!val) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeDomain(val)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Domain analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  const risk = result?.risk

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe2 className="w-6 h-6 text-cyber-400" />
          Domain <span className="text-cyber-400">Intelligence</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          WHOIS/RDAP registration, DNS records, SSL certificate, Shodan port data & risk scoring
        </p>
      </div>

      {/* Samples */}
      <div className="flex flex-wrap gap-2">
        <span className="text-xs text-gray-500 self-center">Try:</span>
        {SAMPLES.map(s => (
          <button key={s} onClick={() => setDomain(s)}
            className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 bg-dark-800 text-gray-400 hover:text-cyber-400 hover:border-cyber-800 font-mono transition-colors">
            {s}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="card flex gap-3">
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          placeholder="Enter domain (e.g. sbi-kyc.xyz or https://phishing.site/login)"
          className="input-field flex-1 font-mono"
        />
        <button onClick={handleAnalyze} disabled={!domain.trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40 shrink-0">
          <Search className="w-4 h-4" />
          Analyze
        </button>
      </div>

      {loading && <LoadingSpinner message="Querying WHOIS, DNS, SSL & Shodan intelligence…" />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm p-4">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Header */}
          <div className="card flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-dark-800 border border-dark-600 flex items-center justify-center">
                <Globe2 className="w-5 h-5 text-cyber-400" />
              </div>
              <div>
                <p className="text-xl font-bold font-mono text-white">{result.domain}</p>
                <p className="text-sm text-gray-400">
                  {result.rdap?.registrar || result.whoisxml?.registrar || 'Registrar unknown'}
                </p>
              </div>
            </div>
            <RiskBadge level={risk?.level} score={risk?.score} />
          </div>

          {/* Risk flags */}
          {risk?.flags?.length > 0 && (
            <div className="card border-red-900/40 bg-red-950/10">
              <h3 className="text-sm font-semibold text-red-400 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> Risk Indicators ({risk.flags.length})
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

          <div className="grid md:grid-cols-2 gap-4">
            {/* WHOIS Registration */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <Calendar className="w-4 h-4 text-cyber-400" /> Registration Info
              </h3>
              {(result.whoisxml?.available || result.rdap) ? (
                <>
                  <InfoRow label="Domain"      value={result.domain} mono highlight />
                  <InfoRow label="Registrar"   value={result.whoisxml?.registrar || result.rdap?.registrar} />
                  <InfoRow label="Created"     value={result.whoisxml?.created || result.rdap?.registered} />
                  <InfoRow label="Expires"     value={result.whoisxml?.expires || result.rdap?.expires} />
                  <InfoRow label="Updated"     value={result.whoisxml?.updated} />
                  <InfoRow label="Domain Age"  value={
                    (result.whoisxml?.age_days || result.rdap?.age_days) != null
                      ? `${result.whoisxml?.age_days ?? result.rdap?.age_days} days`
                      : null
                  } />
                  <InfoRow label="Status"      value={result.whoisxml?.status || result.rdap?.status} />
                  <InfoRow label="Registrant"  value={result.whoisxml?.registrant_org || result.whoisxml?.registrant_name} />
                  <InfoRow label="Country"     value={result.whoisxml?.registrant_country} />
                  <InfoRow label="Privacy"     value={result.whoisxml?.privacy_protected ? 'Protected' : 'Public'} />
                  {result.whoisxml?.name_servers?.length > 0 && (
                    <div className="pt-2">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Name Servers</p>
                      {result.whoisxml.name_servers.map((ns, i) => (
                        <p key={i} className="text-xs font-mono text-gray-400">{ns}</p>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-gray-500">WHOIS data unavailable. Add WHOISXML_API_KEY to .env for full data.</p>
              )}
            </div>

            {/* SSL Certificate */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <LockIcon className="w-4 h-4 text-cyber-400" /> SSL Certificate
              </h3>
              {result.ssl?.available ? (
                <>
                  <InfoRow label="Subject"       value={result.ssl.subject} mono />
                  <InfoRow label="Issuer"        value={result.ssl.issuer} />
                  <InfoRow label="Issuer CN"     value={result.ssl.issuer_cn} mono />
                  <InfoRow label="Valid From"    value={result.ssl.valid_from} />
                  <InfoRow label="Valid Until"   value={result.ssl.valid_until} />
                  <InfoRow label="Days Left"     value={result.ssl.days_remaining != null ? `${result.ssl.days_remaining} days` : null} highlight />
                  <InfoRow label="Self-Signed"   value={result.ssl.self_signed ? 'YES — Untrusted' : 'No'} />
                  <InfoRow label="Expired"       value={result.ssl.expired ? 'YES — Expired' : 'No'} />
                  {result.ssl.sans?.length > 0 && (
                    <div className="pt-2">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">SANs ({result.ssl.sans.length})</p>
                      {result.ssl.sans.slice(0, 5).map((s, i) => (
                        <p key={i} className="text-xs font-mono text-gray-400">{s}</p>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="flex items-center gap-2 text-sm text-yellow-400">
                  <AlertTriangle className="w-4 h-4" />
                  {result.ssl?.error || 'No SSL certificate found'}
                </div>
              )}
            </div>

            {/* DNS Records */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <Globe className="w-4 h-4 text-cyber-400" /> DNS Records
              </h3>
              {['A', 'MX', 'NS', 'TXT'].map(rtype => (
                result.dns?.[rtype]?.length > 0 && (
                  <div key={rtype} className="mb-3">
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{rtype} Records</p>
                    {result.dns[rtype].slice(0, 5).map((rec, i) => (
                      <p key={i} className="text-xs font-mono text-gray-300 break-all">{rec}</p>
                    ))}
                  </div>
                )
              ))}
              {Object.values(result.dns || {}).every(v => v.length === 0) && (
                <p className="text-sm text-gray-500">No DNS records found</p>
              )}
            </div>

            {/* Shodan */}
            <div className="card">
              <h3 className="section-title flex items-center gap-2 mb-3">
                <Server className="w-4 h-4 text-cyber-400" /> Shodan Intelligence
              </h3>
              {!result.shodan?.available ? (
                <p className="text-sm text-gray-500">Add SHODAN_API_KEY to .env to enable Shodan port/vulnerability scanning.</p>
              ) : !result.shodan?.found ? (
                <div className="flex items-center gap-2 text-sm text-green-400">
                  <CheckCircle className="w-4 h-4" /> Not indexed in Shodan
                </div>
              ) : (
                <>
                  <InfoRow label="IP"          value={result.shodan.ip} mono />
                  <InfoRow label="Country"     value={result.shodan.country} />
                  <InfoRow label="City"        value={result.shodan.city} />
                  <InfoRow label="ISP"         value={result.shodan.isp} />
                  <InfoRow label="OS"          value={result.shodan.os} />
                  <InfoRow label="Last Update" value={result.shodan.last_update} />
                  {result.shodan.open_ports?.length > 0 && (
                    <div className="pt-2">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Open Ports ({result.shodan.open_ports.length})</p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.shodan.open_ports.map(p => (
                          <span key={p} className={`text-xs font-mono px-2 py-0.5 rounded border ${
                            [21,22,23,25,445,3389].includes(p)
                              ? 'border-red-800 bg-red-950/30 text-red-300'
                              : 'border-dark-600 bg-dark-800 text-gray-400'
                          }`}>{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.shodan.vulns?.length > 0 && (
                    <div className="pt-2">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">CVEs ({result.shodan.vulns.length})</p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.shodan.vulns.map(v => (
                          <span key={v} className="text-xs font-mono px-2 py-0.5 rounded border border-red-800 bg-red-950/30 text-red-300">{v}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
