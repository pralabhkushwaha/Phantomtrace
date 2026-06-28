import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Globe2, Link2, FileSearch, ShieldCheck, AlertTriangle,
  ArrowRight, Activity, TrendingUp, Database, Plug, Flag,
  Phone, Languages, FolderOpen, Search, Settings, CheckCircle2, Clock,
} from 'lucide-react'
import { getHistory } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const QUICK_LINKS = [
  { to: '/email',     icon: Mail,       label: 'Email Forensics',    desc: 'Upload .eml or paste raw headers' },
  { to: '/homograph', icon: Globe2,     label: 'Homograph Detector', desc: 'Detect brand impersonation domains' },
  { to: '/url',       icon: Link2,      label: 'URL Intelligence',   desc: 'Analyze suspicious links' },
  { to: '/fraud',     icon: FileSearch, label: 'Fraud Detection',    desc: 'Scan email body for scam patterns' },
]

const ROADMAP = [
  {
    icon: Plug,
    label: 'External API Integrations',
    status: 'planned',
    color: 'text-cyber-400',
    border: 'border-cyber-800',
    bg: 'bg-cyber-900/30',
    items: [
      'VirusTotal — URL, hash & domain reputation',
      'WhoisXML / WHOIS — domain registration details',
      'urlscan.io — live URL screenshot & analysis',
      'Shodan — IP/port intelligence',
      'AbuseIPDB — IP reputation check',
      'Google Safe Browsing — URL blocklist',
      'AlienVault OTX — threat intelligence feeds',
    ],
  },
  {
    icon: Flag,
    label: 'Indian-Focused Scam Patterns',
    status: 'planned',
    color: 'text-orange-400',
    border: 'border-orange-800',
    bg: 'bg-orange-900/20',
    items: [
      'OLX / Quickr scams',
      'UPI fraud patterns (GPay, PhonePe, Paytm)',
      'WhatsApp APK scam (Indian variants)',
      'SIM swap fraud indicators',
      'Digital arrest scams (UP Police priority)',
      'Loan app harassment patterns',
      'KYC expiry fraud (Indian bank formats)',
    ],
  },
  {
    icon: Phone,
    label: 'Phone Number / UPI ID OSINT',
    status: 'planned',
    color: 'text-yellow-400',
    border: 'border-yellow-800',
    bg: 'bg-yellow-900/20',
    items: [
      'UPI ID linked account intelligence',
      'Phone number OSINT (Truecaller-style spam lists)',
      'WhatsApp number validation',
    ],
  },
  {
    icon: Languages,
    label: 'Indian Language Support',
    status: 'planned',
    color: 'text-purple-400',
    border: 'border-purple-800',
    bg: 'bg-purple-900/20',
    items: [
      'Hindi scam pattern detection',
      'Hindi fraud email template analysis',
      'Regional language phishing detection',
    ],
  },
  {
    icon: FolderOpen,
    label: 'Case Management Enhancements',
    status: 'in-progress',
    color: 'text-green-400',
    border: 'border-green-800',
    bg: 'bg-green-900/20',
    items: [
      'FIR number linking — tie every investigation to FIR',
      'PDF court-admissible report generation',
      'Chain of custody logging',
      'Export to UP Police CCTNS format',
    ],
  },
  {
    icon: Search,
    label: 'Advanced OSINT Modules',
    status: 'planned',
    color: 'text-pink-400',
    border: 'border-pink-800',
    bg: 'bg-pink-900/20',
    items: [
      'Social Media OSINT — Facebook, Instagram, Twitter',
      'Reverse image search — fake document / profile photo detection',
      'IP Geolocation with Indian ISP data',
      'Dark web monitoring — leaked Indian credentials',
    ],
  },
  {
    icon: Settings,
    label: 'Technical Improvements',
    status: 'planned',
    color: 'text-gray-400',
    border: 'border-dark-600',
    bg: 'bg-dark-800/40',
    items: [
      'Backend API upgrade (Node.js / Flask)',
      'SQLite to PostgreSQL migration',
      'Officer login with role-based access control',
      'API rate limiting and audit logging',
      'Multi-user case collaboration',
    ],
  },
]

const STAT_CARDS = (stats) => [
  { icon: Database,      label: 'Investigations', value: stats.total,              color: 'text-cyber-400' },
  { icon: AlertTriangle, label: 'Critical',        value: stats.critical,           color: 'text-red-400' },
  { icon: TrendingUp,    label: 'High Risk',        value: stats.high,               color: 'text-orange-400' },
  { icon: Activity,      label: 'Avg Risk Score',   value: `${stats.avgScore}/100`,  color: 'text-yellow-400' },
]

export default function Dashboard() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getHistory(10)
      .then(setHistory)
      .catch(() => setHistory([]))
      .finally(() => setLoading(false))
  }, [])

  const stats = {
    total: history.length,
    critical: history.filter((h) => h.risk_level === 'Critical').length,
    high: history.filter((h) => h.risk_level === 'High').length,
    avgScore: history.length
      ? Math.round(history.reduce((s, h) => s + h.risk_score, 0) / history.length)
      : 0,
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-fade-in">

      {/* Page title */}
      <div>
        <h1 className="text-2xl font-bold text-white">
          PhantomTrace <span className="text-cyber-400">SOC Dashboard</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Phishing detection, email forensics &amp; fraud intelligence platform — UP Police Cyber Cell
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {STAT_CARDS(stats).map(({ icon: Icon, label, value, color }) => (
          <div key={label} className="card hover:border-dark-600 transition-colors">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
                <p className={`text-2xl font-bold font-mono mt-1 ${color}`}>{value}</p>
              </div>
              <Icon className={`w-6 h-6 ${color} opacity-60`} />
            </div>
          </div>
        ))}
      </div>

      {/* Quick investigation links */}
      <div>
        <h2 className="section-title">Quick Investigation</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {QUICK_LINKS.map(({ to, icon: Icon, label, desc }) => (
            <Link
              key={to}
              to={to}
              className="card hover:card-glow group transition-all duration-200 hover:border-cyber-700 cursor-pointer block"
            >
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-lg bg-cyber-900/60 border border-cyber-800 flex items-center justify-center group-hover:bg-cyber-800/60 transition-colors">
                  <Icon className="w-4 h-4 text-cyber-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-gray-100 group-hover:text-white">{label}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{desc}</p>
                </div>
                <ArrowRight className="w-4 h-4 text-gray-600 group-hover:text-cyber-400 transition-colors shrink-0 mt-0.5" />
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Recent investigations */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="section-title mb-0">Recent Investigations</h2>
          <Link
            to="/history"
            className="text-xs text-cyber-400 hover:text-cyber-300 flex items-center gap-1"
          >
            View all <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {loading ? (
          <LoadingSpinner message="Loading history..." />
        ) : history.length === 0 ? (
          <div className="card text-center py-12">
            <ShieldCheck className="w-10 h-10 text-dark-500 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">No investigations yet.</p>
            <p className="text-gray-500 text-xs mt-1">
              Run your first analysis using one of the modules above.
            </p>
          </div>
        ) : (
          <div className="card overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700">
                  <th className="text-left px-4 py-3 text-xs uppercase tracking-wider text-gray-500">Type</th>
                  <th className="text-left px-4 py-3 text-xs uppercase tracking-wider text-gray-500">Target</th>
                  <th className="text-left px-4 py-3 text-xs uppercase tracking-wider text-gray-500">Risk</th>
                  <th className="text-left px-4 py-3 text-xs uppercase tracking-wider text-gray-500 hidden sm:table-cell">Date</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr
                    key={h.id}
                    className="border-b border-dark-800 last:border-0 hover:bg-dark-800/40 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono bg-dark-800 border border-dark-600 px-2 py-0.5 rounded text-cyber-300 uppercase">
                        {h.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[200px] truncate">
                      {h.summary}
                    </td>
                    <td className="px-4 py-3">
                      <RiskBadge level={h.risk_level} score={h.risk_score} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 hidden sm:table-cell">
                      {h.created_at ? new Date(h.created_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Platform Upgrade Roadmap */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="section-title mb-0">Platform Upgrade Roadmap</h2>
          <span className="text-[10px] font-mono text-dark-400 uppercase tracking-widest">
            UP Police Cyber Cell · Planned Enhancements
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {ROADMAP.map(({ icon: Icon, label, status, color, border, bg, items }) => (
            <div key={label} className={`card border ${border} ${bg} flex flex-col gap-3`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${color}`} />
                  <span className={`text-sm font-semibold ${color}`}>{label}</span>
                </div>
                {status === 'in-progress' ? (
                  <span className="flex items-center gap-1 text-[9px] font-bold uppercase tracking-wider text-green-400 bg-green-900/40 border border-green-800 px-1.5 py-0.5 rounded">
                    <Clock className="w-2.5 h-2.5" /> In Progress
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-[9px] font-bold uppercase tracking-wider text-dark-400 bg-dark-800 border border-dark-600 px-1.5 py-0.5 rounded">
                    <CheckCircle2 className="w-2.5 h-2.5" /> Planned
                  </span>
                )}
              </div>
              <ul className="space-y-1.5">
                {items.map((item) => (
                  <li key={item} className="flex items-start gap-2 text-xs text-gray-400">
                    <span className={`mt-1 w-1 h-1 rounded-full shrink-0 ${color.replace('text-', 'bg-')}`} />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

    </div>
  )
}
