import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, Globe2, Link2, FileSearch, ShieldCheck, AlertTriangle,
  ArrowRight, Activity, TrendingUp, Database,
} from 'lucide-react'
import { getHistory } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const QUICK_LINKS = [
  { to: '/email',     icon: Mail,       label: 'Email Forensics',     desc: 'Upload .eml or paste raw headers' },
  { to: '/homograph', icon: Globe2,     label: 'Homograph Detector',  desc: 'Detect brand impersonation domains' },
  { to: '/url',       icon: Link2,      label: 'URL Intelligence',    desc: 'Analyze suspicious links' },
  { to: '/fraud',     icon: FileSearch, label: 'Fraud Detection',     desc: 'Scan email body for scam patterns' },
]

export default function Dashboard() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getHistory(10).then(setHistory).catch(() => setHistory([])).finally(() => setLoading(false))
  }, [])

  const stats = {
    total: history.length,
    critical: history.filter(h => h.risk_level === 'Critical').length,
    high: history.filter(h => h.risk_level === 'High').length,
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
          Phishing detection, email forensics &amp; fraud intelligence platform
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Database,     label: 'Investigations', value: stats.total,    color: 'text-cyber-400' },
          { icon: AlertTriangle, label: 'Critical',       value: stats.critical, color: 'text-red-400' },
          { icon: TrendingUp,   label: 'High Risk',       value: stats.high,     color: 'text-orange-400' },
          { icon: Activity,     label: 'Avg Risk Score',  value: `${stats.avgScore}/100`, color: 'text-yellow-400' },
        ].map(({ icon: Icon, label, value, color }) => (
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
          <Link to="/history" className="text-xs text-cyber-400 hover:text-cyber-300 flex items-center gap-1">
            View all <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        {loading ? (
          <LoadingSpinner message="Loading history…" />
        ) : history.length === 0 ? (
          <div className="card text-center py-12">
            <ShieldCheck className="w-10 h-10 text-dark-500 mx-auto mb-3" />
            <p className="text-gray-400 text-sm">No investigations yet.</p>
            <p className="text-gray-500 text-xs mt-1">Run your first analysis using one of the modules above.</p>
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
                {history.map((h, i) => (
                  <tr key={h.id} className="border-b border-dark-800 last:border-0 hover:bg-dark-800/40 transition-colors">
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
    </div>
  )
}
