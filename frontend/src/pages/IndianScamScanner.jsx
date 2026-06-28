import { useState } from 'react'
import { Flag, AlertTriangle, CheckCircle, Search, ChevronDown, ChevronUp, Shield, Zap } from 'lucide-react'
import { RiskBadge, LoadingSpinner } from '../components/UI'
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || ''

async function analyzeIndianScam(text, subject = '') {
  const { data } = await axios.post(`${BASE_URL}/api/indian-scam/analyze`, { text, subject })
  return data
}

const SEVERITY_COLORS = {
  critical: 'text-red-400 border-red-800/60 bg-red-950/30',
  high:     'text-orange-400 border-orange-800/60 bg-orange-950/30',
  medium:   'text-yellow-400 border-yellow-800/60 bg-yellow-950/30',
  low:      'text-blue-400 border-blue-800/60 bg-blue-950/30',
}

const SEVERITY_BADGE = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border border-blue-700',
}

const SAMPLES = [
  {
    label: 'Digital Arrest Scam',
    text: 'This is CBI officer speaking. Your Aadhaar is linked to money laundering case. You are under digital arrest. Stay on call, do not tell anyone. Interpol has issued a warrant against you. Your bank account will be frozen.',
  },
  {
    label: 'UPI QR Trick',
    text: 'Congratulations! You have won Rs 50,000 cashback from Amazon. Scan this QR code to receive the refund. Enter your UPI PIN to collect money. Payment request sent on your Google Pay.',
  },
  {
    label: 'KYC Expiry Fraud',
    text: 'URGENT: Your SBI account has been blocked due to KYC expiry. Update your KYC within 24 hours or your account will be permanently suspended. Click here to verify your Aadhaar and PAN card details immediately.',
  },
  {
    label: 'Loan App Harassment',
    text: 'Your EMI of Rs 5,000 is overdue. Recovery agent will visit your home today. We have access to your contact list and gallery. Pay now or we will inform your family, employer and contacts. Legal action will be taken.',
  },
  {
    label: 'OLX Army Scam',
    text: 'I am Indian Army officer. Due to urgent transfer to Ladakh posting I am selling my Royal Enfield at half price. Please send Rs 5,000 advance via Google Pay to book. I will dispatch via courier after advance payment.',
  },
  {
    label: 'Fake Investment',
    text: 'Join our exclusive Telegram group for guaranteed stock market returns. Our SEBI registered advisor gives 100% profit signals. Daily earning of Rs 5,000. Invest just Rs 10,000 and earn Rs 1,00,000 within 30 days.',
  },
  {
    label: 'APK Scam',
    text: 'Download this SBI official app from the link below. Install the APK file to access your account. Enable screen share on AnyDesk so our customer care can verify your KYC. Your account will be blocked if not done immediately.',
  },
  {
    label: 'SIM Swap',
    text: 'This is Airtel customer care. Your SIM card needs urgent upgrade due to TRAI regulation. Your number will be disconnected within 2 hours. Generate OTP on your current SIM and share with us to activate new SIM.',
  },
]

const CATEGORY_ORDER = [
  'digital_arrest_scam', 'otp_phishing', 'upi_fraud', 'whatsapp_apk_scam',
  'kyc_expiry_fraud', 'loan_app_harassment', 'olx_quickr_scam',
  'sim_swap_fraud', 'investment_scam', 'fake_job_task_scam',
  'fear_authority', 'urgency_pressure',
]

export default function IndianScamScanner() {
  const [text, setText] = useState('')
  const [subject, setSubject] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [expanded, setExpanded] = useState({})

  async function handleScan() {
    if (!text.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeIndianScam(text, subject)
      setResult(data)
      // Auto-expand critical hits
      const autoExpand = {}
      CATEGORY_ORDER.forEach(k => {
        if (data.categories?.[k]?.matched && data.categories[k].severity === 'critical') {
          autoExpand[k] = true
        }
      })
      setExpanded(autoExpand)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Scan failed.')
    } finally {
      setLoading(false)
    }
  }

  function toggle(cat) {
    setExpanded(prev => ({ ...prev, [cat]: !prev[cat] }))
  }

  const detectedCats = result
    ? CATEGORY_ORDER.filter(c => result.categories?.[c]?.matched)
    : []

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Flag className="w-6 h-6 text-orange-400" />
          Indian <span className="text-orange-400">Scam Scanner</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          UP Police Cyber Cell — AI-powered detection of 12 India-specific cyber fraud categories in SMS, email, WhatsApp, or call scripts
        </p>
      </div>

      {/* Coverage badges */}
      <div className="flex flex-wrap gap-2">
        {[
          'Digital Arrest', 'UPI Fraud', 'KYC/Banking', 'APK Scam',
          'SIM Swap', 'Loan App', 'OLX Scam', 'Investment Fraud',
          'OTP Phishing', 'Fake Job', 'Fear Tactics', 'Urgency Pressure',
        ].map(tag => (
          <span key={tag} className="text-[10px] px-2 py-1 rounded-full border border-orange-900/50 bg-orange-950/20 text-orange-400 font-mono">
            {tag}
          </span>
        ))}
      </div>

      {/* Sample buttons */}
      <div>
        <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Quick Test Samples</p>
        <div className="flex flex-wrap gap-2">
          {SAMPLES.map(s => (
            <button key={s.label}
              onClick={() => { setText(s.text); setSubject('') }}
              className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 bg-dark-800 text-gray-400 hover:text-orange-300 hover:border-orange-800 transition-colors">
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="card space-y-3">
        <input
          value={subject}
          onChange={e => setSubject(e.target.value)}
          placeholder="Subject / SMS sender ID / Caller ID (optional)"
          className="input-field w-full"
        />
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={7}
          placeholder="Paste suspicious SMS, email body, WhatsApp message, call transcript, or any text here…"
          className="input-field w-full resize-none font-mono text-sm"
        />
        <div className="flex items-center gap-3">
          <button
            onClick={handleScan}
            disabled={!text.trim() || loading}
            className="btn-primary flex items-center gap-2 disabled:opacity-40">
            <Search className="w-4 h-4" />
            {loading ? 'Scanning…' : 'Detect Scam Patterns'}
          </button>
          {text && (
            <button onClick={() => { setText(''); setSubject(''); setResult(null); setError(null) }}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors">
              Clear
            </button>
          )}
          <span className="text-xs text-gray-600 ml-auto">{text.length} chars</span>
        </div>
      </div>

      {loading && <LoadingSpinner message="Analyzing against UP Police Cyber Cell fraud pattern database…" />}
      {error && (
        <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm p-4">{error}</div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Risk summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Overall Risk</p>
              <RiskBadge level={result.risk_level} score={result.overall_risk_score} />
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Categories Hit</p>
              <p className="text-3xl font-bold font-mono text-orange-400">{result.total_detected}</p>
              <p className="text-xs text-gray-600">of 12 scanned</p>
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Critical</p>
              <p className={`text-3xl font-bold font-mono ${result.critical_count > 0 ? 'text-red-400' : 'text-gray-600'}`}>
                {result.critical_count}
              </p>
              <p className="text-xs text-gray-600">high-severity hits</p>
            </div>
            <div className="card text-center py-4">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Score</p>
              <p className="text-3xl font-bold font-mono text-cyber-400">{result.overall_risk_score}</p>
              <p className="text-xs text-gray-600">out of 100</p>
            </div>
          </div>

          {/* Detected patterns */}
          {detectedCats.length > 0 ? (
            <div>
              <h2 className="section-title flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Detected Fraud Patterns ({detectedCats.length})
              </h2>
              <div className="space-y-2">
                {detectedCats.map(cat => {
                  const c = result.categories[cat]
                  const colorClass = SEVERITY_COLORS[c.severity] || SEVERITY_COLORS.low
                  const badgeClass = SEVERITY_BADGE[c.severity] || SEVERITY_BADGE.low
                  const isOpen = expanded[cat]
                  return (
                    <div key={cat} className={`rounded-xl border ${colorClass} overflow-hidden`}>
                      <button
                        onClick={() => toggle(cat)}
                        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-white/5 transition-colors">
                        <div className="flex items-center gap-3 min-w-0">
                          <AlertTriangle className="w-4 h-4 shrink-0" />
                          <div className="min-w-0">
                            <span className="text-sm font-semibold block">{c.label}</span>
                            <span className="text-xs opacity-60 block truncate">{c.description}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0 ml-3">
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${badgeClass}`}>
                            {c.severity}
                          </span>
                          <span className="text-xs font-mono font-bold opacity-80">+{c.score}</span>
                          {isOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        </div>
                      </button>
                      {isOpen && (
                        <div className="border-t border-current/20 px-4 py-3 bg-black/20">
                          <p className="text-[10px] text-gray-500 mb-2 uppercase tracking-wider">Matched Evidence</p>
                          <div className="space-y-1">
                            {c.matches.map((m, i) => (
                              <div key={i} className="flex items-start gap-2">
                                <Zap className="w-3 h-3 shrink-0 mt-0.5 opacity-60" />
                                <span className="text-xs font-mono opacity-80">{m}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ) : (
            <div className="card text-center py-12">
              <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3" />
              <p className="text-gray-200 font-semibold text-lg">No Scam Patterns Detected</p>
              <p className="text-gray-500 text-sm mt-1">
                Message appears clean against the UP Police Cyber Cell fraud pattern database
              </p>
            </div>
          )}

          {/* All categories status */}
          <div>
            <h2 className="section-title flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyber-400" />
              All 12 Fraud Categories — Scan Status
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {CATEGORY_ORDER.map(cat => {
                const c = result.categories?.[cat]
                if (!c) return null
                return (
                  <div key={cat}
                    className={`flex items-center gap-3 px-3 py-2 rounded-lg border text-sm ${
                      c.matched
                        ? `${SEVERITY_COLORS[c.severity]} border-opacity-60`
                        : 'border-dark-700 bg-dark-800/50 text-gray-600'
                    }`}>
                    {c.matched
                      ? <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      : <CheckCircle className="w-3.5 h-3.5 shrink-0 text-green-700" />}
                    <span className={c.matched ? 'font-medium' : ''}>{c.label}</span>
                    {c.matched && (
                      <span className={`text-[9px] px-1.5 py-0.5 rounded ml-auto font-bold uppercase ${SEVERITY_BADGE[c.severity]}`}>
                        {c.severity}
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
