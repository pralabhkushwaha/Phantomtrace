import { useState } from 'react'
import { Flag, AlertTriangle, CheckCircle, Search, ChevronDown, ChevronUp } from 'lucide-react'
import { analyzeIndianScam } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

const INDIA_CATS = [
  'digital_arrest_scam','upi_fraud','banking_scam','sim_swap_fraud',
  'loan_app_harassment','olx_quickr_scam','apk_scam','investment_scam',
  'otp_request','credential_theft','fear','urgency','reward',
]

const CAT_COLOR = {
  digital_arrest_scam: 'text-red-400 border-red-800 bg-red-900/20',
  upi_fraud:           'text-orange-400 border-orange-800 bg-orange-900/20',
  banking_scam:        'text-yellow-400 border-yellow-800 bg-yellow-900/20',
  sim_swap_fraud:      'text-pink-400 border-pink-800 bg-pink-900/20',
  loan_app_harassment: 'text-purple-400 border-purple-800 bg-purple-900/20',
  olx_quickr_scam:     'text-cyan-400 border-cyan-800 bg-cyan-900/20',
  apk_scam:            'text-red-300 border-red-900 bg-red-950/30',
  investment_scam:     'text-emerald-400 border-emerald-800 bg-emerald-900/20',
  otp_request:         'text-amber-400 border-amber-800 bg-amber-900/20',
  credential_theft:    'text-rose-400 border-rose-800 bg-rose-900/20',
  fear:                'text-red-400 border-red-800 bg-red-900/20',
  urgency:             'text-orange-300 border-orange-900 bg-orange-950/20',
  reward:              'text-green-400 border-green-800 bg-green-900/20',
}

const SAMPLES = [
  {
    label: 'Digital Arrest Scam',
    text: 'This is CBI officer speaking. Your Aadhaar is linked to money laundering case. You are under digital arrest. Stay on call, do not tell anyone. Interpol has issued a warrant against you.',
  },
  {
    label: 'UPI Fraud',
    text: 'Congratulations! You have won Rs 50,000 cashback. Enter your UPI PIN to receive the refund. Scan QR code and enter PIN to get money.',
  },
  {
    label: 'KYC Expiry Fraud',
    text: 'Your SBI account has been blocked due to KYC expiry. Update your KYC immediately or your account will be permanently suspended. Click here to verify your Aadhaar and PAN card.',
  },
  {
    label: 'Loan App Harassment',
    text: 'Your EMI is overdue. Recovery agent will visit. We have access to your contact list and gallery. Pay now or we will inform your contacts and family.',
  },
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
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Scan failed.')
    } finally {
      setLoading(false)
    }
  }

  function toggleExpand(cat) {
    setExpanded(prev => ({ ...prev, [cat]: !prev[cat] }))
  }

  const detectedCats = result
    ? INDIA_CATS.filter(c => result.categories?.[c]?.matched)
    : []

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Flag className="w-6 h-6 text-orange-400" />
          Indian <span className="text-orange-400">Scam Scanner</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          UP Police Cyber Cell — detect Indian-specific fraud patterns in SMS, email, or chat messages
        </p>
      </div>

      {/* Sample buttons */}
      <div className="flex flex-wrap gap-2">
        {SAMPLES.map(s => (
          <button key={s.label} onClick={() => { setText(s.text); setSubject('') }}
            className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 bg-dark-800 text-gray-400 hover:text-white hover:border-orange-700 transition-colors">
            Try: {s.label}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="card space-y-3">
        <input
          value={subject}
          onChange={e => setSubject(e.target.value)}
          placeholder="Subject / SMS sender (optional)"
          className="input-field w-full"
        />
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={6}
          placeholder="Paste the suspicious SMS, email, WhatsApp message, or chat content here…"
          className="input-field w-full resize-none font-mono text-sm"
        />
        <button
          onClick={handleScan}
          disabled={!text.trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40"
        >
          <Search className="w-4 h-4" />
          {loading ? 'Scanning…' : 'Scan for Indian Scam Patterns'}
        </button>
      </div>

      {loading && <LoadingSpinner message="Analyzing for UP Police priority fraud patterns…" />}
      {error && (
        <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm">{error}</div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Risk summary */}
          <div className="card flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Overall Risk Assessment</p>
              <RiskBadge level={result.risk_level} score={result.overall_risk_score} />
            </div>
            <div className="text-right">
              <p className="text-xs text-gray-500 mb-1">Patterns Matched</p>
              <p className="text-2xl font-bold font-mono text-orange-400">{detectedCats.length}</p>
            </div>
          </div>

          {/* Detected patterns */}
          {detectedCats.length > 0 && (
            <div>
              <h2 className="section-title">Detected Fraud Patterns</h2>
              <div className="space-y-2">
                {detectedCats.map(cat => {
                  const c = result.categories[cat]
                  const colorClass = CAT_COLOR[cat] || 'text-gray-400 border-dark-600 bg-dark-800'
                  const isOpen = expanded[cat]
                  return (
                    <div key={cat} className={`card border ${colorClass} p-0 overflow-hidden`}>
                      <button
                        onClick={() => toggleExpand(cat)}
                        className="w-full flex items-center justify-between px-4 py-3 text-left"
                      >
                        <div className="flex items-center gap-3">
                          <AlertTriangle className="w-4 h-4 shrink-0" />
                          <span className="text-sm font-semibold">{c.label}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-mono font-bold">Score: {c.score}</span>
                          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </button>
                      {isOpen && c.matches?.length > 0 && (
                        <div className="border-t border-current/20 px-4 py-3">
                          <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Matched Evidence</p>
                          <div className="flex flex-wrap gap-2">
                            {c.matches.map((m, i) => (
                              <span key={i} className="text-xs font-mono px-2 py-1 rounded bg-black/30 border border-current/30">
                                "{m}"
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Clean result */}
          {detectedCats.length === 0 && (
            <div className="card text-center py-10">
              <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-3" />
              <p className="text-gray-300 font-medium">No Indian scam patterns detected</p>
              <p className="text-gray-500 text-sm mt-1">Message appears clean against UP Police fraud pattern database</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
