import { useState } from 'react'
import { FileSearch, AlertTriangle, CheckCircle } from 'lucide-react'
import { analyzeContent } from '../api/client'
import { LoadingSpinner, ErrorBox, RiskGauge, RiskBadge, SectionCard, RecommendationList } from '../components/UI'

const EXAMPLES = [
  {
    label: 'APK + KYC Scam',
    subject: 'Urgent: KYC Update Required Immediately',
    text: 'Dear Customer, Your account will be suspended within 24 hours. Download APK to verify your KYC immediately. Share your OTP to confirm identity.',
  },
  {
    label: 'Digital Arrest Scam',
    subject: 'CBI Notice - Urgent',
    text: 'This is CBI officer. Your Aadhaar found linked in drug case. You are under digital arrest. Stay on call. Do not inform anyone. Skype hearing arranged.',
  },
  {
    label: 'UPI Fraud',
    subject: 'UPI Cashback Alert',
    text: 'Congratulations! You have won cashback of Rs. 50,000. Send Rs. 1 on UPI to verify. Scan QR code and enter UPI PIN to receive refund amount.',
  },
  {
    label: 'OLX Army Scam',
    subject: 'Interested in your product',
    text: 'I am army officer posted in Ladakh. Interested to buy your product on OLX. Please send advance payment as token amount. I will arrange goods transport.',
  },
  {
    label: 'Loan App Threat',
    subject: 'Loan EMI Overdue',
    text: 'Your loan EMI is overdue. Recovery agent will visit your home. We will upload your photos to your contact list. Share Aadhaar and bank details immediately.',
  },
  {
    label: 'Investment Scam',
    subject: 'Earn Rs.50,000 Daily',
    text: 'Join our Telegram group for guaranteed returns. Double your money in 7 days. Task based earning from home. No investment needed. Crypto trading profit.',
  },
  {
    label: 'SIM Swap',
    subject: 'Your SIM will be blocked',
    text: 'Your Jio SIM card has expired. Complete SIM re-verification immediately to avoid service block. Port your number now. Call 198 and share OTP.',
  },
  {
    label: 'Banking OTP Scam',
    subject: 'HDFC Bank: Account Blocked',
    text: 'Your net banking account has been blocked due to suspicious activity. Share your OTP and Aadhaar number to reactivate within 2 hours.',
  },
]

const CATEGORY_ICONS = {
  urgency: '⏰',
  fear: '😨',
  reward: '🎁',
  credential_theft: '🔐',
  otp_request: '📱',
  banking_scam: '🏦',
  apk_scam: '📲',
  digital_arrest_scam: '🚔',
  olx_quickr_scam: '🛒',
  upi_fraud: '💳',
  loan_app_harassment: '📋',
  sim_swap_fraud: '📡',
  investment_scam: '📈',
}

const PRIORITY_CATS = ['digital_arrest_scam', 'upi_fraud', 'loan_app_harassment', 'sim_swap_fraud', 'olx_quickr_scam', 'investment_scam']

export default function FraudDetection() {
  const [subject, setSubject] = useState('')
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  function loadExample(ex) {
    setSubject(ex.subject)
    setText(ex.text)
    setResult(null)
  }

  async function handleAnalyze() {
    if (!text.trim()) return
    setError(null); setResult(null); setLoading(true)
    try {
      const res = await analyzeContent(text.trim(), subject.trim())
      setResult(res)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const cats = result?.content?.categories || result?.categories || {}

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Email Fraud & Content Detection</h1>
        <p className="text-sm text-gray-400 mt-1">
          Detects 13 social-engineering patterns including India-specific scams: Digital Arrest, UPI Fraud, OLX Scam, SIM Swap, Loan App Harassment, and more.
        </p>
      </div>

      <div className="card space-y-4">
        <input
          className="input-cyber"
          placeholder="Email subject (optional)"
          value={subject}
          onChange={e => setSubject(e.target.value)}
        />
        <textarea
          className="input-cyber h-36 resize-none"
          placeholder="Paste email body, SMS, or WhatsApp message here…"
          value={text}
          onChange={e => setText(e.target.value)}
        />
        <div className="flex items-center gap-3 flex-wrap">
          <button onClick={handleAnalyze} disabled={loading} className="btn-primary">
            <FileSearch className="w-4 h-4" /> Detect Fraud Patterns
          </button>
        </div>

        {/* Example buttons */}
        <div>
          <p className="text-xs text-gray-500 mb-2">Try an example:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map(ex => (
              <button key={ex.label} onClick={() => loadExample(ex)}
                className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                  PRIORITY_CATS.some(c => ex.label.toLowerCase().includes(c.split('_')[0]))
                    ? 'bg-red-900/20 border-red-800 text-red-300 hover:bg-red-900/40'
                    : 'bg-dark-800 border-dark-600 text-cyber-300 hover:bg-dark-700'
                }`}>
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && <LoadingSpinner message="Scanning for fraud patterns…" />}
      {error && <ErrorBox message={error} />}

      {result && (
        <div className="space-y-4 animate-slide-up">
          {/* Summary */}
          <div className="card-glow grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
            <div className="flex flex-col items-center">
              <RiskGauge score={result.overall_risk_score ?? 0} />
              <RiskBadge level={result.risk_level} score={result.overall_risk_score} />
            </div>
            <div className="sm:col-span-2">
              <p className="section-title">Detected Patterns</p>
              {result.detected_labels?.length > 0 ? (
                <ul className="space-y-1.5">
                  {result.detected_labels.map((l, i) => (
                    <li key={i} className={`text-sm flex items-start gap-2 ${
                      l.includes('Digital Arrest') || l.includes('UPI') || l.includes('OLX') || l.includes('SIM') || l.includes('Loan')
                        ? 'text-red-300' : 'text-orange-300'
                    }`}>
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" /> {l}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-green-400 text-sm flex items-center gap-2">
                  <CheckCircle className="w-4 h-4" /> No suspicious patterns detected.
                </p>
              )}
            </div>
          </div>

          {/* UP Police Priority patterns highlighted */}
          {Object.entries(cats).some(([k]) => PRIORITY_CATS.includes(k) && cats[k]?.matched) && (
            <div className="bg-red-900/30 border-2 border-red-700 rounded-xl p-4">
              <p className="text-red-300 font-bold mb-2 flex items-center gap-2">
                🚔 UP Police Priority Scam Patterns Detected
              </p>
              <div className="space-y-1">
                {PRIORITY_CATS.filter(k => cats[k]?.matched).map(k => (
                  <p key={k} className="text-sm text-red-400 flex items-center gap-2">
                    <span>{CATEGORY_ICONS[k]}</span> {cats[k]?.label}
                  </p>
                ))}
              </div>
            </div>
          )}

          {/* All category breakdown */}
          <SectionCard title="All Pattern Categories (13 Types)">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {Object.entries(cats).map(([key, cat]) => (
                <div key={key} className={`rounded-lg p-3 border transition-colors ${
                  cat.matched
                    ? PRIORITY_CATS.includes(key)
                      ? 'bg-red-900/25 border-red-800'
                      : 'bg-orange-900/20 border-orange-800'
                    : 'bg-dark-800 border-dark-700 opacity-50'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-base">{CATEGORY_ICONS[key] || '🔍'}</span>
                    <p className="text-xs font-semibold text-gray-200 flex-1">{cat.label}</p>
                    {cat.matched && (
                      <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold ${
                        PRIORITY_CATS.includes(key)
                          ? 'bg-red-900/50 border-red-700 text-red-400'
                          : 'bg-orange-900/50 border-orange-700 text-orange-400'
                      }`}>
                        {PRIORITY_CATS.includes(key) ? 'PRIORITY' : 'DETECTED'}
                      </span>
                    )}
                  </div>
                  {cat.matched && cat.matches?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {cat.matches.slice(0, 2).map((m, i) => (
                        <span key={i} className="text-[10px] font-mono bg-dark-700 border border-dark-600 px-1.5 py-0.5 rounded text-yellow-300">
                          "{m}"
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      )}
    </div>
  )
}
