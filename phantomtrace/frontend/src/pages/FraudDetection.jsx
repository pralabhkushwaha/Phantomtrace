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
    label: 'Banking OTP Scam',
    subject: 'HDFC Bank: Account Blocked',
    text: 'Your net banking account has been blocked due to suspicious activity. Please share your OTP and Aadhaar number to reactivate your account within 2 hours.',
  },
  {
    label: 'Lottery Reward',
    subject: 'Congratulations! You have won Rs. 50,00,000',
    text: "Congratulations! You've been selected as a lucky winner of our bumper prize lottery. Claim your prize now by clicking the link below. Act immediately — offer expires today!",
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
}

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

  const cats = result?.content?.categories || {}

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Email Fraud &amp; Content Detection</h1>
        <p className="text-sm text-gray-400 mt-1">
          Detect social-engineering patterns: urgency, fear, OTP requests, APK scams, KYC fraud, and more.
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
          className="input-cyber h-40 resize-none"
          placeholder="Paste email body text here…"
          value={text}
          onChange={e => setText(e.target.value)}
        />
        <div className="flex items-center gap-3 flex-wrap">
          <button onClick={handleAnalyze} disabled={loading} className="btn-primary">
            <FileSearch className="w-4 h-4" /> Detect Fraud Patterns
          </button>
          <span className="text-xs text-gray-500">Try an example:</span>
          {EXAMPLES.map(ex => (
            <button key={ex.label} onClick={() => loadExample(ex)}
              className="text-xs bg-dark-800 hover:bg-dark-700 border border-dark-600 px-3 py-1.5 rounded text-cyber-300 transition-colors">
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {loading && <LoadingSpinner message="Scanning for social-engineering patterns…" />}
      {error && <ErrorBox message={error} />}

      {result && (
        <div className="space-y-4 animate-slide-up">
          {/* Summary */}
          <div className="card-glow grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
            <div className="flex flex-col items-center">
              <RiskGauge score={result.risk?.total_score ?? 0} />
              <RiskBadge level={result.risk?.risk_level} score={result.risk?.total_score} />
            </div>
            <div className="sm:col-span-2">
              <p className="section-title">Detected Patterns</p>
              {result.content?.detected_labels?.length > 0 ? (
                <ul className="space-y-1.5">
                  {result.content.detected_labels.map((l, i) => (
                    <li key={i} className="text-sm text-red-300 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      {l}
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

          {/* Category breakdown */}
          <SectionCard title="Pattern Category Breakdown">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {Object.entries(cats).map(([key, cat]) => (
                <div key={key}
                  className={`rounded-lg p-3 border transition-colors ${
                    cat.matched
                      ? 'bg-red-900/20 border-red-800'
                      : 'bg-dark-800 border-dark-700 opacity-60'
                  }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-lg">{CATEGORY_ICONS[key] || '🔍'}</span>
                    <p className="text-sm font-semibold text-gray-200">{cat.label}</p>
                    {cat.matched && (
                      <span className="ml-auto badge-high">Detected</span>
                    )}
                  </div>
                  {cat.matched && cat.matches?.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {cat.matches.map((m, i) => (
                        <span key={i} className="text-xs font-mono bg-dark-700 border border-dark-600 px-2 py-0.5 rounded text-yellow-300">
                          "{m}"
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </SectionCard>

          {result.recommendations?.length > 0 && (
            <SectionCard title="Security Recommendations">
              <RecommendationList recommendations={result.recommendations.slice(0, 6)} />
            </SectionCard>
          )}
        </div>
      )}
    </div>
  )
}
