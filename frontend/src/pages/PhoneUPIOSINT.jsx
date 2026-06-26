import { useState } from 'react'
import { Phone, CreditCard, Search, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import { analyzePhone, analyzeUPI } from '../api/client'
import { LoadingSpinner, ErrorBox, RiskBadge, SectionCard, KVRow, FlagList } from '../components/UI'

const PHONE_EXAMPLES = ['9876543210', '7020123456', '8800112233']
const UPI_EXAMPLES = ['refund.cashback@paytm', 'govt.tax.refund@okaxis', 'prizewinnerXX@ybl', 'john@okicici']

const SCAM_TYPES = [
  { label: 'Digital Arrest', desc: 'CBI/ED/Police impersonation, parcel scam, stay on call' },
  { label: 'UPI Fraud', desc: 'Collect request scam, fake refund, send Rs.1 trick' },
  { label: 'OLX/Army Scam', desc: 'Defence officer buying items, advance payment demand' },
  { label: 'Loan App', desc: 'Instant loan approval, contact list harassment' },
  { label: 'Investment Scam', desc: 'Telegram group, guaranteed returns, crypto doubling' },
  { label: 'KYC Fraud', desc: 'Bank account block, KYC expiry, OTP sharing' },
]

export default function PhoneUPIOSINT() {
  const [mode, setMode] = useState('phone')
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  async function handleAnalyze() {
    if (!input.trim()) return
    setError(null); setResult(null); setLoading(true)
    try {
      const res = mode === 'phone'
        ? await analyzePhone(input.trim())
        : await analyzeUPI(input.trim())
      setResult(res)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Phone className="w-5 h-5 text-cyber-400" /> Phone & UPI OSINT
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Analyze Indian mobile numbers and UPI IDs for fraud risk indicators. Built for UP Police cyber cell investigations.
        </p>
      </div>

      {/* Common Indian scam types quick reference */}
      <div className="card">
        <p className="section-title">Common Scam Types — Quick Reference</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {SCAM_TYPES.map(s => (
            <div key={s.label} className="bg-dark-800 border border-dark-700 rounded-lg p-2.5">
              <p className="text-xs font-semibold text-cyber-300">{s.label}</p>
              <p className="text-xs text-gray-500 mt-0.5">{s.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Input */}
      <div className="card space-y-4">
        <div className="flex gap-2 bg-dark-800 p-1 rounded-lg w-fit">
          {[['phone', '📱 Phone Number'], ['upi', '💳 UPI ID']].map(([m, l]) => (
            <button key={m} onClick={() => { setMode(m); setInput(''); setResult(null) }}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${mode === m ? 'bg-cyber-700 text-white' : 'text-gray-400 hover:text-gray-200'}`}>
              {l}
            </button>
          ))}
        </div>

        <div className="flex gap-3">
          <input
            className="input-cyber flex-1"
            placeholder={mode === 'phone'
              ? 'Enter 10-digit Indian mobile number (e.g. 9876543210)'
              : 'Enter UPI ID (e.g. name@okaxis, name@paytm)'}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          />
          <button onClick={handleAnalyze} disabled={loading} className="btn-primary shrink-0">
            <Search className="w-4 h-4" /> Analyze
          </button>
        </div>

        <div>
          <p className="text-xs text-gray-500 mb-2">Examples:</p>
          <div className="flex flex-wrap gap-2">
            {(mode === 'phone' ? PHONE_EXAMPLES : UPI_EXAMPLES).map(ex => (
              <button key={ex} onClick={() => setInput(ex)}
                className="text-xs font-mono bg-dark-800 hover:bg-dark-700 border border-dark-600 px-3 py-1 rounded text-cyber-300 transition-colors">
                {ex}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading && <LoadingSpinner message="Running OSINT analysis…" />}
      {error && <ErrorBox message={error} />}

      {result && (
        <div className="space-y-4 animate-slide-up">
          {result.error ? (
            <ErrorBox message={result.error} />
          ) : (
            <>
              {/* Risk Summary */}
              <div className={`card border ${
                result.risk_level === 'Critical' ? 'border-red-700 bg-red-900/20' :
                result.risk_level === 'High' ? 'border-orange-700 bg-orange-900/20' :
                result.risk_level === 'Medium' ? 'border-yellow-700 bg-yellow-900/20' :
                'border-green-700 bg-green-900/20'
              }`}>
                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <div>
                    <p className="text-xs text-gray-500 mb-1">
                      {mode === 'phone' ? 'Mobile Number' : 'UPI ID'}
                    </p>
                    <p className="text-lg font-mono font-bold text-white">
                      {result.cleaned || result.upi_id}
                    </p>
                  </div>
                  <RiskBadge level={result.risk_level} score={result.risk_score} />
                </div>
              </div>

              {/* Phone Details */}
              {mode === 'phone' && result.is_valid_indian_mobile && (
                <SectionCard title="Mobile Number Intelligence" icon={Phone}>
                  <div className="space-y-0.5">
                    <KVRow label="Carrier / Network" value={result.carrier} />
                    <KVRow label="Telecom Circle" value={result.telecom_circle} />
                    <KVRow label="Number Type" value={result.number_type} />
                    <KVRow label="Valid Indian Mobile" value="Yes ✓" />
                  </div>
                </SectionCard>
              )}

              {/* UPI Details */}
              {mode === 'upi' && result.valid_format && (
                <SectionCard title="UPI ID Intelligence" icon={CreditCard}>
                  <div className="space-y-0.5">
                    <KVRow label="UPI Handle" value={result.handle} mono />
                    <KVRow label="VPA Suffix" value={result.vpa_suffix} mono />
                    <KVRow label="Bank / App" value={result.bank_or_app} />
                  </div>
                </SectionCard>
              )}

              {/* Flags */}
              {result.flags?.length > 0 && (
                <SectionCard title="Risk Flags" icon={AlertTriangle}>
                  <FlagList flags={result.flags} />
                </SectionCard>
              )}

              {/* Investigation Notes */}
              {result.investigation_notes?.length > 0 && (
                <SectionCard title="Investigation Notes (For Officers)" icon={Info}>
                  <ul className="space-y-2">
                    {result.investigation_notes.map((note, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                        <span className="text-cyber-400 shrink-0">ℹ</span> {note}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-4 bg-dark-800 border border-dark-600 rounded-lg p-3">
                    <p className="text-xs font-semibold text-yellow-400 mb-1">⚠️ Legal Notice</p>
                    <p className="text-xs text-gray-400">
                      Subscriber details require court order / judicial magistrate order under Section 91 CrPC
                      or Section 160 CrPC. Contact the TSP/bank through official LEA portal.
                      Report cybercrime at <span className="text-cyber-400">cybercrime.gov.in</span> or helpline <span className="text-cyber-400">1930</span>.
                    </p>
                  </div>
                </SectionCard>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
