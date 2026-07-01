import { useState } from 'react'
import { Phone, CreditCard, Search, AlertTriangle, Info, Shield, CheckCircle } from 'lucide-react'
import { analyzePhone, analyzeUPI } from '../api/client'
import { RiskBadge, LoadingSpinner } from '../components/UI'

function InfoRow({ label, value, highlight, mono }) {
  if (!value && value !== 0 && value !== false) return null
  return (
    <div className="flex items-start justify-between py-2 border-b border-dark-700 last:border-0 gap-4">
      <span className="text-xs text-gray-500 uppercase tracking-wider shrink-0 w-36">{label}</span>
      <span className={`text-sm text-right break-all ${mono ? 'font-mono' : ''} ${highlight ? 'text-cyber-300 font-semibold' : 'text-gray-300'}`}>
        {String(value)}
      </span>
    </div>
  )
}

export default function PhoneUPIOSINT() {
  const [tab, setTab] = useState('phone')
  const [phoneInput, setPhoneInput] = useState('')
  const [upiInput, setUpiInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handlePhoneSearch() {
    if (!phoneInput.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      setResult(await analyzePhone(phoneInput.trim()))
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Analysis failed.')
    } finally { setLoading(false) }
  }

  async function handleUPISearch() {
    if (!upiInput.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      setResult(await analyzeUPI(upiInput.trim()))
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Analysis failed.')
    } finally { setLoading(false) }
  }

  const isPhone = tab === 'phone'

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Phone className="w-6 h-6 text-cyber-400" />
          Phone & UPI <span className="text-cyber-400">OSINT</span>
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Indian mobile carrier detection (TRAI series data) + UPI fraud pattern analysis
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-dark-800 p-1 rounded-lg w-fit border border-dark-700">
        {['phone', 'upi'].map(t => (
          <button key={t} onClick={() => { setTab(t); setResult(null); setError(null) }}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all capitalize ${
              tab === t
                ? 'bg-cyber-800/60 text-cyber-300 border border-cyber-700'
                : 'text-gray-400 hover:text-gray-200'
            }`}>
            {t === 'phone' ? '📱 Phone Number' : '💳 UPI ID'}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="card flex gap-3">
        <input
          value={isPhone ? phoneInput : upiInput}
          onChange={e => isPhone ? setPhoneInput(e.target.value) : setUpiInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (isPhone ? handlePhoneSearch() : handleUPISearch())}
          placeholder={isPhone ? 'Enter mobile number (e.g. 9319975446 or +919319975446)' : 'Enter UPI ID (e.g. name@okaxis)'}
          className="input-field flex-1 font-mono"
        />
        <button
          onClick={isPhone ? handlePhoneSearch : handleUPISearch}
          disabled={!(isPhone ? phoneInput : upiInput).trim() || loading}
          className="btn-primary flex items-center gap-2 disabled:opacity-40 shrink-0">
          <Search className="w-4 h-4" />
          Analyze
        </button>
      </div>

      {loading && <LoadingSpinner message="Analyzing against TRAI number series database…" />}
      {error && <div className="card border-red-800 bg-red-900/10 text-red-400 text-sm p-4">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Phone result */}
          {result.is_valid_indian_mobile !== undefined && (
            <>
              {!result.is_valid_indian_mobile ? (
                <div className="card border-red-800 bg-red-950/10">
                  <p className="text-red-400 font-semibold">{result.error}</p>
                </div>
              ) : (
                <>
                  {/* Header */}
                  <div className="card flex items-center justify-between flex-wrap gap-4">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-cyber-900/50 border border-cyber-800 flex items-center justify-center">
                        <Phone className="w-6 h-6 text-cyber-400" />
                      </div>
                      <div>
                        <p className="text-xl font-bold font-mono text-white">{result.cleaned}</p>
                        <p className="text-sm text-gray-400">{result.carrier} · {result.telecom_circle}</p>
                      </div>
                    </div>
                    <RiskBadge level={result.risk_level} score={result.risk_score} />
                  </div>

                  <div className="grid md:grid-cols-2 gap-4">
                    {/* Mobile Intelligence */}
                    <div className="card">
                      <h3 className="section-title flex items-center gap-2 mb-3">
                        <Phone className="w-4 h-4 text-cyber-400" /> Mobile Number Intelligence
                      </h3>
                      <InfoRow label="Carrier / Network" value={result.carrier} highlight />
                      <InfoRow label="Telecom Circle"    value={result.telecom_circle} highlight />
                      <InfoRow label="Number Type"       value={result.number_type} />
                      <InfoRow label="Valid Indian Mobile" value="Yes ✓" />
                      {result.numverify?.available && (
                        <>
                          <InfoRow label="Line Type (API)"  value={result.numverify.line_type} />
                          <InfoRow label="Carrier (API)"    value={result.numverify.carrier} highlight />
                          <InfoRow label="Location (API)"   value={result.numverify.location} />
                        </>
                      )}
                    </div>

                    {/* Risk flags */}
                    <div className="card">
                      <h3 className="section-title flex items-center gap-2 mb-3">
                        <AlertTriangle className="w-4 h-4 text-red-400" /> Risk Indicators
                      </h3>
                      {result.flags?.length > 0 ? (
                        result.flags.map((f, i) => (
                          <div key={i} className="flex items-start gap-2 py-1.5 border-b border-dark-700 last:border-0">
                            <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                            <span className="text-xs text-red-300">{f}</span>
                          </div>
                        ))
                      ) : (
                        <div className="flex items-center gap-2 text-sm text-green-400">
                          <CheckCircle className="w-4 h-4" /> No suspicious patterns detected
                        </div>
                      )}
                    </div>
                  </div>

                  {/* MNP Disclaimer */}
                  <div className="card border-yellow-900/40 bg-yellow-950/10 flex gap-3">
                    <Info className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
                    <div className="text-xs text-yellow-300 space-y-1">
                      <p className="font-semibold">Mobile Number Portability (MNP) Disclaimer</p>
                      <p>{result.mnp_disclaimer}</p>
                      <p>For 100% accurate current carrier: Use DoT TAFCOP portal or contact TSP with court order.</p>
                    </div>
                  </div>

                  {/* Investigation notes */}
                  <div className="card">
                    <h3 className="section-title flex items-center gap-2 mb-3">
                      <Info className="w-4 h-4 text-cyber-400" /> Investigation Notes (For Officers)
                    </h3>
                    {result.investigation_notes?.map((n, i) => (
                      <div key={i} className="flex items-start gap-2 py-1.5 border-b border-dark-700 last:border-0">
                        <span className="text-cyber-500 shrink-0">ℹ</span>
                        <span className="text-xs text-gray-300">{n}</span>
                      </div>
                    ))}
                  </div>

                  {/* Legal notice */}
                  <div className="card border-dark-600 bg-dark-800/40 flex gap-3">
                    <Shield className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
                    <div className="text-xs text-gray-400">
                      <p className="font-semibold text-orange-400 mb-1">Legal Notice</p>
                      <p>Subscriber name/address requires <strong>court order / judicial magistrate order</strong> under Section 91 CrPC or Section 160 CrPC. Contact TSP/bank through official LEA portal. Report cybercrime at <span className="text-cyber-400">cybercrime.gov.in</span> or helpline <span className="text-cyber-400">1930</span>.</p>
                    </div>
                  </div>
                </>
              )}
            </>
          )}

          {/* UPI result */}
          {result.upi_id !== undefined && (
            <>
              {!result.valid_format ? (
                <div className="card border-red-800 bg-red-950/10">
                  <p className="text-red-400">{result.error}</p>
                </div>
              ) : (
                <>
                  <div className="card flex items-center justify-between flex-wrap gap-4">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-cyber-900/50 border border-cyber-800 flex items-center justify-center">
                        <CreditCard className="w-6 h-6 text-cyber-400" />
                      </div>
                      <div>
                        <p className="text-xl font-bold font-mono text-white">{result.upi_id}</p>
                        <p className="text-sm text-gray-400">{result.bank_or_app}</p>
                      </div>
                    </div>
                    <RiskBadge level={result.risk_level} score={result.risk_score} />
                  </div>

                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="card">
                      <h3 className="section-title mb-3">UPI ID Intelligence</h3>
                      <InfoRow label="UPI ID"     value={result.upi_id} mono highlight />
                      <InfoRow label="Handle"     value={result.handle} mono />
                      <InfoRow label="VPA Suffix" value={result.vpa_suffix} mono />
                      <InfoRow label="Bank / App" value={result.bank_or_app} highlight />
                    </div>

                    <div className="card">
                      <h3 className="section-title flex items-center gap-2 mb-3">
                        <AlertTriangle className="w-4 h-4 text-red-400" /> Fraud Indicators
                      </h3>
                      {result.flags?.length > 0 ? (
                        result.flags.map((f, i) => (
                          <div key={i} className="flex items-start gap-2 py-1.5 border-b border-dark-700 last:border-0">
                            <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                            <span className="text-xs text-red-300">{f}</span>
                          </div>
                        ))
                      ) : (
                        <div className="flex items-center gap-2 text-sm text-green-400">
                          <CheckCircle className="w-4 h-4" /> No fraud patterns detected
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="card border-dark-600 bg-dark-800/40 flex gap-3">
                    <Shield className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
                    <div className="text-xs text-gray-400">
                      <p className="font-semibold text-orange-400 mb-1">Legal Notice</p>
                      <p>UPI account holder name/details require <strong>official request to NPCI/respective bank</strong> with court order under IT Act. Report fraud: <span className="text-cyber-400">cybercrime.gov.in</span> | Helpline: <span className="text-cyber-400">1930</span></p>
                    </div>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
