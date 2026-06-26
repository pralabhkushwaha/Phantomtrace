import { useState } from 'react'
import { ShieldCheck, ShieldAlert, RefreshCw } from 'lucide-react'
import { RiskGauge, RiskBadge, SectionCard, RecommendationList } from '../components/UI'

function ScoreSlider({ label, value, max, onChange, description, color }) {
  const pct = (value / max) * 100
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center">
        <label className="text-sm font-medium text-gray-300">{label}</label>
        <span className={`font-mono text-sm font-bold ${
          pct >= 70 ? 'text-red-400' : pct >= 40 ? 'text-orange-400' : value > 0 ? 'text-yellow-400' : 'text-green-400'
        }`}>
          {value}/{max}
        </span>
      </div>
      <input
        type="range" min="0" max={max} value={value}
        onChange={e => onChange(parseInt(e.target.value))}
        className="w-full h-1.5 rounded-full bg-dark-700 appearance-none cursor-pointer"
      />
      <p className="text-xs text-gray-500">{description}</p>
    </div>
  )
}

// Mirrors backend risk_engine.py exactly
function calcRisk(scores) {
  const header  = Math.min(Math.round(scores.header  * 0.40), 40)
  const attr    = Math.min(Math.round(scores.attr    * 0.20), 20)  // FIX: now 0-100 scale
  const content = Math.min(Math.round(scores.content * 0.25), 25)
  const attach  = Math.min(Math.round(scores.attach  * 0.20), 20)
  const hg      = Math.min(Math.round(scores.hg      * 0.30), 30)
  const url     = Math.min(Math.round(scores.url     * 0.30), 30)

  const total = Math.min(header + attr + content + attach + hg + url, 100)
  const level = total >= 75 ? 'Critical' : total >= 50 ? 'High' : total >= 25 ? 'Medium' : 'Low'

  return {
    total,
    level,
    breakdown: {
      'Email Header & Auth Failures': { pts: header, max: 40 },
      'Sender Attribution Risk':      { pts: attr,   max: 20 },
      'Content / Fraud Patterns':     { pts: content, max: 25 },
      'Attachment Risk':              { pts: attach,  max: 20 },
      'Homograph / Brand Spoof':      { pts: hg,     max: 30 },
      'URL Intelligence':             { pts: url,    max: 30 },
    },
  }
}

const SLIDERS = [
  { key: 'header',  label: 'Email Header / Auth Failures',   max: 100, desc: 'SPF/DKIM/DMARC failures, Reply-To mismatch, display-name spoofing, suspicious relay TLD. Set to 100 if all three auth checks fail.' },
  { key: 'attr',    label: 'Sender Attribution Risk',        max: 100, desc: 'Newly registered domain, bulletproof hosting, high-risk country, proxy/VPN detected. Set higher for more suspicious indicators.' },
  { key: 'content', label: 'Content / Fraud Pattern Score',  max: 100, desc: 'From Fraud Detection module — urgency, OTP request, APK download, KYC scam, fear tactics.' },
  { key: 'attach',  label: 'Attachment Risk Score',          max: 100, desc: 'Dangerous extension (.exe/.apk/.vbs), double-extension trick, MIME type mismatch.' },
  { key: 'hg',      label: 'Homograph Confidence %',        max: 100, desc: 'Confidence from Homograph Detector — 99% = near-certain brand impersonation, 60% = possible.' },
  { key: 'url',     label: 'URL Risk Score',                 max: 100, desc: 'URL shortener, suspicious TLD, reputation feeds, redirect chain depth, raw IP address.' },
]

const PROFILES = [
  { label: '✅ Clean Email',    scores: { header: 5,  attr: 0,  content: 0,  attach: 0,  hg: 0,  url: 0  } },
  { label: '🏦 KYC Scam',      scores: { header: 60, attr: 40, content: 80, attach: 0,  hg: 70, url: 40 } },
  { label: '📲 APK Malware',   scores: { header: 80, attr: 60, content: 90, attach: 85, hg: 80, url: 60 } },
  { label: '🎭 Brand Spoof',   scores: { header: 70, attr: 30, content: 40, attach: 0,  hg: 95, url: 50 } },
  { label: '🎣 Full Phishing', scores: { header: 100,attr: 80, content: 100,attach: 50, hg: 95, url: 80 } },
]

const DEFAULT = { header: 0, attr: 0, content: 0, attach: 0, hg: 0, url: 0 }

const RECOMMENDATIONS_BY_LEVEL = {
  Critical: [
    { priority: 'Critical', icon: '🛑', title: 'Do NOT interact with this email', detail: 'Multiple high-confidence phishing indicators detected. Do not click any links, download attachments, or reply. Report to your IT/security team immediately.' },
    { priority: 'Critical', icon: '🔐', title: 'Do NOT share OTP or credentials', detail: 'This has the hallmarks of a credential-harvesting attack. No legitimate organization will ask for your OTP, password, or PIN via email.' },
    { priority: 'High',     icon: '📱', title: 'Do NOT install any app from this link', detail: 'APK files sent via email are almost exclusively used to install Android banking trojans or spyware.' },
  ],
  High: [
    { priority: 'High', icon: '⚠️', title: 'Verify sender through official channels', detail: 'Call the official helpline number (from the organization\'s real website) before taking any action requested in this email.' },
    { priority: 'High', icon: '🔍', title: 'Check domain carefully before clicking', detail: 'Hover over all links and verify the real domain. Look for digit substitutions (0→o), extra hyphens, or unusual TLDs.' },
  ],
  Medium: [
    { priority: 'Medium', icon: '⏰', title: 'Do not act on urgency pressure', detail: 'Urgency language ("act within 24 hours") is a social-engineering tactic. Pause and verify independently before responding.' },
    { priority: 'Medium', icon: '🔒', title: 'Enable Multi-Factor Authentication', detail: 'Enable MFA on your email, banking, and social media accounts to reduce damage even if credentials are compromised.' },
  ],
  Low: [
    { priority: 'Low', icon: '✅', title: 'Low risk — standard precautions apply', detail: 'No major indicators detected. Continue to verify sender identity for any email asking you to take action or share information.' },
  ],
}

export default function RiskAssessment() {
  const [scores, setScores] = useState(DEFAULT)
  const update = key => val => setScores(s => ({ ...s, [key]: val }))
  const risk = calcRisk(scores)

  const recs = RECOMMENDATIONS_BY_LEVEL[risk.level] || RECOMMENDATIONS_BY_LEVEL.Low

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Risk Assessment Calculator</h1>
        <p className="text-sm text-gray-400 mt-1">
          Adjust each module's risk level to compute an aggregate score. Use quick profiles or set sliders manually.
        </p>
      </div>

      {/* Quick profiles */}
      <div className="card">
        <p className="section-title">Quick Profiles</p>
        <div className="flex flex-wrap gap-2 items-center">
          {PROFILES.map(p => (
            <button key={p.label} onClick={() => setScores(p.scores)} className="btn-secondary text-xs py-1.5">
              {p.label}
            </button>
          ))}
          <button onClick={() => setScores(DEFAULT)}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 px-3">
            <RefreshCw className="w-3 h-3" /> Reset
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Sliders — takes 3 cols */}
        <div className="lg:col-span-3 card space-y-5">
          <p className="section-title">Module Risk Levels</p>
          {SLIDERS.map(({ key, label, max, desc }) => (
            <ScoreSlider key={key} label={label} value={scores[key]} max={max}
              onChange={update(key)} description={desc} />
          ))}
        </div>

        {/* Live results — takes 2 cols */}
        <div className="lg:col-span-2 space-y-4">

          {/* Gauge */}
          <div className="card-glow flex flex-col items-center gap-3 py-6">
            <p className="section-title text-center">Aggregate Risk Score</p>
            <RiskGauge score={risk.total} />
            <RiskBadge level={risk.level} score={risk.total} />
          </div>

          {/* Breakdown bars */}
          <SectionCard title="Score Breakdown">
            <div className="space-y-3">
              {Object.entries(risk.breakdown).map(([mod, { pts, max }]) => (
                <div key={mod}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400 truncate pr-2">{mod}</span>
                    <span className="font-mono text-cyber-300 shrink-0">{pts}/{max}</span>
                  </div>
                  <div className="h-1.5 bg-dark-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${
                        pts >= max * 0.75 ? 'bg-red-500' :
                        pts >= max * 0.4  ? 'bg-orange-500' :
                        pts > 0           ? 'bg-yellow-500' : 'bg-dark-600'
                      }`}
                      style={{ width: `${max > 0 ? (pts / max) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          {/* Verdict */}
          <div className={`card border ${
            risk.level === 'Critical' ? 'border-red-700 bg-red-900/20' :
            risk.level === 'High'     ? 'border-orange-700 bg-orange-900/20' :
            risk.level === 'Medium'   ? 'border-yellow-700 bg-yellow-900/20' :
                                        'border-green-700 bg-green-900/20'
          }`}>
            <div className="flex items-start gap-3">
              {risk.level === 'Low'
                ? <ShieldCheck className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
                : <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />}
              <div>
                <p className="text-sm font-semibold text-gray-100">{risk.level} Risk — {risk.total}/100</p>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                  {risk.level === 'Critical' && 'Multiple high-confidence phishing indicators. Treat this as a confirmed phishing attempt — do not engage.'}
                  {risk.level === 'High' && 'Significant phishing indicators found. Verify through official channels before taking any action.'}
                  {risk.level === 'Medium' && 'Some suspicious indicators. Exercise caution — do not click links or share credentials.'}
                  {risk.level === 'Low' && 'Few or no risk indicators detected. Always verify sender identity independently.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recommendations */}
      <SectionCard title="Recommendations for this Risk Level">
        <RecommendationList recommendations={recs} />
      </SectionCard>
    </div>
  )
}
