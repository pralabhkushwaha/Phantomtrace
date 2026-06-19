import { useState } from 'react'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import { RiskGauge, RiskBadge, SectionCard, RecommendationList } from '../components/UI'

function ScoreSlider({ label, value, onChange, description }) {
  const color = value >= 70 ? 'accent-red-500' : value >= 40 ? 'accent-orange-500' : 'accent-yellow-400'
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center">
        <label className="text-sm font-medium text-gray-300">{label}</label>
        <span className={`font-mono text-sm font-bold ${value >= 70 ? 'text-red-400' : value >= 40 ? 'text-orange-400' : value > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
          {value}/100
        </span>
      </div>
      <input type="range" min="0" max="100" value={value}
        onChange={e => onChange(parseInt(e.target.value))}
        className="w-full h-1.5 rounded-full bg-dark-700 appearance-none cursor-pointer" />
      <p className="text-xs text-gray-500">{description}</p>
    </div>
  )
}

// Simple local risk calculation mirrors backend risk_engine.py
function calcRisk(scores) {
  const header  = Math.min(Math.round(scores.header * 0.40), 40)
  const attr    = Math.min(scores.attribution * 7, 20)
  const content = Math.min(Math.round(scores.content * 0.25), 25)
  const attach  = Math.min(Math.round(scores.attachment * 0.20), 20)
  const hg      = Math.min(Math.round(scores.homograph * 0.30), 30)
  const url     = Math.min(Math.round(scores.url * 0.30), 30)

  const total = Math.min(header + attr + content + attach + hg + url, 100)
  const level = total >= 75 ? 'Critical' : total >= 50 ? 'High' : total >= 25 ? 'Medium' : 'Low'

  return {
    total_score: total,
    risk_level: level,
    breakdown: {
      'Email Header Forensics': header,
      'Sender Attribution': attr,
      'Content Analysis': content,
      'Attachment Risk': attach,
      'Homograph / Brand Impersonation': hg,
      'URL Intelligence': url,
    },
  }
}

const DEFAULT_SCORES = {
  header: 0,
  attribution: 0,
  content: 0,
  attachment: 0,
  homograph: 0,
  url: 0,
}

const SLIDER_META = [
  { key: 'header',      label: 'Email Header / Auth Failures', description: 'Set based on SPF/DKIM/DMARC failures, Reply-To mismatch, spoofing flags found in header analysis.' },
  { key: 'attribution', label: 'Sender Attribution Indicators', description: 'Number of suspicious indicators (0–3 typically): newly registered domain, bulletproof host, high-risk country.' },
  { key: 'content',     label: 'Content Risk Score',            description: 'Score from the Fraud Detection module — urgency, OTP requests, APK download, KYC scam language.' },
  { key: 'attachment',  label: 'Attachment Risk Score',          description: 'Score from attachment analysis — dangerous extensions, double extensions, malicious filenames.' },
  { key: 'homograph',   label: 'Homograph Confidence',           description: 'Confidence % from the Homograph Detector — how sure the engine is about brand impersonation.' },
  { key: 'url',         label: 'URL Risk Score',                 description: 'Score from URL Intelligence — shortener, suspicious TLD, reputation feeds, redirect chain.' },
]

const QUICK_PROFILES = [
  { label: 'Clean Email', scores: { header: 5, attribution: 0, content: 0, attachment: 0, homograph: 0, url: 0 } },
  { label: 'KYC Scam',    scores: { header: 60, attribution: 1, content: 75, attachment: 0, homograph: 70, url: 40 } },
  { label: 'APK Malware', scores: { header: 80, attribution: 2, content: 90, attachment: 85, homograph: 80, url: 60 } },
  { label: 'Brand Spoof', scores: { header: 70, attribution: 1, content: 40, attachment: 0, homograph: 95, url: 50 } },
]

export default function RiskAssessment() {
  const [scores, setScores] = useState(DEFAULT_SCORES)

  const update = key => val => setScores(s => ({ ...s, [key]: val }))

  const risk = calcRisk(scores)
  const pct = risk.total_score

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Risk Assessment Calculator</h1>
        <p className="text-sm text-gray-400 mt-1">
          Manually enter module sub-scores to compute an aggregate risk rating — useful for combining findings from multiple investigation steps.
        </p>
      </div>

      {/* Quick profiles */}
      <div className="card">
        <p className="section-title">Quick Test Profiles</p>
        <div className="flex flex-wrap gap-2">
          {QUICK_PROFILES.map(p => (
            <button key={p.label} onClick={() => setScores(p.scores)}
              className="btn-secondary text-xs py-1.5">
              {p.label}
            </button>
          ))}
          <button onClick={() => setScores(DEFAULT_SCORES)} className="text-xs text-gray-500 hover:text-gray-300 px-3">
            Reset
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sliders */}
        <div className="lg:col-span-2 card space-y-6">
          <p className="section-title">Module Sub-Scores</p>
          {SLIDER_META.map(({ key, label, description }) => (
            <ScoreSlider key={key} label={label} value={scores[key]}
              onChange={update(key)} description={description} />
          ))}
        </div>

        {/* Live gauge */}
        <div className="space-y-4">
          <div className="card-glow flex flex-col items-center gap-4 py-6">
            <p className="section-title text-center">Aggregate Risk Score</p>
            <RiskGauge score={pct} />
            <RiskBadge level={risk.risk_level} score={pct} />
          </div>

          <SectionCard title="Score Breakdown">
            <div className="space-y-2">
              {Object.entries(risk.breakdown).map(([module, pts]) => (
                <div key={module}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">{module}</span>
                    <span className="font-mono text-cyber-300">{pts}</span>
                  </div>
                  <div className="h-1.5 bg-dark-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${pts >= 20 ? 'bg-red-500' : pts >= 10 ? 'bg-orange-500' : pts > 0 ? 'bg-yellow-500' : 'bg-dark-600'}`}
                      style={{ width: `${(pts / 40) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

          {/* Verdict explanation */}
          <div className={`card border ${
            risk.risk_level === 'Critical' ? 'border-red-700 bg-red-900/20' :
            risk.risk_level === 'High' ? 'border-orange-700 bg-orange-900/20' :
            risk.risk_level === 'Medium' ? 'border-yellow-700 bg-yellow-900/20' :
            'border-green-700 bg-green-900/20'
          }`}>
            <div className="flex items-start gap-3">
              {risk.risk_level === 'Low'
                ? <ShieldCheck className="w-5 h-5 text-green-400 shrink-0" />
                : <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />}
              <div>
                <p className="text-sm font-semibold text-gray-100">{risk.risk_level} Risk</p>
                <p className="text-xs text-gray-400 mt-1">
                  {risk.risk_level === 'Critical' && 'Multiple high-confidence phishing indicators detected. Treat this as a confirmed phishing attempt.'}
                  {risk.risk_level === 'High' && 'Significant phishing indicators found. Verify through official channels before taking any action.'}
                  {risk.risk_level === 'Medium' && 'Some suspicious indicators. Exercise caution and do not click links or share credentials.'}
                  {risk.risk_level === 'Low' && 'Few or no risk indicators found. Always verify sender identity independently.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
