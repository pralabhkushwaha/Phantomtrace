import { clsx } from 'clsx'
import { AlertTriangle, CheckCircle, XCircle, Minus, ShieldAlert, Shield } from 'lucide-react'

// ─── Risk Badge ────────────────────────────────────────────────────────────
export function RiskBadge({ level, score }) {
  const map = {
    Critical: 'badge-critical',
    High: 'badge-high',
    Medium: 'badge-medium',
    Low: 'badge-low',
  }
  return (
    <span className={clsx(map[level] || 'badge-low')}>
      {level}{score !== undefined ? ` (${score}/100)` : ''}
    </span>
  )
}

// ─── Risk Gauge ────────────────────────────────────────────────────────────
export function RiskGauge({ score = 0 }) {
  const angle = (score / 100) * 180
  const color =
    score >= 75 ? '#ef4444' :
    score >= 50 ? '#f97316' :
    score >= 25 ? '#eab308' : '#22c55e'

  const r = 70
  const cx = 90, cy = 90
  const toRad = (d) => (d * Math.PI) / 180
  const startX = cx + r * Math.cos(toRad(180))
  const startY = cy + r * Math.sin(toRad(180))
  const endAngle = 180 - angle
  const endX = cx + r * Math.cos(toRad(endAngle))
  const endY = cy + r * Math.sin(toRad(endAngle))
  const largeArc = angle > 90 ? 0 : 0

  return (
    <div className="flex flex-col items-center gap-1">
      <svg viewBox="0 0 180 100" className="w-44 h-24">
        {/* Background arc */}
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
              fill="none" stroke="#1e3a5f" strokeWidth="14" strokeLinecap="round" />
        {/* Value arc */}
        <path
          d={`M ${startX} ${startY} A ${r} ${r} 0 ${score > 50 ? 1 : 0} 0 ${endX} ${endY}`}
          fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
        />
        {/* Score text */}
        <text x={cx} y={cy - 4} textAnchor="middle" fill={color}
              fontSize="26" fontWeight="bold" fontFamily="monospace">
          {score}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#9ca3af" fontSize="11">
          / 100
        </text>
      </svg>
    </div>
  )
}

// ─── Auth Badge ────────────────────────────────────────────────────────────
export function AuthBadge({ label, status }) {
  const s = (status || 'none').toLowerCase()
  const isPass = s === 'pass'
  const isFail = ['fail', 'softfail', 'permerror', 'temperror'].includes(s)

  return (
    <div className={clsx(
      'flex flex-col items-center gap-1 px-4 py-3 rounded-lg border text-center',
      isPass && 'bg-green-900/30 border-green-700',
      isFail && 'bg-red-900/30 border-red-700',
      !isPass && !isFail && 'bg-dark-800 border-dark-600',
    )}>
      {isPass ? (
        <CheckCircle className="w-5 h-5 text-green-400" />
      ) : isFail ? (
        <XCircle className="w-5 h-5 text-red-400" />
      ) : (
        <Minus className="w-5 h-5 text-gray-400" />
      )}
      <span className="text-xs font-bold tracking-wider text-gray-300">{label}</span>
      <span className={clsx(
        'text-xs font-mono font-bold uppercase',
        isPass && 'text-green-400',
        isFail && 'text-red-400',
        !isPass && !isFail && 'text-gray-400',
      )}>
        {status || 'none'}
      </span>
    </div>
  )
}

// ─── Flag List ─────────────────────────────────────────────────────────────
export function FlagList({ flags = [], emptyText = 'No issues detected.' }) {
  if (!flags.length) {
    return (
      <div className="flex items-center gap-2 text-green-400 text-sm">
        <CheckCircle className="w-4 h-4" /> {emptyText}
      </div>
    )
  }
  return (
    <ul className="space-y-2">
      {flags.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-sm text-red-300">
          <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
          <span>{f}</span>
        </li>
      ))}
    </ul>
  )
}

// ─── Section Card ──────────────────────────────────────────────────────────
export function SectionCard({ title, icon: Icon, children, className }) {
  return (
    <div className={clsx('card animate-slide-up', className)}>
      {title && (
        <div className="flex items-center gap-2 mb-4 pb-3 border-b border-dark-700">
          {Icon && <Icon className="w-4 h-4 text-cyber-400" />}
          <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
        </div>
      )}
      {children}
    </div>
  )
}

// ─── Loading Spinner ───────────────────────────────────────────────────────
export function LoadingSpinner({ message = 'Analyzing…' }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 animate-fade-in">
      <div className="relative">
        <div className="w-14 h-14 rounded-full border-2 border-dark-700" />
        <div className="absolute inset-0 w-14 h-14 rounded-full border-2 border-t-cyber-500 animate-spin" />
        <ShieldAlert className="absolute inset-0 m-auto w-6 h-6 text-cyber-400" />
      </div>
      <p className="text-cyber-400 font-mono text-sm tracking-wider animate-pulse">{message}</p>
    </div>
  )
}

// ─── Error Box ─────────────────────────────────────────────────────────────
export function ErrorBox({ message }) {
  return (
    <div className="bg-red-900/30 border border-red-700 rounded-xl p-4 flex items-start gap-3 animate-fade-in">
      <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
      <div>
        <p className="text-sm font-semibold text-red-300">Analysis Error</p>
        <p className="text-sm text-red-400 mt-1">{message}</p>
      </div>
    </div>
  )
}

// ─── Key-Value Row ─────────────────────────────────────────────────────────
export function KVRow({ label, value, mono = false, className }) {
  return (
    <div className={clsx('grid grid-cols-[160px_1fr] gap-2 text-sm py-1.5 border-b border-dark-800 last:border-0', className)}>
      <span className="text-gray-400 font-medium">{label}</span>
      <span className={clsx(mono ? 'font-mono text-cyber-300' : 'text-gray-200', 'break-all')}>
        {value || <span className="text-gray-500 italic">—</span>}
      </span>
    </div>
  )
}

// ─── Recommendations ───────────────────────────────────────────────────────
export function RecommendationList({ recommendations = [] }) {
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
  const sorted = [...recommendations].sort(
    (a, b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9)
  )
  const badgeClass = {
    Critical: 'badge-critical',
    High: 'badge-high',
    Medium: 'badge-medium',
    Low: 'badge-low',
  }
  return (
    <ul className="space-y-3">
      {sorted.map((r, i) => (
        <li key={i} className="bg-dark-800 rounded-lg p-4 border border-dark-700 hover:border-dark-600 transition-colors">
          <div className="flex items-start gap-3">
            <span className="text-xl leading-none">{r.icon}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <p className="text-sm font-semibold text-gray-100">{r.title}</p>
                <span className={badgeClass[r.priority] || 'badge-low'}>{r.priority}</span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">{r.detail}</p>
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}
