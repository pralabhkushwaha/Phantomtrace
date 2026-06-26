import { useEffect, useState } from 'react'
import { Activity, Trash2, Eye, X, Download, Trash } from 'lucide-react'
import { getHistory, getInvestigation, deleteInvestigation, deleteAllHistory } from '../api/client'
import { LoadingSpinner, ErrorBox, RiskBadge, SectionCard } from '../components/UI'

// ─── Plain text report generator ──────────────────────────────────────────
function generateTextReport(inv) {
  const line = (n = 60) => '='.repeat(n)
  const dash = (n = 60) => '-'.repeat(n)
  const now = new Date().toLocaleString()
  const invDate = inv.created_at ? new Date(inv.created_at).toLocaleString() : 'Unknown'

  let r = ''
  r += line() + '\n'
  r += '        PHANTOMTRACE INVESTIGATION REPORT\n'
  r += '     Phishing Detection & Email Forensics Platform\n'
  r += line() + '\n\n'

  r += `Investigation ID   : #${inv.investigation_id}\n`
  r += `Investigation Type : ${(inv.investigation_type || '').toUpperCase()}\n`
  r += `Analysis Date      : ${invDate}\n`
  r += `Report Generated   : ${now}\n`
  r += dash() + '\n\n'

  // Risk Summary
  const risk = inv.risk || {}
  r += 'RISK SUMMARY\n' + dash() + '\n'
  r += `Overall Risk Score : ${risk.total_score ?? 'N/A'}/100\n`
  r += `Risk Level         : ${risk.risk_level ?? 'N/A'}\n\n`

  if (risk.breakdown) {
    r += 'Score Breakdown:\n'
    Object.entries(risk.breakdown).forEach(([mod, pts]) => {
      r += `  ${mod.padEnd(35)} ${pts} pts\n`
    })
    r += '\n'
  }

  if (risk.explanations?.length) {
    r += 'Risk Explanations:\n'
    risk.explanations.forEach(e => { r += `  > ${e}\n` })
    r += '\n'
  }

  // Email Header section
  const header = inv.header || {}
  if (Object.keys(header).length > 0) {
    r += 'EMAIL HEADER ANALYSIS\n' + dash() + '\n'
    r += `From              : ${header.from_raw || '—'}\n`
    r += `To                : ${header.to || '—'}\n`
    r += `Subject           : ${header.subject || '—'}\n`
    r += `Date              : ${header.date || '—'}\n`
    r += `Reply-To          : ${header.reply_to || '—'}\n`
    r += `Return-Path       : ${header.return_path || '—'}\n`
    r += `Originating IP    : ${header.originating_ip || '—'}\n\n`

    const auth = header.authentication || {}
    r += 'Authentication Results:\n'
    r += `  SPF   : ${(auth.spf || 'none').toUpperCase()}\n`
    r += `  DKIM  : ${(auth.dkim || 'none').toUpperCase()}\n`
    r += `  DMARC : ${(auth.dmarc || 'none').toUpperCase()}\n\n`

    if (header.flags?.length) {
      r += 'Detection Flags:\n'
      header.flags.forEach(f => { r += `  [!] ${f}\n` })
      r += '\n'
    }
  }

  // Attribution
  const attr = inv.attribution || {}
  if (attr.country || attr.asn) {
    r += 'SENDER ATTRIBUTION\n' + dash() + '\n'
    r += `Country           : ${attr.country || '—'}\n`
    r += `City/Region       : ${[attr.city, attr.region].filter(Boolean).join(', ') || '—'}\n`
    r += `ISP/Org           : ${attr.isp || '—'}\n`
    r += `ASN               : ${attr.asn || '—'}\n`
    r += `Reverse DNS       : ${attr.reverse_dns || '—'}\n`
    r += `Registrar         : ${attr.registrar || '—'}\n`
    r += `Domain Age        : ${attr.domain_age_days != null ? attr.domain_age_days + ' days' : '—'}\n`
    r += `Hosting Provider  : ${attr.is_hosting_provider ? 'YES (suspicious)' : 'No'}\n\n`
    if (attr.risk_indicators?.length) {
      r += 'Attribution Risk Indicators:\n'
      attr.risk_indicators.forEach(i => { r += `  [!] ${i}\n` })
      r += '\n'
    }
  }

  // Homograph
  const hg = inv.homograph_sender || inv.homograph || {}
  if (hg.domain) {
    r += 'HOMOGRAPH / BRAND IMPERSONATION\n' + dash() + '\n'
    r += `Domain Analyzed   : ${hg.domain}\n`
    r += `Impersonating     : ${hg.impersonating_brand_name || 'None detected'}\n`
    r += `Confidence        : ${hg.confidence > 0 ? hg.confidence + '%' : '—'}\n`
    r += `Punycode/IDN      : ${hg.punycode_detected ? 'YES' : 'No'}\n`
    r += `Mixed Script      : ${hg.mixed_script ? 'YES (Cyrillic/Greek chars)' : 'No'}\n`
    r += `Digit Substitution: ${hg.digit_substitution ? 'YES (0→o, 1→l)' : 'No'}\n`
    if (hg.flags?.length) {
      r += 'Flags:\n'
      hg.flags.forEach(f => { r += `  [!] ${f}\n` })
    }
    r += '\n'
  }

  // Content Analysis
  const content = inv.content || {}
  if (content.risk_level) {
    r += 'CONTENT / FRAUD ANALYSIS\n' + dash() + '\n'
    r += `Risk Score        : ${content.overall_risk_score ?? '—'}/100\n`
    r += `Risk Level        : ${content.risk_level || '—'}\n\n`
    if (content.detected_labels?.length) {
      r += 'Detected Patterns:\n'
      content.detected_labels.forEach(l => { r += `  [!] ${l}\n` })
      r += '\n'
    }
  }

  // URL Intelligence
  const urls = inv.urls || []
  if (inv.url_analysis || urls.length > 0) {
    const ua = inv.url_analysis || (urls.length > 0 ? urls[0] : {})
    r += 'URL INTELLIGENCE\n' + dash() + '\n'
    r += `URL               : ${ua.url || '—'}\n`
    r += `Verdict           : ${ua.verdict || '—'}\n`
    r += `Risk Score        : ${ua.risk_score ?? '—'}/100\n`
    r += `HTTPS             : ${ua.scheme === 'https' ? 'Yes' : 'NO (plain HTTP)'}\n`
    r += `URL Shortened     : ${ua.is_shortened ? 'YES' : 'No'}\n`
    r += `TLD               : ${ua.tld ? '.' + ua.tld : '—'}\n`
    if (ua.flags?.length) {
      r += 'Flags:\n'
      ua.flags.forEach(f => { r += `  [!] ${f}\n` })
    }
    r += '\n'
  }

  // Malware
  if (inv.verdict && inv.md5) {
    r += 'MALWARE ANALYSIS\n' + dash() + '\n'
    r += `Filename          : ${inv.filename || '—'}\n`
    r += `Verdict           : ${inv.verdict}\n`
    r += `MD5               : ${inv.md5 || '—'}\n`
    r += `SHA256            : ${inv.sha256 || '—'}\n`
    r += `Entropy           : ${inv.entropy ?? '—'}/8.0\n`
    r += `Known Malware Hash: ${inv.hash_reputation?.found ? 'YES — ' + inv.hash_reputation.malware_family : 'No'}\n`
    if (inv.flags?.length) {
      r += 'Flags:\n'
      inv.flags.forEach(f => { r += `  [!] ${f}\n` })
    }
    r += '\n'
  }

  // Recommendations
  const recs = inv.recommendations || []
  if (recs.length) {
    r += 'SECURITY RECOMMENDATIONS\n' + dash() + '\n'
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
    const sorted = [...recs].sort((a, b) => (order[a.priority] ?? 9) - (order[b.priority] ?? 9))
    sorted.forEach((rec, i) => {
      r += `${i + 1}. [${rec.priority.toUpperCase()}] ${rec.title}\n`
      r += `   ${rec.detail}\n\n`
    })
  }

  r += line() + '\n'
  r += 'Generated by PhantomTrace — Phishing Detection & Email Forensics Platform\n'
  r += 'https://phantom-trace.netlify.app\n'
  r += line() + '\n'

  return r
}

function downloadTextReport(inv) {
  const text = generateTextReport(inv)
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `PhantomTrace_Investigation_${inv.investigation_id}_${Date.now()}.txt`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ─── Component ────────────────────────────────────────────────────────────
export default function History() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [confirmClearAll, setConfirmClearAll] = useState(false)

  function load() {
    setLoading(true)
    getHistory(100).then(setHistory).catch(e => setError(e.message)).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function viewDetail(id) {
    setDetailLoading(true)
    try {
      const data = await getInvestigation(id)
      setSelected(data)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setDetailLoading(false)
    }
  }

  async function handleDelete(id, e) {
    e.stopPropagation()
    try {
      await deleteInvestigation(id)
      setHistory(h => h.filter(item => item.id !== id))
      if (selected?.investigation_id === id) setSelected(null)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  async function handleClearAll() {
    try {
      await deleteAllHistory()
      setHistory([])
      setSelected(null)
      setConfirmClearAll(false)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  async function handleDownloadReport(id, e) {
    e.stopPropagation()
    try {
      const data = await getInvestigation(id)
      downloadTextReport(data)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message)
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-white">Investigation History</h1>
          <p className="text-sm text-gray-400 mt-1">
            All past analyses stored in the SQLite database. Download any as a .txt report.
          </p>
        </div>
        {history.length > 0 && (
          <div>
            {!confirmClearAll ? (
              <button onClick={() => setConfirmClearAll(true)}
                className="flex items-center gap-2 text-xs bg-red-900/40 hover:bg-red-900/60 border border-red-700 text-red-300 px-3 py-2 rounded-lg transition-colors">
                <Trash className="w-4 h-4" /> Clear All History
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-xs text-red-400">Delete all {history.length} records?</span>
                <button onClick={handleClearAll}
                  className="text-xs bg-red-700 hover:bg-red-600 text-white px-3 py-1.5 rounded-lg">
                  Yes, Delete All
                </button>
                <button onClick={() => setConfirmClearAll(false)}
                  className="text-xs bg-dark-700 text-gray-300 px-3 py-1.5 rounded-lg">
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <ErrorBox message={error} />}

      {loading ? (
        <LoadingSpinner message="Loading investigation history…" />
      ) : history.length === 0 ? (
        <div className="card text-center py-16">
          <Activity className="w-10 h-10 text-dark-500 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">No investigations recorded yet.</p>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-700 bg-dark-800/50">
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">ID</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Type</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Target</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Risk</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase hidden sm:table-cell">Date</th>
                <th className="text-right px-4 py-3 text-xs text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map(h => (
                <tr key={h.id} onClick={() => viewDetail(h.id)}
                  className="border-b border-dark-800 last:border-0 hover:bg-dark-800/40 transition-colors cursor-pointer">
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">#{h.id}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded border uppercase ${h.type === 'malware' ? 'bg-red-900/40 border-red-700 text-red-300' : 'bg-dark-800 border-dark-600 text-cyber-300'}`}>
                      {h.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[200px] truncate">{h.summary}</td>
                  <td className="px-4 py-3"><RiskBadge level={h.risk_level} score={h.risk_score} /></td>
                  <td className="px-4 py-3 text-xs text-gray-500 hidden sm:table-cell">
                    {h.created_at ? new Date(h.created_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={e => { e.stopPropagation(); viewDetail(h.id) }}
                        title="View Details"
                        className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-cyber-400 transition-colors">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button onClick={e => handleDownloadReport(h.id, e)}
                        title="Download .txt Report"
                        className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-green-400 transition-colors">
                        <Download className="w-4 h-4" />
                      </button>
                      <button onClick={e => handleDelete(h.id, e)}
                        title="Delete"
                        className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-red-400 transition-colors">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail modal */}
      {(selected || detailLoading) && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={() => setSelected(null)}>
          <div className="bg-dark-900 border border-dark-700 rounded-xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-bold text-white">
                  Investigation #{selected?.investigation_id}
                  <span className="text-gray-500 text-sm font-normal ml-2">({selected?.investigation_type})</span>
                </h2>
                {selected && (
                  <RiskBadge level={selected?.risk?.risk_level} score={selected?.risk?.total_score} />
                )}
              </div>
              <div className="flex items-center gap-2">
                {selected && (
                  <button onClick={() => downloadTextReport(selected)}
                    className="flex items-center gap-1.5 text-xs bg-green-900/40 hover:bg-green-900/60 border border-green-700 text-green-300 px-3 py-1.5 rounded-lg transition-colors">
                    <Download className="w-3.5 h-3.5" /> Download .txt
                  </button>
                )}
                <button onClick={() => setSelected(null)} className="p-1.5 rounded hover:bg-dark-800 text-gray-400">
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {detailLoading ? (
              <LoadingSpinner message="Loading details…" />
            ) : selected && (
              <div className="space-y-4">
                {/* Quick summary */}
                {selected.risk?.explanations?.length > 0 && (
                  <div className="bg-dark-800 rounded-lg p-3 space-y-1">
                    {selected.risk.explanations.map((e, i) => (
                      <p key={i} className="text-xs text-gray-300 flex gap-2">
                        <span className="text-cyber-400">▸</span> {e}
                      </p>
                    ))}
                  </div>
                )}

                <SectionCard title="Raw JSON Result">
                  <pre className="text-xs font-mono text-gray-400 whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                    {JSON.stringify(selected, null, 2)}
                  </pre>
                </SectionCard>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
