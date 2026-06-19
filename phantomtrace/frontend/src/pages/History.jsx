import { useEffect, useState } from 'react'
import { Activity, Trash2, Eye, X } from 'lucide-react'
import { getHistory, getInvestigation, deleteInvestigation } from '../api/client'
import { LoadingSpinner, ErrorBox, RiskBadge, SectionCard } from '../components/UI'

export default function History() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)

  function load() {
    setLoading(true)
    getHistory(50).then(setHistory).catch(e => setError(e.message)).finally(() => setLoading(false))
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

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Investigation History</h1>
        <p className="text-sm text-gray-400 mt-1">
          All past email, domain, URL, and content analyses stored in the local SQLite database.
        </p>
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
                <tr key={h.id}
                  onClick={() => viewDetail(h.id)}
                  className="border-b border-dark-800 last:border-0 hover:bg-dark-800/40 transition-colors cursor-pointer">
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">#{h.id}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono bg-dark-800 border border-dark-600 px-2 py-0.5 rounded text-cyber-300 uppercase">
                      {h.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 max-w-[220px] truncate">{h.summary}</td>
                  <td className="px-4 py-3"><RiskBadge level={h.risk_level} score={h.risk_score} /></td>
                  <td className="px-4 py-3 text-xs text-gray-500 hidden sm:table-cell">
                    {h.created_at ? new Date(h.created_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => viewDetail(h.id)} className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-cyber-400">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button onClick={(e) => handleDelete(h.id, e)} className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-red-400">
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
              <h2 className="text-lg font-bold text-white">
                Investigation #{selected?.investigation_id} <span className="text-gray-500 text-sm font-normal">({selected?.investigation_type})</span>
              </h2>
              <button onClick={() => setSelected(null)} className="p-1.5 rounded hover:bg-dark-800 text-gray-400">
                <X className="w-5 h-5" />
              </button>
            </div>
            {detailLoading ? (
              <LoadingSpinner message="Loading details…" />
            ) : (
              <div className="space-y-4">
                <RiskBadge level={selected?.risk?.risk_level} score={selected?.risk?.total_score} />
                <SectionCard title="Raw Result (JSON)">
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
