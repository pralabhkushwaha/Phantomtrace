import { useState, useEffect } from 'react'
import { Folder, Plus, X, Edit2, Trash2, Link, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react'
import { getCases, createCase, updateCase, deleteCase, getCase, getHistory, linkInvestigation } from '../api/client'
import { LoadingSpinner, ErrorBox, RiskBadge, SectionCard } from '../components/UI'

const STATUS_COLORS = {
  'Open': 'bg-blue-900/40 border-blue-700 text-blue-300',
  'Under Investigation': 'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  'Closed': 'bg-green-900/40 border-green-700 text-green-300',
  'Referred': 'bg-purple-900/40 border-purple-700 text-purple-300',
}

const PRIORITY_COLORS = {
  'Critical': 'text-red-400', 'High': 'text-orange-400',
  'Medium': 'text-yellow-400', 'Low': 'text-green-400',
}

const CASE_TYPES = [
  'UPI Fraud', 'Digital Arrest Scam', 'OLX/Quickr Scam', 'Banking KYC Fraud',
  'Loan App Harassment', 'SIM Swap Fraud', 'Investment Scam', 'APK Malware',
  'Phishing Email', 'WhatsApp Scam', 'Other',
]

function CaseForm({ initial = {}, onSave, onCancel }) {
  const [form, setForm] = useState({
    case_title: '', fir_number: '', case_type: '', station: '', district: '',
    officer_name: '', officer_rank: '', victim_name: '', victim_phone: '',
    victim_district: '', amount_lost: '', description: '', priority: 'Medium',
    ...initial,
  })
  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }))

  function handleSubmit() {
    if (!form.case_title.trim()) return alert('Case title is required')
    const payload = { ...form, amount_lost: form.amount_lost ? parseFloat(form.amount_lost) : null }
    onSave(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-dark-900 border border-dark-700 rounded-xl max-w-2xl w-full p-6 my-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-white">{initial.id ? 'Edit Case' : 'New Case'}</h2>
          <button onClick={onCancel} className="p-1.5 rounded hover:bg-dark-800 text-gray-400"><X className="w-5 h-5" /></button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="sm:col-span-2">
            <label className="text-xs text-gray-400 mb-1 block">Case Title *</label>
            <input className="input-cyber" placeholder="Brief description of the case" value={form.case_title} onChange={set('case_title')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">FIR Number</label>
            <input className="input-cyber" placeholder="e.g. 123/2026" value={form.fir_number} onChange={set('fir_number')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Case Type</label>
            <select className="input-cyber" value={form.case_type} onChange={set('case_type')}>
              <option value="">Select type</option>
              {CASE_TYPES.map(t => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Police Station</label>
            <input className="input-cyber" placeholder="Station name" value={form.station} onChange={set('station')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">District</label>
            <input className="input-cyber" placeholder="e.g. Amroha" value={form.district} onChange={set('district')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Officer Name</label>
            <input className="input-cyber" placeholder="Investigating officer" value={form.officer_name} onChange={set('officer_name')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Officer Rank</label>
            <input className="input-cyber" placeholder="e.g. SI, Inspector" value={form.officer_rank} onChange={set('officer_rank')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Victim Name</label>
            <input className="input-cyber" placeholder="Complainant name" value={form.victim_name} onChange={set('victim_name')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Victim Phone</label>
            <input className="input-cyber" placeholder="10-digit mobile" value={form.victim_phone} onChange={set('victim_phone')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Amount Lost (INR)</label>
            <input className="input-cyber" type="number" placeholder="0" value={form.amount_lost} onChange={set('amount_lost')} />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Priority</label>
            <select className="input-cyber" value={form.priority} onChange={set('priority')}>
              {['Low','Medium','High','Critical'].map(p => <option key={p}>{p}</option>)}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs text-gray-400 mb-1 block">Case Description</label>
            <textarea className="input-cyber h-24 resize-none" placeholder="Describe the fraud complaint, suspect details, modus operandi…" value={form.description} onChange={set('description')} />
          </div>
        </div>

        <div className="flex gap-3 mt-5 justify-end">
          <button onClick={onCancel} className="btn-secondary">Cancel</button>
          <button onClick={handleSubmit} className="btn-primary">
            <CheckCircle className="w-4 h-4" /> {initial.id ? 'Save Changes' : 'Create Case'}
          </button>
        </div>
      </div>
    </div>
  )
}

function CaseDetail({ caseId, onClose, onEdit }) {
  const [data, setData] = useState(null)
  const [history, setHistory] = useState([])
  const [linking, setLinking] = useState(false)
  const [selectedInv, setSelectedInv] = useState('')

  useEffect(() => {
    getCase(caseId).then(setData)
    getHistory(50).then(setHistory)
  }, [caseId])

  async function handleLink() {
    if (!selectedInv) return
    await linkInvestigation(caseId, parseInt(selectedInv))
    const updated = await getCase(caseId)
    setData(updated)
    setLinking(false)
    setSelectedInv('')
  }

  if (!data) return <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center"><LoadingSpinner /></div>

  const unlinked = history.filter(h => !data.investigations?.find(i => i.id === h.id))

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4 overflow-y-auto" onClick={onClose}>
      <div className="bg-dark-900 border border-dark-700 rounded-xl max-w-3xl w-full p-6 my-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-white">{data.case_title}</h2>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              {data.fir_number && <span className="text-xs font-mono bg-dark-700 px-2 py-0.5 rounded text-cyber-300">FIR: {data.fir_number}</span>}
              <span className={`text-xs border px-2 py-0.5 rounded ${STATUS_COLORS[data.status] || 'bg-dark-700 border-dark-600 text-gray-300'}`}>{data.status}</span>
              <span className={`text-xs font-bold ${PRIORITY_COLORS[data.priority]}`}>{data.priority} Priority</span>
            </div>
          </div>
          <div className="flex gap-2 shrink-0">
            <button onClick={() => onEdit(data)} className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-cyber-400"><Edit2 className="w-4 h-4" /></button>
            <button onClick={onClose} className="p-1.5 rounded hover:bg-dark-700 text-gray-400"><X className="w-5 h-5" /></button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-sm mb-4">
          {[
            ['Case Type', data.case_type], ['Station', data.station], ['District', data.district],
            ['Officer', data.officer_name], ['Rank', data.officer_rank], ['Victim', data.victim_name],
            ['Victim Phone', data.victim_phone], ['Amount Lost', data.amount_lost ? `₹${data.amount_lost.toLocaleString('en-IN')}` : '—'],
          ].map(([label, val]) => val ? (
            <div key={label} className="bg-dark-800 rounded-lg p-2.5">
              <p className="text-xs text-gray-500">{label}</p>
              <p className="text-sm text-gray-200 font-medium mt-0.5">{val}</p>
            </div>
          ) : null)}
        </div>

        {data.description && (
          <div className="bg-dark-800 rounded-lg p-3 mb-4">
            <p className="text-xs text-gray-500 mb-1">Description</p>
            <p className="text-sm text-gray-300">{data.description}</p>
          </div>
        )}

        {/* Linked Investigations */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="section-title mb-0">Linked Investigations ({data.investigations?.length || 0})</p>
            <button onClick={() => setLinking(l => !l)}
              className="text-xs flex items-center gap-1 text-cyber-400 hover:text-cyber-300">
              <Link className="w-3.5 h-3.5" /> Link Investigation
            </button>
          </div>

          {linking && (
            <div className="flex gap-2">
              <select className="input-cyber flex-1 text-xs" value={selectedInv} onChange={e => setSelectedInv(e.target.value)}>
                <option value="">Select investigation to link…</option>
                {unlinked.map(h => (
                  <option key={h.id} value={h.id}>#{h.id} — {h.type.toUpperCase()} — {h.summary?.substring(0,40)} ({h.risk_level})</option>
                ))}
              </select>
              <button onClick={handleLink} className="btn-primary text-xs py-2 px-3">Link</button>
            </div>
          )}

          {data.investigations?.length > 0 ? (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {data.investigations.map(inv => (
                <div key={inv.id} className="flex items-center gap-3 bg-dark-800 rounded-lg p-2.5 border border-dark-700">
                  <span className="text-xs font-mono bg-dark-700 px-2 py-0.5 rounded text-cyber-300 uppercase">{inv.type}</span>
                  <span className="text-xs text-gray-300 flex-1 truncate">{inv.summary}</span>
                  <RiskBadge level={inv.risk_level} score={inv.risk_score} />
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500 italic">No investigations linked yet. Run an analysis and link it here.</p>
          )}
        </div>
      </div>
    </div>
  )
}

export default function CaseManagement() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [editCase, setEditCase] = useState(null)
  const [viewCase, setViewCase] = useState(null)
  const [statusFilter, setStatusFilter] = useState('')

  function load() {
    setLoading(true)
    getCases(statusFilter || null).then(setCases).catch(e => setError(e.message)).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [statusFilter])

  async function handleCreate(data) {
    try {
      await createCase(data)
      setShowForm(false)
      load()
    } catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  async function handleUpdate(data) {
    try {
      await updateCase(editCase.id, data)
      setEditCase(null)
      setViewCase(null)
      load()
    } catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  async function handleDelete(id, e) {
    e.stopPropagation()
    if (!window.confirm('Delete this case? This cannot be undone.')) return
    try {
      await deleteCase(id)
      load()
    } catch (e) { setError(e?.response?.data?.detail || e.message) }
  }

  const stats = {
    total: cases.length,
    open: cases.filter(c => c.status === 'Open').length,
    investigating: cases.filter(c => c.status === 'Under Investigation').length,
    totalLost: cases.reduce((s, c) => s + (c.amount_lost || 0), 0),
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Folder className="w-5 h-5 text-cyber-400" /> Case Management
          </h1>
          <p className="text-sm text-gray-400 mt-1">FIR-linked investigation tracking for UP Police cyber cell.</p>
        </div>
        <button onClick={() => setShowForm(true)} className="btn-primary">
          <Plus className="w-4 h-4" /> New Case
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Cases', value: stats.total, color: 'text-cyber-400' },
          { label: 'Open', value: stats.open, color: 'text-blue-400' },
          { label: 'Under Investigation', value: stats.investigating, color: 'text-yellow-400' },
          { label: 'Total Amount Lost', value: `₹${stats.totalLost.toLocaleString('en-IN')}`, color: 'text-red-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card">
            <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
            <p className={`text-xl font-bold font-mono mt-1 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex gap-2 flex-wrap">
        {['', 'Open', 'Under Investigation', 'Closed', 'Referred'].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${statusFilter === s ? 'bg-cyber-700 border-cyber-600 text-white' : 'bg-dark-800 border-dark-600 text-gray-400 hover:text-gray-200'}`}>
            {s || 'All'}
          </button>
        ))}
      </div>

      {error && <ErrorBox message={error} />}

      {loading ? (
        <LoadingSpinner message="Loading cases…" />
      ) : cases.length === 0 ? (
        <div className="card text-center py-16">
          <Folder className="w-10 h-10 text-dark-500 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">No cases found. Create your first case to get started.</p>
          <button onClick={() => setShowForm(true)} className="btn-primary mx-auto mt-4">
            <Plus className="w-4 h-4" /> Create First Case
          </button>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-dark-700 bg-dark-800/50">
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Case</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase hidden sm:table-cell">FIR No.</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Type</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase hidden md:table-cell">Amount</th>
                <th className="text-left px-4 py-3 text-xs text-gray-500 uppercase">Status</th>
                <th className="text-right px-4 py-3 text-xs text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {cases.map(c => (
                <tr key={c.id} onClick={() => setViewCase(c.id)}
                  className="border-b border-dark-800 last:border-0 hover:bg-dark-800/40 transition-colors cursor-pointer">
                  <td className="px-4 py-3">
                    <p className="text-sm font-medium text-gray-200 truncate max-w-[200px]">{c.case_title}</p>
                    <p className={`text-xs font-bold ${PRIORITY_COLORS[c.priority]}`}>{c.priority}</p>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-cyber-300 hidden sm:table-cell">{c.fir_number || '—'}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">{c.case_type || '—'}</td>
                  <td className="px-4 py-3 text-xs text-red-300 hidden md:table-cell">
                    {c.amount_lost ? `₹${c.amount_lost.toLocaleString('en-IN')}` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs border px-2 py-0.5 rounded ${STATUS_COLORS[c.status] || 'bg-dark-700 border-dark-600 text-gray-300'}`}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={e => { e.stopPropagation(); setEditCase(c) }}
                        className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-cyber-400">
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button onClick={e => handleDelete(c.id, e)}
                        className="p-1.5 rounded hover:bg-dark-700 text-gray-400 hover:text-red-400">
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

      {showForm && <CaseForm onSave={handleCreate} onCancel={() => setShowForm(false)} />}
      {editCase && <CaseForm initial={editCase} onSave={handleUpdate} onCancel={() => setEditCase(null)} />}
      {viewCase && (
        <CaseDetail
          caseId={viewCase}
          onClose={() => setViewCase(null)}
          onEdit={(c) => { setViewCase(null); setEditCase(c) }}
        />
      )}
    </div>
  )
}
