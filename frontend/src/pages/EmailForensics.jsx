import { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, FileText, Server, Shield, Globe, Paperclip, ChevronDown, ChevronUp } from 'lucide-react'
import { analyzeEmailFile, analyzeEmailRaw } from '../api/client'
import {
  LoadingSpinner, ErrorBox, RiskGauge, RiskBadge,
  AuthBadge, FlagList, SectionCard, KVRow, RecommendationList,
} from '../components/UI'

export default function EmailForensics() {
  const [mode, setMode] = useState('paste')       // 'paste' | 'upload'
  const [rawText, setRawText] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [showReceivedChain, setShowReceivedChain] = useState(false)

  const onDrop = useCallback(files => {
    if (files[0]) setFile(files[0])
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'], 'text/plain': ['.txt'] },
    maxFiles: 1,
  })

  async function handleAnalyze() {
    setError(null)
    setResult(null)
    setLoading(true)
    try {
      let res
      if (mode === 'upload' && file) {
        res = await analyzeEmailFile(file)
      } else if (rawText.trim()) {
        res = await analyzeEmailRaw(rawText.trim())
      } else {
        setError('Please upload an .eml file or paste email headers.')
        setLoading(false)
        return
      }
      setResult(res)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  const auth = result?.header?.authentication || {}

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Email Header Forensics</h1>
        <p className="text-sm text-gray-400 mt-1">
          Analyze .eml files or pasted email headers for SPF/DKIM/DMARC, spoofing, and sender attribution.
        </p>
      </div>

      {/* Input card */}
      <div className="card space-y-4">
        {/* Mode toggle */}
        <div className="flex gap-2 bg-dark-800 p-1 rounded-lg w-fit">
          {['paste', 'upload'].map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${
                mode === m
                  ? 'bg-cyber-700 text-white'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {m === 'paste' ? '📋 Paste Headers' : '📁 Upload .eml'}
            </button>
          ))}
        </div>

        {mode === 'paste' ? (
          <textarea
            className="input-cyber h-48 resize-none"
            placeholder="Paste raw email headers or full .eml content here…

Example:
From: support@amazon-secure.xyz
To: victim@gmail.com
Subject: Urgent: Account Verification Required
Received: from mail.xyz-host.ru (123.45.67.89)…"
            value={rawText}
            onChange={e => setRawText(e.target.value)}
          />
        ) : (
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
              isDragActive
                ? 'border-cyber-400 bg-cyber-900/20'
                : 'border-dark-600 hover:border-dark-400'
            }`}
          >
            <input {...getInputProps()} />
            <Upload className="w-8 h-8 text-gray-500 mx-auto mb-3" />
            {file ? (
              <div>
                <p className="text-cyber-300 font-mono text-sm">{file.name}</p>
                <p className="text-gray-500 text-xs mt-1">{(file.size / 1024).toFixed(1)} KB</p>
              </div>
            ) : (
              <div>
                <p className="text-gray-300 font-medium">Drop .eml file here</p>
                <p className="text-gray-500 text-xs mt-1">or click to browse</p>
              </div>
            )}
          </div>
        )}

        <button onClick={handleAnalyze} disabled={loading} className="btn-primary">
          <Shield className="w-4 h-4" />
          {loading ? 'Analyzing…' : 'Analyze Email'}
        </button>
      </div>

      {loading && <LoadingSpinner message="Running forensic analysis…" />}
      {error && <ErrorBox message={error} />}

      {result && (
        <div className="space-y-4 animate-slide-up">
          {/* Risk summary */}
          <div className="card-glow grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
            <div className="flex flex-col items-center">
              <RiskGauge score={result.risk?.total_score ?? 0} />
              <RiskBadge level={result.risk?.risk_level} score={result.risk?.total_score} />
            </div>
            <div className="sm:col-span-2 space-y-2">
              <p className="section-title">Risk Breakdown</p>
              {(result.risk?.explanations || []).map((e, i) => (
                <p key={i} className="text-xs text-gray-300 flex gap-2">
                  <span className="text-cyber-400">▸</span> {e}
                </p>
              ))}
            </div>
          </div>

          {/* Auth checks */}
          <SectionCard title="Authentication Results" icon={Shield}>
            <div className="grid grid-cols-3 gap-3">
              <AuthBadge label="SPF" status={auth.spf} />
              <AuthBadge label="DKIM" status={auth.dkim} />
              <AuthBadge label="DMARC" status={auth.dmarc} />
            </div>
          </SectionCard>

          {/* Header fields */}
          <SectionCard title="Email Header Fields" icon={FileText}>
            <div className="space-y-0.5">
              <KVRow label="From" value={result.header?.from_raw} mono />
              <KVRow label="To" value={result.header?.to} mono />
              <KVRow label="Subject" value={result.header?.subject} />
              <KVRow label="Date" value={result.header?.date} />
              <KVRow label="Reply-To" value={result.header?.reply_to || '—'} mono />
              <KVRow label="Return-Path" value={result.header?.return_path || '—'} mono />
              <KVRow label="Message-ID" value={result.header?.message_id} mono />
              <KVRow label="Originating IP" value={result.header?.originating_ip || '—'} mono />
            </div>
          </SectionCard>

          {/* Flags */}
          <SectionCard title="Detection Flags" icon={Shield}>
            <FlagList flags={result.header?.flags} />
          </SectionCard>

          {/* Attribution */}
          {result.attribution && (
            <SectionCard title="Sender Attribution" icon={Globe}>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-0.5">
                <KVRow label="Country" value={result.attribution.country} />
                <KVRow label="City / Region" value={[result.attribution.city, result.attribution.region].filter(Boolean).join(', ') || '—'} />
                <KVRow label="ISP / Org" value={result.attribution.isp} mono />
                <KVRow label="ASN" value={result.attribution.asn} mono />
                <KVRow label="Reverse DNS" value={result.attribution.reverse_dns} mono />
                <KVRow label="Registrar" value={result.attribution.registrar} />
                <KVRow label="Domain Age" value={result.attribution.domain_age_days != null ? `${result.attribution.domain_age_days} days` : '—'} />
                <KVRow label="Hosting Provider" value={result.attribution.is_hosting_provider ? 'Yes ⚠️' : 'No'} />
              </div>
              {result.attribution.risk_indicators?.length > 0 && (
                <div className="mt-3">
                  <FlagList flags={result.attribution.risk_indicators} />
                </div>
              )}
            </SectionCard>
          )}

          {/* Received chain */}
          {result.header?.received_hops?.length > 0 && (
            <SectionCard title="Received Header Chain" icon={Server}>
              <button
                onClick={() => setShowReceivedChain(v => !v)}
                className="flex items-center gap-2 text-xs text-cyber-400 hover:text-cyber-300 mb-3"
              >
                {showReceivedChain ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                {showReceivedChain ? 'Collapse' : `Show ${result.header.received_hops.length} hops`}
              </button>
              {showReceivedChain && (
                <div className="space-y-2">
                  {result.header.received_hops.map((hop, i) => (
                    <div key={i} className="bg-dark-800 rounded-lg p-3 border border-dark-700">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-cyber-400">Hop {i + 1}</span>
                        {hop.ips?.map(ip => (
                          <span key={ip} className="text-xs font-mono bg-dark-700 px-2 py-0.5 rounded text-yellow-300">{ip}</span>
                        ))}
                      </div>
                      {hop.from_host && <p className="text-xs text-gray-400">From: <span className="text-gray-200 font-mono">{hop.from_host}</span></p>}
                      {hop.by_host && <p className="text-xs text-gray-400">By: <span className="text-gray-200 font-mono">{hop.by_host}</span></p>}
                    </div>
                  ))}
                </div>
              )}
            </SectionCard>
          )}

          {/* Attachments */}
          {result.header?.attachments?.count > 0 && (
            <SectionCard title="Attachments" icon={Paperclip}>
              <div className="space-y-2">
                {result.header.attachments.attachments.map((att, i) => (
                  <div key={i} className="bg-dark-800 rounded-lg p-3 border border-dark-700">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm text-gray-200">{att.filename}</span>
                      <RiskBadge level={att.risk_score >= 30 ? 'High' : att.risk_score > 0 ? 'Medium' : 'Low'} />
                    </div>
                    {att.flags?.length > 0 && (
                      <div className="mt-2">
                        <FlagList flags={att.flags} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          {/* Recommendations */}
          {result.recommendations?.length > 0 && (
            <SectionCard title="Security Recommendations">
              <RecommendationList recommendations={result.recommendations} />
            </SectionCard>
          )}
        </div>
      )}
    </div>
  )
}
