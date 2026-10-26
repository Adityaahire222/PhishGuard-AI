import { useState, type FormEvent } from 'react'
import {
  Activity, ArrowUpRight, ChevronRight, CircleAlert, CircleCheck,
  CircleHelp, Clock3, Fingerprint, LoaderCircle, LockKeyhole, Mail, ScanSearch,
  Shield, ShieldAlert, ShieldCheck, Sparkles, TriangleAlert, X,
} from 'lucide-react'

type Classification = 'PHISHING' | 'SUSPICIOUS' | 'LEGITIMATE' | 'INCONCLUSIVE'
type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN'
type Detection = {
  classification: Classification
  risk_level: RiskLevel
  indicators: string[]
  explanation: string
  recommended_action: string
}

const MAX_LENGTH = 20_000
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')

function isClassification(value: unknown): value is Classification {
  return value === 'PHISHING' || value === 'SUSPICIOUS' || value === 'LEGITIMATE' || value === 'INCONCLUSIVE'
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return value === 'LOW' || value === 'MEDIUM' || value === 'HIGH' || value === 'UNKNOWN'
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function codePointLength(value: string) {
  return Array.from(value).length
}

function parseDetection(value: unknown): Detection | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  if (!('classification' in value) || !('risk_level' in value) || !('indicators' in value) ||
    !('explanation' in value) || !('recommended_action' in value)) return null
  const candidate = value
  if (
    !isClassification(candidate.classification) ||
    !isRiskLevel(candidate.risk_level) ||
    !isStringArray(candidate.indicators) ||
    typeof candidate.explanation !== 'string' ||
    !candidate.explanation.trim() ||
    typeof candidate.recommended_action !== 'string' ||
    !candidate.recommended_action.trim()
  ) return null

  const inconclusive = candidate.classification === 'INCONCLUSIVE'
  if (inconclusive !== (candidate.risk_level === 'UNKNOWN')) return null

  return {
    classification: candidate.classification,
    risk_level: candidate.risk_level,
    indicators: candidate.indicators,
    explanation: candidate.explanation,
    recommended_action: candidate.recommended_action,
  }
}

const classificationStyle: Record<Classification, { label: string; tone: string; icon: typeof ShieldAlert; note: string }> = {
  PHISHING: { label: 'Phishing', tone: 'danger', icon: ShieldAlert, note: 'Strong signs of deception detected' },
  SUSPICIOUS: { label: 'Suspicious', tone: 'warning', icon: TriangleAlert, note: 'Some warning signs need a closer look' },
  LEGITIMATE: { label: 'Likely legitimate', tone: 'success', icon: ShieldCheck, note: 'No concrete phishing signs identified' },
  INCONCLUSIVE: { label: 'Inconclusive', tone: 'neutral', icon: CircleHelp, note: 'There is not enough evidence to decide' },
}

function App() {
  const [emailText, setEmailText] = useState('')
  const [result, setResult] = useState<Detection | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const trimmedLength = codePointLength(emailText.trim())
  const inputLength = codePointLength(emailText)
  const invalidReason = !trimmedLength
    ? 'Paste an email message to begin the analysis.'
    : inputLength > MAX_LENGTH
      ? `Email text must be ${MAX_LENGTH.toLocaleString()} characters or fewer.`
      : ''

  async function analyzeEmail(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setResult(null)
    if (invalidReason) {
      setError(invalidReason)
      return
    }

    setLoading(true)
    try {
      const response = await fetch(`${API_BASE_URL}/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText }),
      })
      let payload: unknown
      try {
        payload = await response.json()
      } catch {
        payload = null
      }
      if (!response.ok) {
        const detail = payload && typeof payload === 'object' && !Array.isArray(payload) &&
          'detail' in payload && typeof payload.detail === 'string'
          ? payload.detail
          : ''
        throw new Error(detail || `Analysis service returned an error (${response.status}).`)
      }
      const detection = parseDetection(payload)
      if (!detection) throw new Error('The analysis service returned an invalid response. Please try again.')
      setResult(detection)
    } catch (requestError) {
      setError(requestError instanceof TypeError
        ? 'Could not reach the analysis service. Check that the local API is running.'
        : requestError instanceof Error && requestError.message
          ? requestError.message
          : 'Could not reach the analysis service. Check that the local API is running.')
    } finally {
      setLoading(false)
    }
  }

  function clearEmail() {
    setEmailText('')
    setResult(null)
    setError('')
  }

  const resultTone = result ? classificationStyle[result.classification] : null
  const ResultIcon = resultTone?.icon

  return (
    <div className="app-shell min-h-screen text-slate-100">
      <header className="site-header">
        <div className="header-inner">
          <a className="brand" href="#top" aria-label="PhishGuard AI home">
            <span className="brand-mark"><Shield size={21} strokeWidth={2.4} /></span>
            <span className="brand-name">phishguard<span>.ai</span></span>
          </a>
          <div className="header-status" role="status">
            <span className="status-dot" />
            <span>LOCAL ANALYSIS</span>
            <span className="status-divider" />
            <span className="model-caption"><Activity size={14} /> Ollama</span>
          </div>
        </div>
      </header>

      <main id="top" className="main-content">
        <section className="welcome-row" aria-labelledby="page-title">
          <div>
            <div className="eyebrow"><Sparkles size={14} /> EMAIL SECURITY WORKSPACE</div>
            <h1 id="page-title">Know what’s in your inbox.</h1>
            <p className="page-subtitle">Analyze a message for phishing signals with your locally configured AI.</p>
          </div>
          <div className="privacy-chip"><LockKeyhole size={15} /> Private by configuration</div>
        </section>

        <div className="workspace-grid">
          <section className="panel input-panel" aria-labelledby="input-heading">
            <div className="panel-heading">
              <div className="heading-icon"><Mail size={18} /></div>
              <div>
                <h2 id="input-heading">Email to analyze</h2>
                <p>Paste the message content below</p>
              </div>
              <span className="step-tag">01 <ChevronRight size={13} /> INPUT</span>
            </div>

            <form onSubmit={analyzeEmail} noValidate>
              <label htmlFor="email-text" className="sr-only">Email text</label>
              <textarea
                id="email-text"
                value={emailText}
                onChange={(event) => { setEmailText(event.target.value); setError(''); setResult(null) }}
                placeholder={'Paste an email here…\n\nFor the most useful assessment, include the sender, subject, and full message body.'}
                maxLength={MAX_LENGTH * 2}
                aria-describedby="input-hint character-count"
                aria-invalid={Boolean(error && invalidReason)}
              />
              <div className="input-meta">
                <span id="input-hint" className="input-hint"><LockKeyhole size={13} /> Message content is treated as untrusted data</span>
                <span id="character-count" className={inputLength > MAX_LENGTH ? 'count-over' : ''}>
                  {inputLength.toLocaleString()} <span>/ {MAX_LENGTH.toLocaleString()}</span>
                </span>
              </div>
              {error && <div className="error-banner" role="alert"><CircleAlert size={17} /><span>{error}</span></div>}
              <div className="form-actions">
                <button className="clear-button" type="button" onClick={clearEmail} disabled={!emailText && !result && !error}>
                  <X size={16} /> Clear
                </button>
                <button className="analyze-button" type="submit" disabled={loading}>
                  {loading ? <><LoaderCircle className="spin" size={17} /> Analyzing email</> : <><ScanSearch size={17} /> Analyze email <ArrowUpRight size={15} /></>}
                </button>
              </div>
            </form>

            <div className="privacy-note">
              <div className="privacy-note-icon"><Fingerprint size={17} /></div>
              <p><strong>Local model, configured by you.</strong> Email text is sent to the Ollama service configured for this app. Review your local endpoint settings before submitting sensitive messages.</p>
            </div>
          </section>

          <section className={`panel result-panel ${result ? `result-${resultTone?.tone}` : ''}`} aria-labelledby="result-heading" aria-live="polite">
            <div className="panel-heading result-heading">
              <div className="heading-icon result-heading-icon"><Activity size={18} /></div>
              <div>
                <h2 id="result-heading">Analysis report</h2>
                <p>{result ? 'Assessment from the configured model' : 'Your findings will appear here'}</p>
              </div>
              <span className="step-tag">02 <ChevronRight size={13} /> REPORT</span>
            </div>

            {loading ? (
              <div className="result-state loading-state" role="status">
                <div className="loading-orbit"><LoaderCircle className="spin" size={29} /></div>
                <h3>Reading the signals</h3>
                <p>Your message is being assessed by the configured local model.</p>
                <div className="loading-track"><span /></div>
              </div>
            ) : result && resultTone && ResultIcon ? (
              <div className="report-content">
                <div className={`classification-card tone-${resultTone.tone}`}>
                  <div className="classification-icon"><ResultIcon size={24} /></div>
                  <div className="classification-copy">
                    <span className="micro-label">CLASSIFICATION</span>
                    <h3>{resultTone.label}</h3>
                    <p>{resultTone.note}</p>
                  </div>
                  <div className="risk-pill"><span>RISK</span><strong>{result.risk_level}</strong></div>
                </div>

                <div className="report-section">
                  <div className="section-title"><span className="section-marker"><CircleCheck size={15} /></span><h3>Assessment</h3></div>
                  <p className="explanation-text">{result.explanation}</p>
                </div>

                <div className="report-section indicators-section">
                  <div className="section-title"><span className="section-marker"><ScanSearch size={15} /></span><h3>Detected indicators</h3><span className="section-count">{result.indicators?.length ?? 0}</span></div>
                  {result.indicators?.length ? (
                    <ul className="indicator-list">{result.indicators.map((indicator, index) => <li key={`${index}-${indicator}`}><span className="indicator-bullet" />{indicator}</li>)}</ul>
                  ) : <p className="no-indicators">No specific indicators were returned for this message.</p>}
                </div>

                <div className="action-card">
                  <div className="action-icon"><ShieldCheck size={17} /></div>
                  <div><span className="micro-label">RECOMMENDED NEXT STEP</span><p>{result.recommended_action}</p></div>
                </div>
                <p className="model-caveat"><CircleHelp size={13} /> AI-generated assessment; not verified threat intelligence.</p>
              </div>
            ) : error ? (
              <div className="result-state error-state" role="status">
                <div className="empty-illustration"><CircleAlert size={32} /></div>
                <span className="micro-label">ANALYSIS UNAVAILABLE</span>
                <h3>Could not display the analysis</h3>
                <p>{error}</p>
              </div>
            ) : (
              <div className="result-state empty-state">
                <div className="empty-illustration"><div className="empty-orbit orbit-one" /><div className="empty-orbit orbit-two" /><div className="empty-shield"><Shield size={34} /></div><span className="orbit-dot dot-one" /><span className="orbit-dot dot-two" /></div>
                <span className="micro-label">READY WHEN YOU ARE</span>
                <h3>Start with an email</h3>
                <p>Paste a message to see its classification, risk level, and observed indicators.</p>
                <div className="empty-footer"><Clock3 size={14} /> Results appear here after analysis</div>
              </div>
            )}
          </section>
        </div>

        <footer className="page-footer">
          <span><span className="footer-mark"><Shield size={13} /></span> PhishGuard AI <span className="footer-version">· Local email analysis</span></span>
          <span className="footer-disclaimer">Always verify unexpected requests through a trusted channel.</span>
        </footer>
      </main>
    </div>
  )
}

export default App
