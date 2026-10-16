import { useEffect, useRef, useState } from 'react'
import {
  Activity, ArrowDownRight, ArrowLeft, ArrowRight, ArrowUpRight, BadgeCheck,
  BarChart3, BookOpen, Check, ChevronDown, CircleAlert, CircleHelp, Clock3,
  ExternalLink, FileText, Fingerprint, Globe2, History, Link2, LoaderCircle,
  LockKeyhole, LogOut, Menu, QrCode, ScanLine, Shield, ShieldAlert, ShieldCheck,
  ShieldX, Sparkles, Upload, UserRound, X,
} from 'lucide-react'
import { api, postJson } from './api'

const NAV = [
  { label: 'Overview', icon: BarChart3 },
  { label: 'URL scanner', icon: ScanLine },
  { label: 'Message scan', icon: FileText },
  { label: 'QR scanner', icon: QrCode },
  { label: 'Scan history', icon: History },
]

const verdictMeta = {
  safe: { label: 'Likely safe', tone: 'safe', icon: ShieldCheck },
  suspicious: { label: 'Suspicious', tone: 'warning', icon: ShieldAlert },
  phishing: { label: 'High risk', tone: 'danger', icon: ShieldX },
}

function App() {
  const [page, setPage] = useState('URL scanner')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [accessToken, setAccessToken] = useState(() => localStorage.getItem('signalguard.access'))
  const [mobileNav, setMobileNav] = useState(false)

  function navigate(nextPage) {
    setPage(nextPage)
    setError('')
    setMobileNav(false)
  }

  async function runScan(path, payload) {
    setBusy(true)
    setError('')
    try {
      const data = await postJson(path, payload)
      setResult(data)
      setPage('result')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  function onLogin(tokens) {
    localStorage.setItem('signalguard.access', tokens.access)
    localStorage.setItem('signalguard.refresh', tokens.refresh)
    setAccessToken(tokens.access)
    setPage('Overview')
    setError('')
  }

  function logout() {
    localStorage.removeItem('signalguard.access')
    localStorage.removeItem('signalguard.refresh')
    setAccessToken(null)
    navigate('URL scanner')
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <a className="brand-lockup" href="#home" onClick={(event) => { event.preventDefault(); navigate('URL scanner') }}>
          <span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
          <span className="brand-name">signal<span>guard</span></span>
          <span className="brand-version">BETA</span>
        </a>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {NAV.map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-item ${page === label ? 'nav-active' : ''}`} onClick={() => navigate(label)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {label === 'URL scanner' && <span className="nav-live" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-rule" />
          <div className="workspace-label">RESOURCES</div>
          <button className={`nav-item ${page === 'Browser extension' ? 'nav-active' : ''}`} onClick={() => navigate('Browser extension')}>
            <ExternalLink size={17} strokeWidth={1.8} /><span>Browser extension</span>
          </button>
          <button className={`nav-item ${page === 'About' ? 'nav-active' : ''}`} onClick={() => navigate('About')}>
            <CircleHelp size={17} strokeWidth={1.8} /><span>About SignalGuard</span>
          </button>
          <div className="sidebar-account">
            <span className="account-avatar"><UserRound size={16} /></span>
            <span className="account-copy"><b>{accessToken ? 'Signed in' : 'Guest session'}</b><small>{accessToken ? 'Personal workspace' : 'Scans are not saved to an account'}</small></span>
            {accessToken ? <><button className="icon-quiet" aria-label="Profile" title="Profile" onClick={() => navigate('Profile')}><UserRound size={15} /></button><button className="icon-quiet" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={16} /></button></> : <button className="sign-in-link" onClick={() => navigate('Account')}>Sign in</button>}
          </div>
        </div>
      </aside>
      {mobileNav && <button aria-label="Close navigation" className="nav-scrim" onClick={() => setMobileNav(false)} />}
      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu icon-quiet" aria-label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={19} /></button>
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><b>{page === 'result' ? 'Scan result' : page}</b></div>
          <div className="topbar-right">
            <span className="system-status">URL-only analysis</span>
            <button className="help-button" aria-label="About SignalGuard" onClick={() => navigate('About')}><CircleHelp size={17} /></button>
          </div>
        </header>
        <div className="page-content">
          {error && <div className="error-banner" role="alert"><CircleAlert size={17} />{error}<button onClick={() => setError('')} aria-label="Dismiss"><X size={15} /></button></div>}
          {page === 'URL scanner' && <ScannerPage onScan={(url) => runScan('/scan/', { url })} busy={busy} />}
          {page === 'Overview' && <DashboardPage authenticated={Boolean(accessToken)} onLogin={() => navigate('Account')} onOpenScan={(scan) => { setResult(scan); navigate('result') }} onNavigate={navigate} />}
          {page === 'Message scan' && <MessagePage onResult={(scan) => { setResult(scan); setPage('result') }} />}
          {page === 'QR scanner' && <QRPage onScan={(url) => runScan('/scan/qr/', { decoded_url: url })} busy={busy} />}
          {page === 'Scan history' && <HistoryPage authenticated={Boolean(accessToken)} onLogin={() => navigate('Account')} onOpen={(scan) => { setResult(scan); navigate('result') }} />}
          {page === 'result' && result && <ResultPage result={result} authenticated={Boolean(accessToken)} onBack={() => navigate('URL scanner')} />}
          {page === 'Account' && <AccountPage onLogin={onLogin} onCancel={() => navigate('URL scanner')} />}
          {page === 'Browser extension' && <ExtensionPage />}
          {page === 'About' && <AboutPage />}
          {page === 'Profile' && <ProfilePage authenticated={Boolean(accessToken)} onLogin={() => navigate('Account')} />}
        </div>
      </main>
    </div>
  )
}

function PageHeading({ eyebrow, title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>
}

function ScannerPage({ onScan, busy }) {
  const [url, setUrl] = useState('')
  const [localError, setLocalError] = useState('')
  function submit(event) {
    event.preventDefault()
    let value = url.trim()
    if (!value) return setLocalError('Paste a URL to start the check.')
    if (!/^https?:\/\//i.test(value)) value = `https://${value}`
    try {
      const parsed = new URL(value)
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname.includes('.')) throw new Error()
    } catch {
      return setLocalError('Enter a valid web address, such as example.com.')
    }
    setLocalError('')
    onScan(value)
  }
  return (
    <>
      <PageHeading eyebrow="LINK INTELLIGENCE" title="Check a link before you click." description="Inspect a URL for phishing signals, domain tricks and suspicious structure." />
      <section className="scan-panel">
        <div className="panel-topline"><div className="panel-icon"><ScanLine size={17} /></div><div><b>Single URL analysis</b><span>HTTP and HTTPS links supported</span></div><span className="panel-step">01 <span>/</span> 01</span></div>
        <form className="scan-form" onSubmit={submit}>
          <label htmlFor="scan-url">Website address</label>
          <div className="url-input-wrap"><Link2 size={18} /><input id="scan-url" type="text" inputMode="url" autoComplete="url" placeholder="https://website.com/path" value={url} onChange={(event) => { setUrl(event.target.value); setLocalError('') }} /><button className="paste-button" type="button" onClick={async () => { try { setUrl(await navigator.clipboard.readText()) } catch { setLocalError('Clipboard access is not available. Paste the link into the field.') } }}>Paste</button></div>
          {localError && <span className="field-error">{localError}</span>}
          <div className="form-footer"><span><LockKeyhole size={13} /> The page is not opened or fetched</span><button className="button-primary" type="submit" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={16} /> Checking</> : <>Analyze URL <ArrowRight size={16} /></>}</button></div>
        </form>
        <div className="scan-note"><ShieldCheck size={16} /><p>Analysis runs on URL structure and an optional trained model. A low-risk result is not a guarantee that a website is safe.</p></div>
      </section>
      <div className="lower-grid">
        <section className="content-section"><div className="section-heading"><div><h2>What we inspect</h2><p>Signals used to assess the URL, without visiting it.</p></div><span className="quiet-tag"><Fingerprint size={13} /> URL-only</span></div><div className="inspection-list"><div><span className="inspection-icon green"><Globe2 size={16} /></span><span><b>Domain structure</b><small>Subdomains, IP hosts, unusual suffixes</small></span></div><div><span className="inspection-icon blue"><Activity size={16} /></span><span><b>URL patterns</b><small>Length, symbols, entropy and keywords</small></span></div><div><span className="inspection-icon amber"><Sparkles size={16} /></span><span><b>Brand similarity</b><small>Common brand lookalikes and typosquats</small></span></div></div></section>
        <aside className="notice-panel"><div className="notice-mark"><Shield size={19} /></div><div><b>Privacy by design</b><p>SignalGuard never opens the submitted site. Content and screenshot analysis are not enabled in this build.</p><button onClick={() => setTimeout(() => document.querySelector('#scan-url')?.focus(), 0)}>Understood <ArrowRight size={14} /></button></div></aside>
      </div>
      <p className="page-footnote"><CircleHelp size={13} /> URL inspection helps surface warning signs. It cannot confirm that a site or its content is safe.</p>
    </>
  )
}

function ResultPage({ result, authenticated, onBack }) {
  const [feedback, setFeedback] = useState('')
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false)
  const [feedbackBusy, setFeedbackBusy] = useState(false)
  const meta = verdictMeta[result.verdict] || verdictMeta.suspicious
  const VerdictIcon = meta.icon
  const features = result.features || {}
  const indicators = [
    { warn: !features.uses_https, label: features.uses_https ? 'HTTPS connection' : 'No HTTPS detected' },
    { warn: features.brand_lookalike, label: features.brand_lookalike ? `Possible ${features.suspected_brand} impersonation` : 'No known brand lookalike found' },
    { warn: features.suspicious_keyword_count > 0, label: features.suspicious_keyword_count ? `${features.suspicious_keyword_count} suspicious keyword${features.suspicious_keyword_count > 1 ? 's' : ''}` : 'No suspicious keywords found' },
    { warn: features.subdomain_count > 1, label: `${features.subdomain_count} subdomain${features.subdomain_count === 1 ? '' : 's'}` },
    { warn: features.has_ip_address, label: features.has_ip_address ? 'IP address used as host' : 'Hostname is a domain name' },
    { warn: features.suspicious_tld, label: features.suspicious_tld ? `Unusual .${features.domain_suffix} domain suffix` : `.${features.domain_suffix || 'domain'} suffix` },
  ]

  async function sendFeedback(isCorrect) {
    setFeedbackBusy(true)
    try {
      await postJson('/feedback/', { scan_id: result.id, prediction_correct: isCorrect })
      setFeedback(isCorrect ? 'Thanks, your feedback was recorded.' : 'Thanks. Your report is saved for review.')
      setFeedbackSubmitted(true)
    } catch (error) {
      setFeedback(error.message)
    } finally {
      setFeedbackBusy(false)
    }
  }

  return (
    <>
      <button className="back-link" onClick={onBack}><ArrowLeft size={15} /> Back to scanner</button>
      <PageHeading eyebrow="ANALYSIS COMPLETE" title="Scan result" description="A URL-level assessment. The website itself was not opened." />
      <section className={`verdict-banner tone-${meta.tone}`}><div className="verdict-symbol"><VerdictIcon size={25} /></div><div className="verdict-copy"><div className="verdict-overline">{meta.label.toUpperCase()}</div><h2>{result.verdict === 'phishing' ? 'Do not trust this link' : result.verdict === 'suspicious' ? 'Treat this link with caution' : 'No strong warning signs found'}</h2><p className="result-url">{result.url}</p></div><div className="risk-block"><span>Risk score</span><b>{result.risk_score}<small>%</small></b><div className="risk-track"><i style={{ width: `${result.risk_score}%` }} /></div></div></section>
      <div className="result-grid">
        <section className="result-section"><div className="section-heading"><div><h2>Why this URL was flagged</h2><p>{result.analysis_mode === 'hybrid' ? 'Rule findings and model associations learned from its training data.' : 'Readable signals from the submitted link.'}</p></div><span className={`mode-pill ${result.analysis_mode === 'hybrid' ? 'mode-model' : ''}`}>{result.analysis_mode === 'hybrid' ? 'MODEL + RULES' : 'RULE-BASED'}</span></div><div className="reason-list">{(result.reasons || []).map((reason, index) => <div className="reason-row" key={`${reason}-${index}`}><span className="reason-number">{String(index + 1).padStart(2, '0')}</span><span>{reason}</span><ArrowUpRight size={14} /></div>)}{(result.model_explanations || []).map((reason, index) => <div className="reason-row" key={`model-${reason}`}><span className="reason-number">M{index + 1}</span><span>{reason} was associated with a higher phishing score in the training data.</span><ArrowUpRight size={14} /></div>)}</div><div className="content-state"><CircleHelp size={15} /><span>Content analysis unavailable for this URL. SignalGuard does not fetch or execute remote page content.</span></div></section>
        <section className="result-section indicators-section"><div className="section-heading"><div><h2>URL indicators</h2><p>Observed attributes, not proof of legitimacy.</p></div></div><div className="indicator-list">{indicators.map((indicator) => <div key={indicator.label}><span className={indicator.warn ? 'indicator-warning' : 'indicator-ok'}>{indicator.warn ? <CircleAlert size={15} /> : <Check size={15} />}</span><span>{indicator.label}</span></div>)}</div><div className="feature-chips"><span>Length <b>{features.url_length ?? '—'}</b></span><span>Path <b>{features.path_length ?? '—'}</b></span><span>Query params <b>{features.query_parameter_count ?? '—'}</b></span></div></section>
      </div>
      <section className="recommendation-band"><div className="recommendation-icon"><ShieldAlert size={19} /></div><div><b>Recommended next step</b><p>{(result.recommendations || [])[0] || 'Avoid entering sensitive details on this site.'}</p></div><span className="recommendation-label">SAFETY NOTE</span></section>
      <section className="feedback-row"><div><b>Was this assessment useful?</b><span>{feedback || (authenticated ? 'Feedback is saved for review; it does not automatically train the model.' : 'Feedback is attached to your saved scans when signed in.')}</span></div><div className="feedback-actions"><button disabled={feedbackBusy || feedbackSubmitted} onClick={() => sendFeedback(true)}><Check size={15} /> Correct</button><button disabled={feedbackBusy || feedbackSubmitted} onClick={() => sendFeedback(false)}><X size={15} /> Incorrect</button></div></section>
    </>
  )
}

function DashboardPage({ authenticated, onLogin, onOpenScan, onNavigate }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    if (!authenticated) return
    setLoading(true)
    api('/dashboard/').then(setData).catch((err) => setError(err.message)).finally(() => setLoading(false))
  }, [authenticated])
  if (!authenticated) return <AccountPrompt title="Your workspace, at a glance." copy="Sign in to see your own scan activity and recent links. Guest scans are not included in saved history." onLogin={onLogin} />
  const max = Math.max(1, ...(data?.trends || []).map((day) => day.safe + day.suspicious + day.phishing))
  return <>
    <PageHeading eyebrow="PERSONAL WORKSPACE" title="Overview" description="A clear view of the links you have checked." action={<button className="button-primary" onClick={() => onNavigate('URL scanner')}><ScanLine size={16} /> New scan</button>} />
    {loading && <div className="loading-line"><LoaderCircle className="spin" size={16} /> Loading your scan data</div>}
    {error && <div className="inline-notice"><CircleAlert size={16} />{error}</div>}
    {!loading && data && <>
      <div className="stat-grid"><StatCard label="URLs scanned" value={data.total} icon={Link2} accent="green" detail="Your saved scans" /><StatCard label="Likely safe" value={data.safe} icon={ShieldCheck} accent="mint" detail="No strong URL warnings" /><StatCard label="Suspicious" value={data.suspicious} icon={ShieldAlert} accent="amber" detail="Requires extra caution" /><StatCard label="High risk" value={data.phishing} icon={ShieldX} accent="rose" detail="Flagged by the analysis" /></div>
      <div className="dashboard-panels"><section className="result-section chart-panel"><div className="section-heading"><div><h2>Scan activity</h2><p>Daily scans for the last 7 days</p></div><span className="quiet-tag"><Activity size={13} /> {data.total} total</span></div><div className="chart-area">{data.trends.map((day) => { const total = day.safe + day.suspicious + day.phishing; return <div className="chart-column" key={day.date}><div className="chart-stack" title={`${total} scans`}><i className="bar-safe" style={{ height: `${(day.safe / max) * 110}px` }} /><i className="bar-suspicious" style={{ height: `${(day.suspicious / max) * 110}px` }} /><i className="bar-phishing" style={{ height: `${(day.phishing / max) * 110}px` }} /></div><small>{new Date(`${day.date}T00:00:00`).toLocaleDateString(undefined, { weekday: 'short' })}</small></div> })}</div><div className="chart-legend"><span><i className="legend-safe" />Safe</span><span><i className="legend-suspicious" />Suspicious</span><span><i className="legend-phishing" />High risk</span><span className="avg-risk">Avg. risk <b>{data.average_risk}%</b></span></div></section>
      <section className="result-section recent-panel"><div className="section-heading"><div><h2>Recent scans</h2><p>Your latest URL checks.</p></div><button className="text-action" onClick={() => onNavigate('Scan history')}>View all <ArrowRight size={14} /></button></div><RecentScans scans={data.recent_scans} onOpen={onOpenScan} /></section></div>
    </>}
  </>
}

function StatCard({ label, value, icon: Icon, accent, detail }) {
  return <section className="stat-card"><div className={`stat-icon ${accent}`}><Icon size={17} /></div><span className="stat-label">{label}</span><b className="stat-value">{value}</b><small>{detail}</small></section>
}

function RecentScans({ scans, onOpen }) {
  if (!scans?.length) return <div className="empty-state compact-empty"><div className="empty-icon"><ScanLine size={20} /></div><b>No saved scans yet</b><p>Run a URL check to begin building your history.</p></div>
  return <div className="recent-list">{scans.map((scan) => { const meta = verdictMeta[scan.verdict] || verdictMeta.suspicious; return <button className="recent-item" key={scan.id} onClick={() => onOpen(scan)}><span className={`recent-status status-${meta.tone}`}><Shield size={14} /></span><span className="recent-url"><b>{scan.url}</b><small>{new Date(scan.created_at).toLocaleString()}</small></span><span className="recent-risk">{scan.risk_score}%</span><ArrowRight className="recent-arrow" size={14} /></button> })}</div>
}

function HistoryPage({ authenticated, onLogin, onOpen }) {
  const [scans, setScans] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { if (authenticated) api('/history/').then(setScans).catch((err) => setError(err.message)) }, [authenticated])
  if (!authenticated) return <AccountPrompt title="Keep a record of your checks." copy="Sign in to save scan results and review their explanations later." onLogin={onLogin} />
  return <><PageHeading eyebrow="YOUR ACTIVITY" title="Scan history" description="Review the URL checks associated with your account." />{error && <div className="inline-notice"><CircleAlert size={16} />{error}</div>}{!scans ? <div className="loading-line"><LoaderCircle className="spin" size={16} /> Loading history</div> : scans.length ? <div className="history-table-wrap"><table className="history-table"><thead><tr><th>URL</th><th>Verdict</th><th>Risk</th><th>Date checked</th><th /></tr></thead><tbody>{scans.map((scan) => { const meta = verdictMeta[scan.verdict] || verdictMeta.suspicious; return <tr key={scan.id}><td><span className="history-url">{scan.url}</span><small>{scan.reasons?.[0] || 'No strong URL warning signs.'}</small></td><td><span className={`table-status status-${meta.tone}`}><i />{meta.label}</span></td><td className="history-score">{scan.risk_score}%</td><td className="history-date">{new Date(scan.created_at).toLocaleString()}</td><td><button className="row-open" aria-label="Open scan details" onClick={() => onOpen(scan)}><ArrowUpRight size={16} /></button></td></tr> })}</tbody></table></div> : <div className="empty-state"><div className="empty-icon"><History size={20} /></div><b>Your history is clear</b><p>Signed-in scans will appear here.</p></div>}</>
}

function MessagePage({ onResult }) {
  const [text, setText] = useState('')
  const [results, setResults] = useState(null)
  const [localError, setLocalError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event) {
    event.preventDefault()
    if (!text.trim()) return setLocalError('Paste a message to find its links.')
    setLocalError('')
    setBusy(true)
    try {
      const response = await postJson('/scan/text/', { text })
      setResults(response.results)
    } catch (error) {
      setLocalError(error.message)
    } finally {
      setBusy(false)
    }
  }
  return <><PageHeading eyebrow="MESSAGE TRIAGE" title="Check links in a message." description="Paste an email, SMS or chat message to inspect each link it contains." /><div className="workflow-grid"><section className="scan-panel message-panel"><form onSubmit={submit}><label htmlFor="message-content">Message content</label><textarea id="message-content" rows="9" maxLength="20000" placeholder="Paste the message here…" value={text} onChange={(event) => setText(event.target.value)} /><div className="textarea-footer"><span>{text.length.toLocaleString()} / 20,000</span><span>Up to 20 unique links are analyzed</span></div>{localError && <span className="field-error">{localError}</span>}<div className="form-footer"><span><LockKeyhole size={13} /> Message text is not stored</span><button className="button-primary" disabled={busy} type="submit">{busy ? <LoaderCircle className="spin" size={16} /> : <ScanLine size={16} />} Find and scan links</button></div></form></section><aside className="message-side"><div className="notice-mark"><FileText size={18} /></div><h3>Link-by-link review</h3><p>Detected URLs are assessed using the same analysis as a single-link scan. Message urgency and writing style are not evaluated.</p><div className="message-check"><Check size={14} />Distinct links are deduplicated</div><div className="message-check"><Check size={14} />Maximum 20 URLs per message</div></aside></div>{results && <section className="result-section message-results"><div className="section-heading"><div><h2>Detected links <span className="count-badge">{results.length}</span></h2><p>Each result is from the URL analysis pipeline.</p></div></div><RecentScans scans={results} onOpen={onResult} /></section>}</>
}

function QRPage({ onScan, busy }) {
  const videoRef = useRef(null)
  const controlsRef = useRef(null)
  const [camera, setCamera] = useState(false)
  const [error, setError] = useState('')
  const [decoding, setDecoding] = useState(false)
  async function startCamera() {
    setError('')
    setCamera(true)
    try {
      const { BrowserQRCodeReader } = await import('@zxing/browser')
      const reader = new BrowserQRCodeReader()
      controlsRef.current = await reader.decodeFromVideoDevice(undefined, videoRef.current, (result) => {
        if (!result) return
        controlsRef.current?.stop()
        setCamera(false)
        onScan(result.getText())
      })
    } catch {
      setCamera(false)
      setError('Camera access was unavailable. Upload a QR image instead.')
    }
  }
  async function uploadImage(event) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type) || file.size > 5 * 1024 * 1024) {
      return setError('Choose a PNG, JPEG or WebP image under 5 MB.')
    }
    setDecoding(true)
    setError('')
    try {
      const { BrowserQRCodeReader } = await import('@zxing/browser')
      const reader = new BrowserQRCodeReader()
      const imageUrl = URL.createObjectURL(file)
      let decoded
      try {
        decoded = await reader.decodeFromImageUrl(imageUrl)
      } finally {
        URL.revokeObjectURL(imageUrl)
      }
      onScan(decoded.getText())
    } catch {
      setError('No readable QR code was found in this image.')
    } finally {
      setDecoding(false)
    }
  }
  useEffect(() => () => controlsRef.current?.stop(), [])
  return <><PageHeading eyebrow="QR SAFETY" title="Scan a QR code before you go." description="Decode a link from an image or camera, then run it through the same URL checks." /><div className="qr-layout"><section className="qr-stage">{camera ? <div className="camera-view"><video ref={videoRef} muted playsInline /><div className="scan-frame" /><button className="camera-stop" onClick={() => { controlsRef.current?.stop(); setCamera(false) }}><X size={15} /> Stop camera</button></div> : <div className="qr-placeholder"><div className="qr-illustration"><QrCode size={43} strokeWidth={1.3} /><span><ScanLine size={18} /></span></div><b>Drop in a QR image</b><p>PNG, JPEG or WebP · 5 MB max</p><label className="button-secondary upload-button"><Upload size={16} /> {decoding ? 'Reading image…' : 'Choose image'}<input type="file" accept="image/png,image/jpeg,image/webp" onChange={uploadImage} disabled={decoding || busy} /></label><button className="camera-link" onClick={startCamera}><ScanLine size={15} /> Use camera</button></div>}{error && <div className="qr-error"><CircleAlert size={15} />{error}</div>}{busy && <div className="loading-line qr-loading"><LoaderCircle className="spin" size={16} /> Analyzing decoded link</div>}</section><aside className="qr-aside"><span className="eyebrow">QUISHING DEFENSE</span><h2>One scan.<br />The same checks.</h2><p>The QR is decoded in your browser. Only its extracted text is sent for URL analysis; the image itself is not uploaded.</p><div className="qr-steps"><div><span>1</span><b>Decode locally</b><small>Image processing stays in this browser.</small></div><div><span>2</span><b>Inspect the URL</b><small>Signals and risk score match a standard scan.</small></div><div><span>3</span><b>Choose carefully</b><small>No decoded link opens automatically.</small></div></div></aside></div></>
}

function AccountPrompt({ title, copy, onLogin }) {
  return <><PageHeading eyebrow="PERSONAL WORKSPACE" title={title} description={copy} /><section className="account-prompt"><span className="account-prompt-icon"><UserRound size={22} /></span><div><b>Sign in to continue</b><p>Accounts keep scan history private and let you review the activity dashboard.</p></div><button className="button-primary" onClick={onLogin}>Sign in <ArrowRight size={15} /></button></section></>
}

function AccountPage({ onLogin, onCancel }) {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (mode === 'register') await postJson('/auth/register/', { username, email, password })
      const tokens = await postJson('/auth/token/', { username, password })
      onLogin(tokens)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return <><button className="back-link" onClick={onCancel}><ArrowLeft size={15} /> Back to scanner</button><div className="auth-layout"><section className="auth-panel"><div className="auth-symbol"><Shield size={21} /></div><div className="eyebrow">SIGNALGUARD ACCOUNT</div><h1>{mode === 'login' ? 'Welcome back.' : 'Create your account.'}</h1><p>Sign in to keep your scan history private and accessible across sessions.</p><div className="auth-tabs"><button className={mode === 'login' ? 'auth-tab-active' : ''} onClick={() => { setMode('login'); setError('') }}>Sign in</button><button className={mode === 'register' ? 'auth-tab-active' : ''} onClick={() => { setMode('register'); setError('') }}>Register</button></div><form onSubmit={submit} className="auth-form"><label htmlFor="account-username">Username</label><input id="account-username" required autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />{mode === 'register' && <><label htmlFor="account-email">Email address</label><input id="account-email" type="email" required autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} /></>}<label htmlFor="account-password">Password</label><input id="account-password" type="password" required minLength={mode === 'register' ? 10 : undefined} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={(event) => setPassword(event.target.value)} />{mode === 'register' && <small className="password-hint">Use at least 10 characters.</small>}{error && <span className="field-error">{error}</span>}<button className="button-primary auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />}{mode === 'login' ? 'Sign in' : 'Create account'}</button></form><span className="auth-footnote"><LockKeyhole size={13} /> Passwords are hashed by Django. Sessions use JWT.</span></section><aside className="auth-aside"><div className="auth-aside-mark"><ShieldCheck size={23} /></div><span className="eyebrow">A CLEARER SIGNAL</span><h2>Keep the link.<br />Skip the guesswork.</h2><p>Review the reasoning behind each URL check, not just the score.</p></aside></div></>
}

function ExtensionPage() {
  return <><PageHeading eyebrow="BROWSER PROTECTION" title="A second look, right in the browser." description="A small Chromium extension prototype that checks a selected link before you open it." action={<a className="button-secondary extension-download" href="/extension.zip" download><Upload size={15} /> Extension package</a>} /><section className="extension-intro"><div className="extension-visual"><div className="extension-browser"><div className="browser-dots"><i /><i /><i /><span /></div><div className="browser-page-lines"><i /><i /><i /><i /></div><div className="extension-popup"><span className="brand-mark"><Shield size={14} /></span><b>SignalGuard</b><span className="popup-warning"><ShieldAlert size={14} /> Suspicious link</span><button>Review before opening</button></div></div></div><div className="extension-copy"><span className="eyebrow">MANIFEST V3 · CHROMIUM</span><h2>Control stays with you.</h2><p>Use the context menu to scan a link. High-risk links are never blocked silently; the extension offers an explicit option to continue.</p><div className="extension-points"><div><Check size={15} />Selected-link scanning</div><div><Check size={15} />Risk and reason summary</div><div><Check size={15} />User-controlled open action</div></div><div className="extension-setup">Local API expected at <code>127.0.0.1:8000</code></div></div></section><div className="extension-caveat"><CircleAlert size={16} /><span>Prototype only. The extension sends selected URLs to your local SignalGuard API. Review permissions and configure the API address before installing.</span></div></>
}

function AboutPage() {
  return <><PageHeading eyebrow="ABOUT THE PROJECT" title="Clear signals, no false certainty." description="SignalGuard is a student project for inspecting suspicious links without opening them." /><div className="about-layout"><section className="result-section about-main"><div className="about-mark"><Shield size={21} /></div><h2>Risk is a signal, not a verdict.</h2><p>The scanner looks at URL structure, suspicious words, hostname composition and common brand lookalikes. If a Random Forest model has been trained from a labeled dataset, its output is combined with those rule checks.</p><p>Until a model artifact exists, results are explicitly marked <b>rule-based</b>. A low score is not a guarantee that a site is legitimate.</p></section><div className="about-details"><div><span>01</span><b>Does not visit links</b><p>No website HTML, scripts or redirects are fetched during a scan.</p></div><div><span>02</span><b>Explains its reasoning</b><p>Reasons describe visible URL properties, not claims about page content.</p></div><div><span>03</span><b>Feedback is reviewed</b><p>User feedback is stored for review and never triggers automatic retraining.</p></div></div></div></>
}

function ProfilePage({ authenticated, onLogin }) {
  const [profile, setProfile] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => { if (authenticated) api('/profile/').then(setProfile).catch((err) => setError(err.message)) }, [authenticated])
  if (!authenticated) return <AccountPrompt title="Your profile." copy="Sign in to view your account details." onLogin={onLogin} />
  return <><PageHeading eyebrow="ACCOUNT" title="Profile" description="Your SignalGuard account details." />{error && <div className="inline-notice">{error}</div>}{profile && <section className="profile-panel"><span className="account-avatar large-avatar"><UserRound size={21} /></span><div><span className="eyebrow">USERNAME</span><b>{profile.username}</b></div><div><span className="eyebrow">EMAIL</span><b>{profile.email || 'No email provided'}</b></div><div><span className="eyebrow">DATA</span><b>Private account history</b></div></section>}</>
}

export default App