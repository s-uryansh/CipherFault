import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, CreditCard, FileCode2, GitBranch, KeyRound, LogOut, RefreshCw, ScanLine, Settings, Upload } from "lucide-react";
import { api, clearApiKey, getApiKey, setApiKey } from "./api";
import type { AnalysisReport, ApiKeyInfo, Me, ScanStatus, ScanSummary, UsageResponse, VerifiedFact } from "./types";

type Page = "dashboard" | "scan" | "integrations" | "billing" | "settings";

export function App() {
  const [apiKey, setKey] = useState(getApiKey());
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!apiKey) return;
    api.me().then(setMe).catch((err) => setError(String(err.message || err)));
  }, [apiKey]);

  if (!apiKey || !me) {
    return <Login apiKey={apiKey} error={error} onSave={(value) => { setApiKey(value); setKey(value); setError(""); }} />;
  }

  return <Shell me={me} onLogout={() => { clearApiKey(); setKey(""); setMe(null); }} />;
}

function Login({ apiKey, error, onSave }: { apiKey: string; error: string; onSave: (value: string) => void }) {
  const [value, setValue] = useState(apiKey);
  const [status, setStatus] = useState("checking");

  useEffect(() => {
    api.health().then((res) => setStatus(res.ok ? "online" : "offline")).catch(() => setStatus("offline"));
  }, []);

  return (
    <main className="login">
      <section className="login-panel">
        <div className="brand"><span className="mark">C</span><span>CipherFault</span></div>
        <h1>Security scan dashboard</h1>
        <p>Use your API key to upload binaries, track scans, and inspect verified crypto evidence.</p>
        <label>API key</label>
        <input value={value} onChange={(event) => setValue(event.target.value)} placeholder="cf_..." />
        {error && <p className="error">{error}</p>}
        <button onClick={() => onSave(value)} disabled={!value.trim()}>Open dashboard</button>
        <span className={`health ${status}`}>Backend {status}</span>
      </section>
    </main>
  );
}

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const [page, setPage] = useState<Page>("dashboard");
  const [scanId, setScanId] = useState<string | null>(null);

  const openScan = (id: string) => {
    setScanId(id);
    setPage("scan");
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="mark">C</span><span>CipherFault</span></div>
        <div className="org">{me.org_name}<small>{me.tier}</small></div>
        <nav>
          <NavButton icon={<ScanLine />} active={page === "dashboard"} onClick={() => setPage("dashboard")}>Scans</NavButton>
          <NavButton icon={<GitBranch />} active={page === "integrations"} onClick={() => setPage("integrations")}>CI Integrations</NavButton>
          <NavButton icon={<CreditCard />} active={page === "billing"} onClick={() => setPage("billing")}>Usage & Billing</NavButton>
          <NavButton icon={<Settings />} active={page === "settings"} onClick={() => setPage("settings")}>Settings</NavButton>
        </nav>
        <button className="logout" onClick={onLogout}><LogOut size={16} /> Log out</button>
      </aside>
      <main className="main">
        <header className="topbar">
          <div><strong>{title(page)}</strong><span>{me.org_id}</span></div>
          <button onClick={() => location.reload()}><RefreshCw size={16} /> Refresh</button>
        </header>
        <section className="content">
          {page === "dashboard" && <Dashboard me={me} onOpenScan={openScan} />}
          {page === "scan" && <ScanDetail scanId={scanId} />}
          {page === "integrations" && <Integrations />}
          {page === "billing" && <Billing me={me} />}
          {page === "settings" && <SettingsPage me={me} />}
        </section>
      </main>
    </div>
  );
}

function NavButton({ icon, active, children, onClick }: { icon: ReactNode; active: boolean; children: ReactNode; onClick: () => void }) {
  return <button className={active ? "nav active" : "nav"} onClick={onClick}>{icon}{children}</button>;
}

function Dashboard({ me, onOpenScan }: { me: Me; onOpenScan: (id: string) => void }) {
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [message, setMessage] = useState("");

  const refresh = () => Promise.all([api.getUsage(me.org_id).then(setUsage), api.listScans(me.org_id).then(setScans)]).catch((err) => setMessage(String(err.message || err)));

  useEffect(() => { refresh(); }, [me.org_id]);

  async function upload(file: File | undefined) {
    if (!file) return;
    setMessage("Uploading and scanning...");
    try {
      const result = await api.uploadScan(file);
      setMessage(`Scan ${result.status}: ${result.scan_id}`);
      await refresh();
      onOpenScan(result.scan_id);
    } catch (err) {
      setMessage(String((err as Error).message || err));
    }
  }

  const tier1 = scans.reduce((sum, scan) => sum + scan.tier1, 0);
  const tier2 = scans.reduce((sum, scan) => sum + scan.tier2, 0);

  return (
    <>
      <div className="stats">
        <Stat label="Scans this period" value={`${usage?.monthly_used ?? 0}/${usage?.monthly_limit ?? "∞"}`} />
        <Stat label="Verified findings" value={tier1} tone="tier1" />
        <Stat label="Indicators pending" value={tier2} tone="tier2" />
      </div>
      <label className="upload">
        <Upload size={18} />
        Upload ELF binary
        <input type="file" onChange={(event) => upload(event.target.files?.[0])} />
      </label>
      {message && <p className="notice">{message}</p>}
      <ScanTable scans={scans} onOpenScan={onOpenScan} />
    </>
  );
}

function Stat({ label, value, tone = "" }: { label: string; value: string | number; tone?: string }) {
  return <article className="stat"><span>{label}</span><strong className={tone}>{value}</strong></article>;
}

function ScanTable({ scans, onOpenScan }: { scans: ScanSummary[]; onOpenScan: (id: string) => void }) {
  if (scans.length === 0) return <div className="empty"><ScanLine /><strong>No scans yet</strong><span>Upload a binary to start testing.</span></div>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Binary</th><th>Status</th><th>Tier 1</th><th>Tier 2</th><th>Scanned</th></tr></thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} onClick={() => onOpenScan(scan.id)}>
              <td><code>{scan.filename}</code><small>{scan.target_sha256?.slice(0, 12) || scan.id.slice(0, 8)}</small></td>
              <td><StatusBadge status={scan.status} /></td>
              <td className="tier1 mono">{scan.tier1}</td>
              <td className="tier2 mono">{scan.tier2}</td>
              <td>{new Date(scan.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScanDetail({ scanId }: { scanId: string | null }) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [tab, setTab] = useState<"verified" | "indicators">("verified");
  const [cbom, setCbom] = useState("");

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    const tick = async () => {
      const next = await api.getScan(scanId);
      if (cancelled) return;
      setScan(next);
      if (next.status === "complete") {
        setReport(await api.getFindings(scanId));
        setCbom(JSON.stringify(await api.getCbom(scanId), null, 2));
        return;
      }
      if (next.status !== "failed") window.setTimeout(tick, 2000);
    };
    tick().catch(console.error);
    return () => { cancelled = true; };
  }, [scanId]);

  if (!scanId) return <div className="empty"><FileCode2 /><strong>Select a scan</strong></div>;
  if (!scan) return <div className="empty"><RefreshCw /><strong>Loading scan...</strong></div>;

  return (
    <div>
      <div className="scan-head">
        <h2>{scan.filename}</h2>
        <StatusBadge status={scan.status} />
        <code>{report?.target_sha256 || scan.id}</code>
        {scan.error && <p className="error">{scan.error}</p>}
      </div>
      {scan.status !== "complete" && <div className="empty"><RefreshCw /><strong>{scan.status}</strong><span>{scan.stage || "waiting"}</span></div>}
      {report && (
        <>
          <div className="tabs">
            <button className={tab === "verified" ? "on tier1" : ""} onClick={() => setTab("verified")}>VERIFIED ({report.verified_facts.length})</button>
            <button className={tab === "indicators" ? "on tier2" : ""} onClick={() => setTab("indicators")}>INDICATORS ({report.indicators.length})</button>
          </div>
          {tab === "verified" ? report.verified_facts.map((fact, index) => <Finding key={fact.id || index} fact={fact} />) : report.indicators.map((indicator, index) => (
            <article className="finding indicator" key={index}>
              <strong><code>{indicator.primitive || "UNKNOWN"}</code> {indicator.pattern || "Indicator"}</strong>
              <p>{indicator.analyst_question || "Needs analyst review."}</p>
            </article>
          ))}
          <details className="cbom"><summary>CBOM JSON</summary><pre>{cbom}</pre></details>
        </>
      )}
    </div>
  );
}

function Finding({ fact }: { fact: VerifiedFact }) {
  const provenance = fact.provenance || [];
  return (
    <article className="finding verified">
      <div><code>{fact.primitive || "UNKNOWN"}</code>{fact.cwe && <code>{fact.cwe}</code>}<span>{fact.call_addr}</span></div>
      <p>{fact.summary || "Verified crypto evidence."}</p>
      {provenance.length > 0 ? <div className="provenance">{provenance.map((addr) => <code key={addr}>{addr}</code>)}</div> : <small>Provenance path not available for this fact.</small>}
      {fact.analyst_note && <small>{fact.analyst_note}</small>}
    </article>
  );
}

function Billing({ me }: { me: Me }) {
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  useEffect(() => { api.getUsage(me.org_id).then(setUsage).catch(console.error); }, [me.org_id]);
  const pct = usage?.monthly_limit ? Math.min(100, Math.round((usage.monthly_used / usage.monthly_limit) * 100)) : 0;
  return <article className="panel"><h2>Current plan: {usage?.tier || me.tier}</h2><p>{usage?.monthly_used ?? 0} of {usage?.monthly_limit ?? "unlimited"} scans this period</p><div className="bar"><span style={{ width: `${pct}%` }} /></div><p>Stripe billing will be added after the demo scan flow is stable.</p></article>;
}

function Integrations() {
  return <article className="panel"><h2>GitHub CI</h2><pre>{`name: CipherFault\non: [pull_request]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: CipherFault scan\n        run: echo "CI action coming soon"`}</pre></article>;
}

function SettingsPage({ me }: { me: Me }) {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [created, setCreated] = useState("");
  const [name, setName] = useState("dashboard");
  const refresh = () => api.listApiKeys(me.org_id).then(setKeys).catch(console.error);
  useEffect(() => { refresh(); }, [me.org_id]);

  async function create() {
    const result = await api.createApiKey(me.org_id, name);
    setCreated(result.api_key);
    await refresh();
  }

  return (
    <article className="panel">
      <h2>API keys</h2>
      <div className="inline-form"><input value={name} onChange={(event) => setName(event.target.value)} /><button onClick={create}><KeyRound size={16} /> Create key</button></div>
      {created && <p className="notice">Save this key now: <code>{created}</code></p>}
      {keys.map((key) => <div className="key-row" key={key.id}><code>{key.key_prefix || "unknown"}</code><span>{key.name}</span><span>{key.revoked_at ? "revoked" : "active"}</span><button onClick={() => api.revokeApiKey(me.org_id, key.id).then(refresh)}>Revoke</button></div>)}
    </article>
  );
}

function StatusBadge({ status }: { status: string }) {
  const Icon = status === "complete" ? CheckCircle2 : status === "failed" ? AlertTriangle : RefreshCw;
  return <span className={`status ${status}`}><Icon size={14} />{status}</span>;
}

function title(page: Page) {
  return { dashboard: "Scans", scan: "Scan detail", integrations: "CI Integrations", billing: "Usage & Billing", settings: "Settings" }[page];
}
