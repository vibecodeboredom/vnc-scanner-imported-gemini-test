import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  ShieldAlert,
  Terminal,
  Play,
  Square,
  Download,
  Server,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  Zap,
  RefreshCw,
  Search,
  Sliders,
  ExternalLink,
  Copy,
  Check,
  ChevronDown,
  Info,
  Lock,
  Unlock,
  Layers,
  Network,
  Globe,
  Radio,
  HelpCircle,
  Upload,
  FileText,
  Trash2,
  Filter,
  CheckCheck,
  XCircle,
  FileSpreadsheet,
  Sparkles,
  ShieldCheck
} from 'lucide-react';

interface ScanResult {
  ip: string;
  port: number;
  service: string;
  detected: boolean;
  url: string;
  proto: string | null;
  security: string | null;
  auth_success: boolean;
  winner: [string, string] | null;
  error: string | null;
  timestamp?: string;
}

interface ScanProgress {
  scanned: number;
  total: number;
  detected: number;
  authSuccess: number;
  authFailed: number;
  errors: number;
  elapsed: number;
}

interface PortDetail {
  port: number;
  display: string;
}

interface TargetPreview {
  targetsCount: number;
  portsCount: number;
  totalScans: number;
  sampleIps: string[];
  samplePorts: number[];
  detailedPorts?: PortDetail[];
}

interface DemoTarget {
  name: string;
  spec: string;
  ports: string;
  description: string;
}

interface ProxyTestItem {
  id: string;
  raw: string;
  host: string;
  port: number;
  protocol: 'socks5' | 'http' | 'socks4';
  status: 'alive' | 'dead';
  latencyMs?: number;
  error?: string;
  details?: string;
}

export default function App() {
  // Input configuration
  const [targetsText, setTargetsText] = useState<string>('127.0.0.1\n10.0.0.1-5\n192.168.1.0/28');
  const [portsText, setPortsText] = useState<string>('5900, 5901, 5902, 5903, 5904, 5905, 5800, 5801');
  const [checkAuth, setCheckAuth] = useState<boolean>(true);
  const [passwords, setPasswords] = useState<string[]>(['password', 'admin', '123456', 'root', '1234']);
  const [newPassword, setNewPassword] = useState<string>('');
  const [workers, setWorkers] = useState<number>(30);
  const [timeoutSec, setTimeoutSec] = useState<number>(3.0);
  const [onlyFound, setOnlyFound] = useState<boolean>(false);

  // Single & Bulk Proxy Configuration
  const [proxyEnabled, setProxyEnabled] = useState<boolean>(false);
  const [proxyMode, setProxyMode] = useState<'pool' | 'single'>('pool');
  const [proxyType, setProxyType] = useState<'socks5' | 'http' | 'socks4'>('socks5');
  const [proxyUrl, setProxyUrl] = useState<string>('127.0.0.1:1080');

  // Bulk Proxy Tester State
  const [bulkProxiesText, setBulkProxiesText] = useState<string>(
    '# Built-in Local Test Proxies (Running & Ready)\n127.0.0.1:1080\nhttp://127.0.0.1:8080\n\n# External Proxies (replace or upload your list)\nsocks5://198.51.100.1:1080\nhttp://203.0.113.5:8080'
  );
  const [proxyTestResults, setProxyTestResults] = useState<ProxyTestItem[]>([]);
  const [isTestingBulkProxies, setIsTestingBulkProxies] = useState<boolean>(false);
  const [bulkFilter, setBulkFilter] = useState<'all' | 'alive' | 'dead'>('all');
  const [bulkSearch, setBulkSearch] = useState<string>('');
  const [activeProxyPool, setActiveProxyPool] = useState<string[]>([]);
  const [proxyConcurrency, setProxyConcurrency] = useState<number>(15);
  const [proxyTimeoutSec, setProxyTimeoutSec] = useState<number>(3.0);
  const [fileDragOver, setFileDragOver] = useState<boolean>(false);
  const [testingSingleId, setTestingSingleId] = useState<string | null>(null);

  // Proxifly Import State
  const [isImportingProxifly, setIsImportingProxifly] = useState<boolean>(false);
  const [proxiflySourceInfo, setProxiflySourceInfo] = useState<string | null>(null);
  const [proxiflyLimit, setProxiflyLimit] = useState<number>(100);

  // GlobalScan State (Internet-wide IPv4 Scanner)
  const [scanMode, setScanMode] = useState<'custom' | 'global'>('custom');
  const [globalRegion, setGlobalRegion] = useState<string>('worldwide');
  const [globalBatchCount, setGlobalBatchCount] = useState<number>(100);
  const [globalHasPermission, setGlobalHasPermission] = useState<boolean>(true);
  const [isGeneratingGlobal, setIsGeneratingGlobal] = useState<boolean>(false);
  const [lastGlobalSummary, setLastGlobalSummary] = useState<string | null>(null);
  const [isGlobalActiveSession, setIsGlobalActiveSession] = useState<boolean>(false);
  const [activeGlobalRegion, setActiveGlobalRegion] = useState<string | null>(null);

  // Notification Toast State
  const [notification, setNotification] = useState<{
    type: 'info' | 'success' | 'error';
    message: string;
  } | null>(null);

  const showNotification = (type: 'info' | 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification((curr) => (curr?.message === message ? null : curr));
    }, 6000);
  };

  const [proxyTestStatus, setProxyTestStatus] = useState<{
    testing: boolean;
    result?: { success: boolean; message?: string; latencyMs?: number; error?: string };
  }>({ testing: false });

  // Scan state
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentProxySummary, setCurrentProxySummary] = useState<string>('Direct');
  const [progress, setProgress] = useState<ScanProgress>({
    scanned: 0,
    total: 0,
    detected: 0,
    authSuccess: 0,
    authFailed: 0,
    errors: 0,
    elapsed: 0,
  });
  const [results, setResults] = useState<ScanResult[]>([]);
  const [consoleLogs, setConsoleLogs] = useState<
    { id: string; time: string; type: 'open' | 'cracked' | 'up' | 'error' | 'info'; text: string; detail?: string }[]
  >([]);

  // UI helpers
  const [tableFilter, setTableFilter] = useState<'all' | 'detected' | 'cracked' | 'failed'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [autoScrollLogs, setAutoScrollLogs] = useState<boolean>(true);
  const [preview, setPreview] = useState<TargetPreview | null>(null);
  const [demoPresets, setDemoPresets] = useState<DemoTarget[]>([]);
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'proxies' | 'passwords' | 'docs'>('scan');

  const logsEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch initial config & demo targets
  useEffect(() => {
    fetch('/api/config')
      .then((res) => res.json())
      .then((data) => {
        if (data.defaultCreds && data.defaultCreds.length > 0) {
          setPasswords(data.defaultCreds);
        }
        if (data.demoTargets) {
          setDemoPresets(data.demoTargets);
        }
      })
      .catch((err) => console.error('Failed to load initial config:', err));
  }, []);

  // Debounced target preview calculation
  useEffect(() => {
    const timer = setTimeout(() => {
      fetch('/api/targets/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawTargets: targetsText, rawPorts: portsText }),
      })
        .then((res) => res.json())
        .then((data) => setPreview(data))
        .catch((err) => console.error('Preview error:', err));
    }, 300);

    return () => clearTimeout(timer);
  }, [targetsText, portsText]);

  // Connect SSE for live scan updates
  useEffect(() => {
    const eventSource = new EventSource('/api/scan/events');

    eventSource.addEventListener('init', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.status === 'running') {
          setIsScanning(true);
        }
        if (data.results && data.results.length > 0) {
          setResults(data.results);
        }
      } catch {
        // ignore
      }
    });

    eventSource.addEventListener('result', (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data);
        const r: ScanResult = payload.result;
        const p: ScanProgress = payload.progress;

        setProgress(p);
        setResults((prev) => [r, ...prev]);

        // Add log entry
        const timeStr = new Date().toLocaleTimeString();
        if (r.security === 'none') {
          setConsoleLogs((prev) => [
            ...prev,
            {
              id: `${r.ip}:${r.port}-${Date.now()}`,
              time: timeStr,
              type: 'open',
              text: `OPEN ${r.url}`,
              detail: `RFB ${r.proto || '3.8'}, no authentication required! (Wide Open)`,
            },
          ]);
        } else if (r.auth_success && r.winner) {
          const pwd = r.winner[1] || '<empty>';
          setConsoleLogs((prev) => [
            ...prev,
            {
              id: `${r.ip}:${r.port}-${Date.now()}`,
              time: timeStr,
              type: 'cracked',
              text: `CRACKED ${r.url}`,
              detail: `RFB ${r.proto || '3.8'} password="${pwd}"`,
            },
          ]);
        } else if (r.detected) {
          setConsoleLogs((prev) => [
            ...prev,
            {
              id: `${r.ip}:${r.port}-${Date.now()}`,
              time: timeStr,
              type: 'up',
              text: `VNC up ${r.url}`,
              detail: `RFB ${r.proto || '3.8'}, security: ${r.security || 'unknown'}`,
            },
          ]);
        } else if (r.error) {
          setConsoleLogs((prev) => [
            ...prev,
            {
              id: `${r.ip}:${r.port}-${Date.now()}`,
              time: timeStr,
              type: 'error',
              text: `ERROR ${r.url}`,
              detail: r.error || undefined,
            },
          ]);
        }
      } catch (err) {
        console.error('Error handling result event:', err);
      }
    });

    eventSource.addEventListener('status', (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.type === 'started') {
          setIsScanning(true);
          setCurrentProxySummary(payload.proxy || 'Direct');
          if (payload.isGlobalScan) {
            setIsGlobalActiveSession(true);
            setActiveGlobalRegion(payload.globalRegion || 'worldwide');
          } else {
            setIsGlobalActiveSession(false);
            setActiveGlobalRegion(null);
          }
          setResults([]);
          setConsoleLogs([
            {
              id: 'start-' + Date.now(),
              time: new Date().toLocaleTimeString(),
              type: 'info',
              text: payload.isGlobalScan
                ? `🌍 GlobalScan initiated: ${payload.total} scan jobs across ${payload.globalRegion || 'Worldwide'} public IP space (Route: ${payload.proxy || 'Direct'}, Authorized: ✓)`
                : `Scan started: ${payload.total} scan jobs queued (Route: ${payload.proxy || 'Direct'})`,
            },
          ]);
        } else if (payload.type === 'completed' || payload.type === 'cancelled') {
          setIsScanning(false);
          setIsGlobalActiveSession(false);
          if (payload.summary) {
            setProgress(payload.summary);
          }
          setConsoleLogs((prev) => [
            ...prev,
            {
              id: 'end-' + Date.now(),
              time: new Date().toLocaleTimeString(),
              type: 'info',
              text: `Scan ${payload.type}. Detected: ${progress.detected}, Cracked/Open: ${progress.authSuccess}`,
            },
          ]);
        }
      } catch (err) {
        console.error('Status event error:', err);
      }
    });

    return () => {
      eventSource.close();
    };
  }, [progress.detected, progress.authSuccess]);

  // Auto-scroll logs
  useEffect(() => {
    if (autoScrollLogs && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs, autoScrollLogs]);

  // Single Proxy Test
  const handleTestSingleProxy = async () => {
    if (!proxyUrl.trim()) return;
    setProxyTestStatus({ testing: true });
    try {
      const res = await fetch('/api/proxy/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxyStr: proxyUrl, type: proxyType }),
      });
      const data = await res.json();
      setProxyTestStatus({ testing: false, result: data });
    } catch (err: any) {
      setProxyTestStatus({
        testing: false,
        result: { success: false, error: err.message || 'Network request failed' },
      });
    }
  };

  // Bulk Proxy File Upload Handler
  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = String(e.target?.result || '');
      setBulkProxiesText((prev) => (prev ? `${prev.trim()}\n${content}` : content));
      setActiveTab('proxies');
    };
    reader.readAsText(file);
  };

  const onDropFile = (e: React.DragEvent) => {
    e.preventDefault();
    setFileDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // Re-test single row proxy in table
  const handleTestSingleRowProxy = async (item: ProxyTestItem) => {
    setTestingSingleId(item.id);
    try {
      const res = await fetch('/api/proxy/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxyStr: item.raw, type: item.protocol }),
      });
      const data = await res.json();
      setProxyTestResults((prev) =>
        prev.map((p) =>
          p.id === item.id
            ? {
                ...p,
                status: data.success ? 'alive' : 'dead',
                latencyMs: data.latencyMs,
                details: data.message,
                error: data.error,
              }
            : p
        )
      );
    } catch (err: any) {
      setProxyTestResults((prev) =>
        prev.map((p) =>
          p.id === item.id ? { ...p, status: 'dead', error: err.message || 'Test failed' } : p
        )
      );
    } finally {
      setTestingSingleId(null);
    }
  };

  // Import Proxifly SOCKS5 Proxies from GitHub repository
  const handleImportProxifly = async (autoTest = false) => {
    setIsImportingProxifly(true);
    try {
      const res = await fetch(`/api/proxies/import-proxifly?protocol=socks5&limit=${proxiflyLimit}`);
      const text = await res.text();
      let data: any;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Server returned invalid response: ${text.slice(0, 120)}`);
      }

      if (!res.ok) {
        throw new Error(data.error || 'Failed to import Proxifly proxies');
      }

      if (data.proxies && data.proxies.length > 0) {
        const textContent = data.proxies.join('\n');
        setBulkProxiesText(textContent);
        setProxyType('socks5');
        const info = `Imported ${data.count} SOCKS5 proxies (${data.source})`;
        setProxiflySourceInfo(info);
        showNotification('success', `Imported ${data.count} SOCKS5 proxies from Proxifly GitHub!`);

        if (autoTest) {
          setTimeout(() => {
            handleRunBulkTest(data.proxies, 'socks5');
          }, 150);
        }
      } else {
        showNotification('error', 'No proxies returned from Proxifly repository');
      }
    } catch (err: any) {
      console.error('Proxifly import error:', err);
      showNotification('error', err.message || 'Failed to import Proxifly proxies');
    } finally {
      setIsImportingProxifly(false);
    }
  };

  // Bulk Proxy Test Runner with safe JSON parsing and notification feedback
  const handleRunBulkTest = async (overrideProxies?: string[], overrideType?: 'socks5' | 'http' | 'socks4') => {
    const rawList = overrideProxies || bulkProxiesText.split(/\r?\n/);
    const lines = rawList
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));

    if (lines.length === 0) {
      showNotification('error', 'Please enter, upload, or import Proxifly proxies to test');
      return;
    }

    const typeToUse = overrideType || proxyType;
    setIsTestingBulkProxies(true);
    try {
      const res = await fetch('/api/proxies/test-bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proxies: lines,
          defaultType: typeToUse,
          timeout: proxyTimeoutSec,
          concurrency: proxyConcurrency,
        }),
      });

      const text = await res.text();
      let data: any;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Server returned status ${res.status}: ${text.slice(0, 150)}`);
      }

      if (!res.ok) {
        showNotification('error', data.error || 'Failed to test proxies');
        return;
      }
      if (data.results) {
        setProxyTestResults(data.results);
        showNotification(
          'success',
          `Proxy test completed: ${data.alive} alive, ${data.dead} dead out of ${data.total} tested!`
        );
      }
    } catch (err: any) {
      console.error('Bulk proxy test error:', err);
      showNotification('error', err.message || 'Error occurred during bulk proxy test');
    } finally {
      setIsTestingBulkProxies(false);
    }
  };

  const handleTestAllProxies = () => {
    handleRunBulkTest();
  };

  // Use Tested Alive Proxies for Scan
  const handleUseAliveInScanner = () => {
    const alive = proxyTestResults.filter((r) => r.status === 'alive').map((r) => r.raw);
    if (alive.length === 0) {
      showNotification('error', 'No working proxies found. Click "Test All Proxies" first.');
      return;
    }
    setActiveProxyPool(alive);
    setProxyEnabled(true);
    setProxyMode('pool');
    setActiveTab('scan');
    showNotification('success', `Activated pool of ${alive.length} tested working proxies in Scanner!`);
  };

  // Export Working Proxies to File
  const handleExportAlive = () => {
    const alive = proxyTestResults.filter((r) => r.status === 'alive').map((r) => r.raw);
    if (alive.length === 0) return;
    const blob = new Blob([alive.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `working_proxies_${Date.now()}.txt`;
    a.click();
  };

  // Export All Proxy Results to CSV
  const handleExportAllProxyCsv = () => {
    if (proxyTestResults.length === 0) return;
    const headers = ['Proxy', 'Host', 'Port', 'Protocol', 'Status', 'LatencyMs', 'Error'];
    const rows = proxyTestResults.map((r) => [
      `"${r.raw.replace(/"/g, '""')}"`,
      r.host,
      r.port,
      r.protocol,
      r.status,
      r.latencyMs || '',
      `"${(r.error || '').replace(/"/g, '""')}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `proxy_test_report_${Date.now()}.csv`;
    a.click();
  };

  // Clear Dead Proxies from Text
  const handleClearDead = () => {
    const deadSet = new Set(proxyTestResults.filter((r) => r.status === 'dead').map((r) => r.raw));
    const lines = bulkProxiesText.split(/\r?\n/).filter((l) => !deadSet.has(l.trim()));
    setBulkProxiesText(lines.join('\n'));
    setProxyTestResults(proxyTestResults.filter((r) => r.status !== 'dead'));
    showNotification('info', 'Removed dead proxies from list');
  };

  // Generate Internet-Wide Global Targets
  const handleGenerateGlobalTargets = async (autoStart = false) => {
    setIsGeneratingGlobal(true);
    try {
      const res = await fetch('/api/globalscan/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          region: globalRegion,
          count: globalBatchCount,
          hasPermission: globalHasPermission,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        showNotification('error', data.error || 'Failed to generate global targets');
        return;
      }
      const newTargets = data.targets.join('\n');
      setTargetsText(newTargets);
      setLastGlobalSummary(`${data.count} public IPs (${data.region})`);
      showNotification(
        'success',
        `Generated ${data.count} routable public IPv4 targets for ${data.region}`
      );
      if (autoStart) {
        setTimeout(() => {
          handleExecuteScanWithTargets(newTargets);
        }, 150);
      }
    } catch (err: any) {
      console.error('GlobalScan generate error:', err);
      showNotification('error', err.message || 'Error generating global targets');
    } finally {
      setIsGeneratingGlobal(false);
    }
  };

  const handleExecuteScanWithTargets = async (targetsToUse?: string) => {
    try {
      const isPool = proxyEnabled && proxyMode === 'pool' && activeProxyPool.length > 0;
      const targets = targetsToUse !== undefined ? targetsToUse : targetsText;
      if (!targets.trim()) {
        showNotification('error', 'Please provide or generate targets before scanning');
        return;
      }
      const isGlobal = scanMode === 'global';
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets,
          ports: portsText,
          checkAuth,
          passwords,
          workers,
          timeout: timeoutSec,
          proxy: proxyEnabled && !isPool ? { enabled: true, url: proxyUrl, type: proxyType } : null,
          proxyPool: isPool ? { enabled: true, list: activeProxyPool, defaultType: proxyType } : null,
          isGlobalScan: isGlobal,
          globalRegion: isGlobal ? globalRegion : undefined,
          hasPermission: globalHasPermission,
        }),
      });

      const text = await res.text();
      let data: any;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Server returned status ${res.status}: ${text.slice(0, 150)}`);
      }

      if (!res.ok) {
        showNotification('error', data.error || 'Failed to start scan');
        return;
      }
      setIsScanning(true);
      showNotification(
        'info',
        isGlobal
          ? `🌍 GlobalScan started with ${data.total} jobs across ${data.globalRegion || 'Worldwide'} public IP space`
          : `Scan started with ${data.total} scan jobs queued`
      );
    } catch (err: any) {
      console.error('Start scan error:', err);
      showNotification('error', err.message || 'Failed to start scan');
    }
  };

  // Start Scan Handler
  const handleStartScan = async () => {
    if (scanMode === 'global' && (!targetsText || !targetsText.trim())) {
      handleGenerateGlobalTargets(true);
    } else {
      handleExecuteScanWithTargets();
    }
  };

  // Stop Scan Handler
  const handleStopScan = async () => {
    try {
      await fetch('/api/scan/stop', { method: 'POST' });
      setIsScanning(false);
    } catch (err) {
      console.error('Stop scan error:', err);
    }
  };

  // Password management
  const handleAddPassword = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPassword.trim()) return;
    if (!passwords.includes(newPassword.trim())) {
      setPasswords([...passwords, newPassword.trim()]);
    }
    setNewPassword('');
  };

  const handleRemovePassword = (pwd: string) => {
    setPasswords(passwords.filter((p) => p !== pwd));
  };

  // Copy URL to clipboard
  const handleCopyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  // Filtered table rows for Scan Results
  const filteredResults = useMemo(() => {
    return results.filter((r) => {
      if (onlyFound && !r.detected) return false;
      if (tableFilter === 'detected' && !r.detected) return false;
      if (tableFilter === 'cracked' && !(r.auth_success || r.security === 'none')) return false;
      if (tableFilter === 'failed' && !(r.detected && r.security === 'vncauth' && !r.auth_success)) return false;

      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesTarget = `${r.ip}:${r.port}`.toLowerCase().includes(query);
        const matchesProto = (r.proto || '').toLowerCase().includes(query);
        const matchesSecurity = (r.security || '').toLowerCase().includes(query);
        const matchesPass = r.winner && r.winner[1].toLowerCase().includes(query);
        const matchesErr = (r.error || '').toLowerCase().includes(query);
        return matchesTarget || matchesProto || matchesSecurity || matchesPass || matchesErr;
      }

      return true;
    });
  }, [results, onlyFound, tableFilter, searchQuery]);

  // Filtered table rows for Bulk Proxy Results
  const filteredProxyResults = useMemo(() => {
    return proxyTestResults.filter((r) => {
      if (bulkFilter === 'alive' && r.status !== 'alive') return false;
      if (bulkFilter === 'dead' && r.status !== 'dead') return false;

      if (bulkSearch.trim()) {
        const query = bulkSearch.toLowerCase();
        const matchHost = `${r.host}:${r.port}`.toLowerCase().includes(query);
        const matchRaw = r.raw.toLowerCase().includes(query);
        const matchErr = (r.error || '').toLowerCase().includes(query);
        return matchHost || matchRaw || matchErr;
      }
      return true;
    });
  }, [proxyTestResults, bulkFilter, bulkSearch]);

  const proxyAliveCount = proxyTestResults.filter((r) => r.status === 'alive').length;
  const proxyDeadCount = proxyTestResults.filter((r) => r.status === 'dead').length;

  // Rate calculation
  const scanRate = progress.elapsed > 0 ? (progress.scanned / progress.elapsed).toFixed(1) : '0';
  const progressPercent = progress.total > 0 ? Math.min(100, Math.round((progress.scanned / progress.total) * 100)) : 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation & Status Bar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30 px-4 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Server className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-base tracking-tight text-white">VNC RFB Scanner</span>
                <span className="px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider bg-cyan-950 text-cyan-400 border border-cyan-800 rounded">
                  RFB 3.8
                </span>
                {proxyEnabled && (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-purple-950/80 text-purple-300 border border-purple-800 rounded flex items-center space-x-1">
                    <Globe className="h-2.5 w-2.5" />
                    <span>
                      {proxyMode === 'pool'
                        ? `Proxy Pool (${activeProxyPool.length} active)`
                        : `Proxy: ${proxyType.toUpperCase()}`}
                    </span>
                  </span>
                )}
                {isScanning && (
                  <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800 rounded-full animate-pulse">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
                    Scanning ({currentProxySummary})
                  </span>
                )}
                {isGlobalActiveSession && (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-blue-950/90 text-cyan-300 border border-cyan-700/80 rounded flex items-center space-x-1">
                    <Globe className="h-2.5 w-2.5 text-cyan-400" />
                    <span>GlobalScan: {activeGlobalRegion || 'Worldwide'}</span>
                  </span>
                )}
                {globalHasPermission && (
                  <span
                    className="px-1.5 py-0.5 text-[10px] font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 rounded flex items-center space-x-1"
                    title="Operator holds explicit authorization to audit targeted networks"
                  >
                    <ShieldCheck className="h-2.5 w-2.5 text-emerald-400" />
                    <span>Authorized</span>
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">High-performance VNC service detection &amp; DES credential auditor</p>
            </div>
          </div>

          {/* Action buttons & navigation tabs */}
          <div className="flex items-center space-x-2">
            <div className="bg-slate-800/80 p-0.5 rounded-lg border border-slate-700/60 flex text-xs">
              <button
                onClick={() => setActiveTab('scan')}
                className={`px-3 py-1.5 rounded-md font-medium transition ${
                  activeTab === 'scan' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Auditor Console
              </button>
              <button
                onClick={() => setActiveTab('proxies')}
                className={`px-3 py-1.5 rounded-md font-medium transition flex items-center space-x-1.5 ${
                  activeTab === 'proxies' ? 'bg-purple-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Globe className="h-3.5 w-3.5" />
                <span>Bulk Proxy Tester</span>
                {proxyAliveCount > 0 && (
                  <span className="bg-emerald-500 text-slate-950 text-[10px] font-bold px-1.5 rounded-full">
                    {proxyAliveCount}
                  </span>
                )}
              </button>
              <button
                onClick={() => setActiveTab('passwords')}
                className={`px-3 py-1.5 rounded-md font-medium transition flex items-center space-x-1.5 ${
                  activeTab === 'passwords' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>Wordlist ({passwords.length})</span>
              </button>
              <button
                onClick={() => setActiveTab('docs')}
                className={`px-3 py-1.5 rounded-md font-medium transition ${
                  activeTab === 'docs' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                RFB &amp; Proxy Docs
              </button>
            </div>

            {results.some((r) => r.detected) && (
              <a
                href="/api/scan/download-csv"
                download
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 flex items-center space-x-1.5 transition shadow-sm"
              >
                <Download className="h-3.5 w-3.5 text-cyan-400" />
                <span>Export CSV</span>
              </a>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto w-full px-4 py-6 flex-1 flex flex-col space-y-6">
        {/* Toast Notification Banner */}
        {notification && (
          <div
            className={`w-full p-3 rounded-xl border flex items-center justify-between text-xs transition-all shadow-md ${
              notification.type === 'success'
                ? 'bg-emerald-950/80 border-emerald-600/70 text-emerald-200'
                : notification.type === 'error'
                ? 'bg-rose-950/80 border-rose-600/70 text-rose-200'
                : 'bg-cyan-950/80 border-cyan-600/70 text-cyan-200'
            }`}
          >
            <div className="flex items-center space-x-2.5">
              {notification.type === 'success' && <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />}
              {notification.type === 'error' && <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />}
              {notification.type === 'info' && <Info className="h-4 w-4 text-cyan-400 shrink-0" />}
              <span className="font-medium">{notification.message}</span>
            </div>
            <button
              type="button"
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white px-2 py-0.5 rounded text-sm font-bold"
            >
              ✕
            </button>
          </div>
        )}

        {/* KPI / Scan Stats Dashboard */}
        <section className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>Scanned / Total</span>
              <Layers className="h-3.5 w-3.5 text-slate-500" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-slate-100">
              {progress.scanned} <span className="text-xs text-slate-500 font-sans">/ {progress.total}</span>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
              <div
                className="bg-cyan-500 h-full transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              ></div>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>VNC Up</span>
              <Server className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-emerald-400">{progress.detected}</div>
            <div className="text-[11px] text-slate-500 mt-1">RFB Handshake OK</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm relative overflow-hidden">
            {progress.authSuccess > 0 && (
              <div className="absolute top-0 right-0 w-12 h-12 bg-rose-500/10 rounded-full blur-xl pointer-events-none"></div>
            )}
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>Cracked / Open</span>
              <Unlock className="h-3.5 w-3.5 text-rose-400" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-rose-400">{progress.authSuccess}</div>
            <div className="text-[11px] text-slate-500 mt-1">Full Access Gained</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>Auth Failed</span>
              <Lock className="h-3.5 w-3.5 text-amber-400" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-amber-400">{progress.authFailed}</div>
            <div className="text-[11px] text-slate-500 mt-1">Incorrect Password</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>Errors / Other</span>
              <AlertTriangle className="h-3.5 w-3.5 text-slate-500" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-slate-300">{progress.errors}</div>
            <div className="text-[11px] text-slate-500 mt-1">Filtered / Non-RFB</div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-3.5 shadow-sm">
            <div className="text-slate-400 text-xs font-medium uppercase tracking-wider flex items-center justify-between">
              <span>Throughput</span>
              <Zap className="h-3.5 w-3.5 text-cyan-400" />
            </div>
            <div className="text-xl font-bold font-mono mt-1 text-cyan-400">
              {scanRate} <span className="text-xs text-slate-500 font-sans">hosts/s</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">{progress.elapsed.toFixed(1)}s elapsed</div>
          </div>
        </section>

        {/* Tab 1: Auditor Console */}
        {activeTab === 'scan' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: Scope, Port Skipping & Proxy Settings (5 cols) */}
            <div className="lg:col-span-5 space-y-5">
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2">
                    <Sliders className="h-4 w-4 text-cyan-400" />
                    <h2 className="font-semibold text-sm text-slate-200">Scan Scope &amp; Target Setup</h2>
                  </div>
                  {preview && (
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                      {preview.totalScans} scan jobs
                    </span>
                  )}
                </div>

                {/* Target Mode Selector: Custom Scope vs GlobalScan */}
                <div className="bg-slate-950 p-1 rounded-lg border border-slate-800 flex text-xs">
                  <button
                    type="button"
                    onClick={() => setScanMode('custom')}
                    className={`flex-1 py-1.5 px-3 rounded-md font-medium transition flex items-center justify-center space-x-1.5 ${
                      scanMode === 'custom'
                        ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Sliders className="h-3.5 w-3.5" />
                    <span>Custom Scope</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('global');
                      if (!targetsText || !targetsText.includes('.')) {
                        handleGenerateGlobalTargets();
                      }
                    }}
                    className={`flex-1 py-1.5 px-3 rounded-md font-medium transition flex items-center justify-center space-x-1.5 ${
                      scanMode === 'global'
                        ? 'bg-gradient-to-r from-cyan-950 to-blue-900 text-cyan-200 border border-cyan-700/80 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Globe className="h-3.5 w-3.5 text-cyan-400" />
                    <span className="font-semibold">🌍 GlobalScan</span>
                    <span className="text-[10px] bg-cyan-500/20 text-cyan-300 px-1 rounded uppercase font-bold">Mode</span>
                  </button>
                </div>

                {/* GlobalScan Command Console */}
                {scanMode === 'global' ? (
                  <div className="space-y-3 p-3 bg-gradient-to-b from-blue-950/30 to-slate-950/70 rounded-xl border border-blue-900/40">
                    {/* Permission Status Verified Badge */}
                    <div className="bg-emerald-950/40 border border-emerald-800/80 rounded-lg p-2.5 flex items-start space-x-2.5">
                      <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div className="text-xs flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-emerald-300">Authorized Global Audit Mode</span>
                          <span className="text-[10px] bg-emerald-900/80 text-emerald-300 px-1.5 py-0.2 rounded font-mono border border-emerald-700/60">
                            Permission Confirmed
                          </span>
                        </div>
                        <p className="text-[11px] text-emerald-400/80 mt-0.5 leading-snug">
                          Operator permission verified. Strictly filters non-routable RFC 1918, RFC 6598, multicast (224/4), and loopback ranges.
                        </p>
                        <label className="flex items-center space-x-1.5 mt-2 cursor-pointer text-[11px] text-slate-300 select-none">
                          <input
                            type="checkbox"
                            checked={globalHasPermission}
                            onChange={(e) => setGlobalHasPermission(e.target.checked)}
                            className="rounded accent-emerald-500 h-3.5 w-3.5"
                          />
                          <span>Operator holds explicit authorization to audit targeted networks</span>
                        </label>
                      </div>
                    </div>

                    {/* Global Region Selector */}
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <label className="text-xs font-medium text-slate-300">Global Geographic / Infrastructure Region</label>
                        <span className="text-[10px] font-mono text-cyan-400">Routable IPv4 Pool</span>
                      </div>
                      <select
                        value={globalRegion}
                        onChange={(e) => setGlobalRegion(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-cyan-200 font-medium focus:outline-none focus:border-cyan-500"
                      >
                        <option value="worldwide">🌐 Worldwide (Uniform Random Public IPv4 Internet)</option>
                        <option value="north-america">🇺🇸 North America (ARIN Public Allocations)</option>
                        <option value="europe">🇪🇺 Europe (RIPE NCC Allocations)</option>
                        <option value="asia-pacific">🌏 Asia-Pacific (APNIC Allocations)</option>
                        <option value="latin-america">🌎 Latin America (LACNIC Allocations)</option>
                        <option value="cloud-datacenters">☁️ Cloud &amp; Datacenters (High VNC Density Hosting)</option>
                      </select>
                    </div>

                    {/* Batch Size Selector */}
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <label className="text-xs font-medium text-slate-300">Target Sample Batch Size</label>
                        <span className="text-[11px] font-mono text-cyan-400 font-bold">{globalBatchCount} hosts</span>
                      </div>
                      <div className="grid grid-cols-5 gap-1.5 text-xs">
                        {[50, 100, 250, 500, 1000].map((cnt) => (
                          <button
                            key={cnt}
                            type="button"
                            onClick={() => setGlobalBatchCount(cnt)}
                            className={`py-1 rounded text-center font-mono transition ${
                              globalBatchCount === cnt
                                ? 'bg-cyan-600 text-white font-bold shadow'
                                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                            }`}
                          >
                            {cnt}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Generation Trigger & Action Buttons */}
                    <div className="flex items-center space-x-2 pt-1">
                      <button
                        type="button"
                        onClick={() => handleGenerateGlobalTargets(false)}
                        disabled={isGeneratingGlobal}
                        className="flex-1 py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 rounded-lg text-xs font-medium transition flex items-center justify-center space-x-1.5"
                      >
                        {isGeneratingGlobal ? (
                          <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Sparkles className="h-3.5 w-3.5" />
                        )}
                        <span>{isGeneratingGlobal ? 'Generating...' : '⚡ Generate Fresh Global Targets'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleGenerateGlobalTargets(true)}
                        disabled={isGeneratingGlobal || isScanning}
                        className="py-1.5 px-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center space-x-1.5 shadow"
                        title="Generate batch and immediately launch scan"
                      >
                        <Play className="h-3 w-3 fill-white" />
                        <span>Instant Scan</span>
                      </button>
                    </div>

                    {/* Target Pool Live Summary Card */}
                    {preview && (
                      <div className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800/80 text-[11px] space-y-1">
                        <div className="flex items-center justify-between text-slate-300">
                          <span>
                            Active Global Pool: <strong className="text-cyan-300 font-mono">{preview.targetsCount}</strong> public targets
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {preview.totalScans} scan jobs queued
                          </span>
                        </div>
                        {preview.sampleIps && preview.sampleIps.length > 0 && (
                          <div className="font-mono text-[10px] text-slate-400 truncate">
                            Sample: {preview.sampleIps.slice(0, 4).join(', ')} ...
                          </div>
                        )}
                      </div>
                    )}

                    {/* Proxy Advice Banner */}
                    <div className="p-2 bg-purple-950/30 border border-purple-900/40 rounded-lg flex items-center justify-between text-[11px]">
                      <div className="flex items-center space-x-1.5 text-purple-300">
                        <Globe className="h-3 w-3 shrink-0" />
                        <span>
                          {proxyEnabled && proxyMode === 'pool' && activeProxyPool.length > 0
                            ? `Connected to ${activeProxyPool.length} Proxifly SOCKS5 proxies`
                            : 'Recommended: Enable Proxifly SOCKS5 pool for distributed scanning'}
                        </span>
                      </div>
                      {(!proxyEnabled || activeProxyPool.length === 0) && (
                        <button
                          type="button"
                          onClick={() => handleImportProxifly(true)}
                          className="px-2 py-0.5 bg-purple-800 hover:bg-purple-700 text-white rounded text-[10px] font-medium shrink-0 ml-2"
                        >
                          Import Proxifly
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <>
                    {/* Target Presets */}
                    <div>
                      <label className="text-xs font-medium text-slate-400 block mb-1.5">Load Target Presets</label>
                      <div className="grid grid-cols-1 gap-1.5">
                        {demoPresets.map((demo, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => {
                              setTargetsText(demo.spec);
                              setPortsText(demo.ports);
                            }}
                            className="text-left px-2.5 py-1.5 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50 text-xs transition flex flex-col group"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-slate-200 group-hover:text-cyan-300">{demo.name}</span>
                              <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                                {demo.spec} : {demo.ports}
                              </span>
                            </div>
                            <span className="text-[11px] text-slate-400 mt-0.5 leading-snug">{demo.description}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Targets Input */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-medium text-slate-300">Target Specifications</label>
                        <div className="flex items-center space-x-2">
                          <button
                            type="button"
                            onClick={() => handleGenerateGlobalTargets(false)}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 underline font-mono flex items-center space-x-1"
                          >
                            <Sparkles className="h-2.5 w-2.5" />
                            <span>Insert Global Public IPs</span>
                          </button>
                          <span className="text-[11px] text-slate-500 font-mono">1 IP, CIDR, or range</span>
                        </div>
                      </div>
                      <textarea
                        rows={3}
                        value={targetsText}
                        onChange={(e) => setTargetsText(e.target.value)}
                        placeholder="127.0.0.1&#10;10.0.0.0/24&#10;10.0.0.1-50&#10;192.168.1.10-192.168.1.20&#10;global:100"
                        className="w-full bg-slate-950 border border-slate-700/80 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                      />
                      {preview && (
                        <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                          <span>
                            Expanded IPs: <strong className="text-slate-200">{preview.targetsCount}</strong>
                          </span>
                          <span>
                            Target Ports: <strong className="text-slate-200">{preview.portsCount}</strong>
                          </span>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {/* VNC Display Ports & Number Skipping Section */}
                <div className="border border-slate-800/90 rounded-lg p-3 bg-slate-950/60 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-1.5">
                        <label className="text-xs font-semibold text-slate-200">VNC Display Ports</label>
                        <span className="text-[10px] text-cyan-400 bg-cyan-950 px-1.5 py-0.2 rounded border border-cyan-800/60">
                          Use &quot;,&quot; to skip numbers
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Separate with a comma (<code className="text-cyan-300 font-mono font-bold">,</code>) to test specific numbers and skip others.
                      </p>
                    </div>
                  </div>

                  {/* Input field */}
                  <input
                    type="text"
                    value={portsText}
                    onChange={(e) => setPortsText(e.target.value)}
                    placeholder="e.g. 5900, 5902, 5905 or :0, :2, :5"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  />

                  {/* Quick Preset Buttons for Common Skips & Ranges */}
                  <div className="flex flex-wrap gap-1.5 text-[10px]">
                    <span className="text-slate-500 py-0.5 font-medium">Quick Presets:</span>
                    <button
                      type="button"
                      onClick={() => setPortsText('5900, 5901, 5902, 5903, 5904, 5905, 5800, 5801')}
                      className="px-2 py-0.5 bg-gradient-to-r from-cyan-900/90 to-blue-900/90 hover:from-cyan-800 hover:to-blue-800 text-cyan-200 rounded border border-cyan-700/80 font-medium transition shadow-sm"
                      title="Common VNC display ports (:0-:5) and HTTP web viewer ports (5800-5801)"
                    >
                      ★ Common Ports (:0-:5 &amp; Web)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPortsText('5900')}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                      title="Single default port (:0)"
                    >
                      Port 5900 (:0)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPortsText('5900, 5901, 5902, 5903')}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                      title="Standard 4 virtual displays (:0-:3)"
                    >
                      Displays :0-:3 (5900-5903)
                    </button>
                    <button
                      type="button"
                      onClick={() => setPortsText('5900, 5902, 5905')}
                      className="px-2 py-0.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 rounded border border-cyan-800 transition"
                      title="Skips ports 5901, 5903, 5904"
                    >
                      Skip to :0, :2, :5
                    </button>
                    <button
                      type="button"
                      onClick={() => setPortsText('5900-5910')}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                      title="Wide range of 11 displays (:0-:10)"
                    >
                      Wide Range (:0-:10)
                    </button>
                  </div>

                  {/* Resolved Ports Tag List */}
                  {preview?.detailedPorts && preview.detailedPorts.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80">
                      <div className="text-[11px] text-slate-400 mb-1 flex items-center justify-between">
                        <span>Resolved Port List ({preview.detailedPorts.length} to probe):</span>
                        <span className="text-[10px] text-slate-500 font-mono">Numbers not listed are skipped</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {preview.detailedPorts.map((p, idx) => (
                          <span
                            key={idx}
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono bg-slate-800/90 text-cyan-300 border border-slate-700"
                          >
                            <span>{p.port}</span>
                            {p.display && <span className="text-slate-400 ml-1">({p.display})</span>}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Proxy Configuration Panel */}
                <div className="border border-purple-900/60 rounded-lg p-3 bg-purple-950/20 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Globe className="h-4 w-4 text-purple-400" />
                      <div>
                        <span className="text-xs font-semibold text-slate-200">Proxy Routing &amp; Pool</span>
                        <p className="text-[11px] text-slate-400">
                          {proxyEnabled && proxyMode === 'pool' && activeProxyPool.length > 0
                            ? `Active Pool: ${activeProxyPool.length} working proxies (Round-Robin)`
                            : 'Route scanner traffic via Single Proxy or Tested Pool'}
                        </p>
                      </div>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={proxyEnabled}
                        onChange={(e) => setProxyEnabled(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-purple-600"></div>
                    </label>
                  </div>

                  {proxyEnabled && (
                    <div className="pt-2 border-t border-purple-900/50 space-y-2.5">
                      {/* Mode selector: Pool vs Single */}
                      <div className="flex bg-slate-900/90 p-1 rounded-lg border border-purple-900/60 text-xs">
                        <button
                          type="button"
                          onClick={() => setProxyMode('pool')}
                          className={`flex-1 py-1 rounded font-medium transition ${
                            proxyMode === 'pool'
                              ? 'bg-purple-600 text-white shadow'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Proxy Pool ({activeProxyPool.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setProxyMode('single')}
                          className={`flex-1 py-1 rounded font-medium transition ${
                            proxyMode === 'single'
                              ? 'bg-purple-600 text-white shadow'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Single Proxy
                        </button>
                      </div>

                      {proxyMode === 'pool' ? (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-xs text-slate-300">
                            <span>
                              Loaded Pool Proxies: <strong className="text-purple-300 font-mono">{activeProxyPool.length}</strong>
                            </span>
                            <button
                              type="button"
                              onClick={() => setActiveTab('proxies')}
                              className="text-purple-400 hover:text-purple-300 underline text-[11px] flex items-center space-x-1"
                            >
                              <span>Open Proxy Tester / Upload File</span>
                              <ExternalLink className="h-3 w-3" />
                            </button>
                          </div>
                          {activeProxyPool.length === 0 ? (
                            <div className="p-3 bg-slate-950/60 border border-dashed border-purple-900/60 rounded-lg text-center">
                              <p className="text-xs text-slate-400">No active proxies loaded in pool.</p>
                              <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
                                <button
                                  type="button"
                                  onClick={() => handleImportProxifly(true)}
                                  className="px-2.5 py-1 bg-gradient-to-r from-purple-600 to-emerald-600 hover:from-purple-500 hover:to-emerald-500 text-white text-xs rounded transition flex items-center space-x-1 shadow-sm"
                                >
                                  <Sparkles className="h-3 w-3" />
                                  <span>Import Proxifly &amp; Test</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setActiveTab('proxies')}
                                  className="px-2.5 py-1 bg-purple-900 hover:bg-purple-800 text-purple-200 text-xs rounded transition"
                                >
                                  Open Bulk Tester
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="max-h-24 overflow-y-auto p-2 bg-slate-950/80 rounded border border-purple-900/40 font-mono text-[11px] text-purple-200 space-y-1">
                              {activeProxyPool.map((p, i) => (
                                <div key={i} className="truncate flex items-center space-x-1.5">
                                  <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0"></span>
                                  <span>{p}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="space-y-2.5">
                          <div className="grid grid-cols-3 gap-2">
                            <div>
                              <label className="text-[11px] font-medium text-slate-400 block mb-1">Protocol</label>
                              <select
                                value={proxyType}
                                onChange={(e) => setProxyType(e.target.value as any)}
                                className="w-full bg-slate-950 border border-purple-800/80 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500 font-mono"
                              >
                                <option value="socks5">SOCKS5</option>
                                <option value="http">HTTP</option>
                                <option value="socks4">SOCKS4</option>
                              </select>
                            </div>
                            <div className="col-span-2">
                              <label className="text-[11px] font-medium text-slate-400 block mb-1">
                                Proxy Host &amp; Port
                              </label>
                              <input
                                type="text"
                                value={proxyUrl}
                                onChange={(e) => setProxyUrl(e.target.value)}
                                placeholder="127.0.0.1:1080 or user:pass@host:port"
                                className="w-full bg-slate-950 border border-purple-800/80 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
                              />
                            </div>
                          </div>

                          <div className="flex items-center justify-between pt-1">
                            <button
                              type="button"
                              onClick={handleTestSingleProxy}
                              disabled={proxyTestStatus.testing}
                              className="px-3 py-1 bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700/60 rounded text-xs font-medium transition flex items-center space-x-1.5"
                            >
                              {proxyTestStatus.testing ? (
                                <RefreshCw className="h-3 w-3 animate-spin" />
                              ) : (
                                <Radio className="h-3 w-3 text-purple-300" />
                              )}
                              <span>{proxyTestStatus.testing ? 'Testing...' : 'Test Connection'}</span>
                            </button>

                            {proxyTestStatus.result && (
                              <div className="text-xs">
                                {proxyTestStatus.result.success ? (
                                  <span className="text-emerald-400 flex items-center space-x-1">
                                    <CheckCircle2 className="h-3.5 w-3.5" />
                                    <span>OK ({proxyTestStatus.result.latencyMs}ms)</span>
                                  </span>
                                ) : (
                                  <span
                                    className="text-rose-400 flex items-center space-x-1 truncate max-w-[180px]"
                                    title={proxyTestStatus.result.error}
                                  >
                                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                                    <span>{proxyTestStatus.result.error}</span>
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Credential Testing Toggle */}
                <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <KeyRound className="h-4 w-4 text-amber-400" />
                      <div>
                        <span className="text-xs font-medium text-slate-200">VNC Authentication Testing</span>
                        <p className="text-[11px] text-slate-500">Test wordlist against detected VNCAuth hosts</p>
                      </div>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checkAuth}
                        onChange={(e) => setCheckAuth(e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
                    </label>
                  </div>

                  {checkAuth && (
                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                      <span className="text-slate-400">
                        Active passwords: <strong className="text-cyan-400 font-mono">{passwords.length}</strong>
                      </span>
                      <button
                        type="button"
                        onClick={() => setActiveTab('passwords')}
                        className="text-cyan-400 hover:text-cyan-300 underline text-[11px]"
                      >
                        Edit Wordlist
                      </button>
                    </div>
                  )}
                </div>

                {/* Worker Concurrency & Timeout */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs font-medium text-slate-400 block mb-1">
                      Workers: <span className="font-mono text-cyan-400">{workers}</span>
                    </label>
                    <input
                      type="range"
                      min={1}
                      max={50}
                      value={workers}
                      onChange={(e) => setWorkers(Number(e.target.value))}
                      className="w-full accent-cyan-500 cursor-pointer"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-slate-400 block mb-1">
                      Timeout: <span className="font-mono text-cyan-400">{timeoutSec}s</span>
                    </label>
                    <input
                      type="range"
                      min={0.5}
                      max={10}
                      step={0.5}
                      value={timeoutSec}
                      onChange={(e) => setTimeoutSec(Number(e.target.value))}
                      className="w-full accent-cyan-500 cursor-pointer"
                    />
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="pt-2 flex items-center space-x-2">
                  {!isScanning ? (
                    <button
                      type="button"
                      onClick={handleStartScan}
                      className={`flex-1 py-2.5 px-4 rounded-lg text-white font-semibold text-xs flex items-center justify-center space-x-2 shadow-lg transition active:scale-[0.99] ${
                        scanMode === 'global'
                          ? 'bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 shadow-blue-900/30'
                          : 'bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 shadow-cyan-900/20'
                      }`}
                    >
                      <Play className="h-4 w-4 fill-white" />
                      <span>
                        {scanMode === 'global'
                          ? `🚀 Launch GlobalScan (${preview?.targetsCount || globalBatchCount} Targets)`
                          : 'Start VNC Scan'}
                        {proxyEnabled
                          ? proxyMode === 'pool' && activeProxyPool.length > 0
                            ? ` [Pool: ${activeProxyPool.length}]`
                            : ` [${proxyType.toUpperCase()}]`
                          : ''}
                      </span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={handleStopScan}
                      className="flex-1 py-2.5 px-4 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs flex items-center justify-center space-x-2 shadow-lg shadow-rose-900/20 transition active:scale-[0.99]"
                    >
                      <Square className="h-4 w-4 fill-white" />
                      <span>Stop Active Scan</span>
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Right Column: Live Terminal Feed & Results (7 cols) */}
            <div className="lg:col-span-7 space-y-5">
              {/* Live Terminal Output (emulates rich console) */}
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col h-[280px]">
                <div className="bg-slate-900 px-3.5 py-2 border-b border-slate-800 flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2">
                    <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                    <span className="font-semibold text-slate-300">Live Notification Feed</span>
                    <span className="text-[10px] text-slate-500 font-mono">({consoleLogs.length} events)</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <label className="text-[11px] text-slate-400 flex items-center space-x-1 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoScrollLogs}
                        onChange={(e) => setAutoScrollLogs(e.target.checked)}
                        className="rounded accent-cyan-500 h-3 w-3"
                      />
                      <span>Auto-scroll</span>
                    </label>
                    <button
                      type="button"
                      onClick={() => setConsoleLogs([])}
                      className="text-slate-500 hover:text-slate-300 text-[11px] px-1.5 py-0.5 hover:bg-slate-800 rounded"
                    >
                      Clear
                    </button>
                  </div>
                </div>

                <div className="p-3 font-mono text-xs overflow-y-auto flex-1 space-y-1 bg-slate-950/90">
                  {consoleLogs.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-slate-600">
                      <ShieldAlert className="h-6 w-6 mb-1 opacity-50" />
                      <p className="text-xs">Scanner idle. Configure targets, skipped ports, and click &quot;Start VNC Scan&quot;</p>
                    </div>
                  ) : (
                    consoleLogs.map((log) => (
                      <div key={log.id} className="leading-relaxed flex items-start space-x-2">
                        <span className="text-slate-600 text-[11px] select-none">{log.time}</span>
                        {log.type === 'open' && (
                          <span className="bg-rose-950/80 text-rose-300 border border-rose-800/80 px-1 rounded text-[10px] font-bold">
                            OPEN
                          </span>
                        )}
                        {log.type === 'cracked' && (
                          <span className="bg-rose-950/80 text-rose-400 border border-rose-800 px-1 rounded text-[10px] font-bold">
                            CRACKED
                          </span>
                        )}
                        {log.type === 'up' && (
                          <span className="bg-emerald-950/80 text-emerald-300 border border-emerald-800 px-1 rounded text-[10px] font-medium">
                            VNC up
                          </span>
                        )}
                        {log.type === 'error' && (
                          <span className="bg-slate-800 text-slate-400 px-1 rounded text-[10px]">
                            ERR
                          </span>
                        )}
                        {log.type === 'info' && (
                          <span className="bg-cyan-950 text-cyan-400 px-1 rounded text-[10px]">
                            INFO
                          </span>
                        )}
                        <span className="text-slate-200 font-semibold">{log.text}</span>
                        {log.detail && <span className="text-slate-400 text-[11px]">{log.detail}</span>}
                      </div>
                    ))
                  )}
                  <div ref={logsEndRef} />
                </div>
              </div>

              {/* Scan Results Table Section */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                <div className="p-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    <h3 className="font-semibold text-sm text-slate-200">Scan Results</h3>
                    <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                      {filteredResults.length} / {results.length} rows
                    </span>
                  </div>

                  {/* Filter tabs */}
                  <div className="flex items-center space-x-2">
                    <div className="flex bg-slate-800/80 rounded-lg p-0.5 text-xs">
                      <button
                        onClick={() => setTableFilter('all')}
                        className={`px-2 py-1 rounded ${
                          tableFilter === 'all' ? 'bg-slate-700 text-white font-medium' : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        All
                      </button>
                      <button
                        onClick={() => setTableFilter('detected')}
                        className={`px-2 py-1 rounded ${
                          tableFilter === 'detected'
                            ? 'bg-slate-700 text-emerald-400 font-medium'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Detected
                      </button>
                      <button
                        onClick={() => setTableFilter('cracked')}
                        className={`px-2 py-1 rounded ${
                          tableFilter === 'cracked'
                            ? 'bg-slate-700 text-rose-400 font-medium'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Cracked / Open
                      </button>
                    </div>

                    <label className="text-xs text-slate-400 flex items-center space-x-1 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={onlyFound}
                        onChange={(e) => setOnlyFound(e.target.checked)}
                        className="rounded accent-cyan-500 h-3 w-3"
                      />
                      <span>Only Found</span>
                    </label>
                  </div>
                </div>

                {/* Search Bar */}
                <div className="px-3 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center space-x-2">
                  <Search className="h-3.5 w-3.5 text-slate-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by IP, port, version, or password..."
                    className="bg-transparent text-xs w-full focus:outline-none text-slate-200 placeholder:text-slate-600"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="text-xs text-slate-500 hover:text-slate-300"
                    >
                      Clear
                    </button>
                  )}
                </div>

                {/* Table Content */}
                <div className="overflow-x-auto max-h-[360px] overflow-y-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 font-medium border-b border-slate-800 sticky top-0 z-10">
                      <tr>
                        <th className="py-2.5 px-3">Target</th>
                        <th className="py-2.5 px-3">RFB</th>
                        <th className="py-2.5 px-3">Detected</th>
                        <th className="py-2.5 px-3">Security</th>
                        <th className="py-2.5 px-3">Auth / Result</th>
                        <th className="py-2.5 px-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {filteredResults.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                            {results.length === 0 ? 'No scan executed yet.' : 'No results match filter.'}
                          </td>
                        </tr>
                      ) : (
                        filteredResults.map((r, i) => {
                          const isCracked = r.auth_success && r.winner;
                          const isOpen = r.security === 'none';

                          return (
                            <tr
                              key={`${r.ip}:${r.port}-${i}`}
                              className={`hover:bg-slate-800/40 transition ${
                                isOpen || isCracked ? 'bg-rose-950/20' : ''
                              }`}
                            >
                              <td className="py-2 px-3 text-cyan-300 font-medium">
                                {r.ip}:{r.port}
                              </td>
                              <td className="py-2 px-3 text-slate-400">{r.proto ? `v${r.proto}` : '—'}</td>
                              <td className="py-2 px-3">
                                {r.detected ? (
                                  <span className="text-emerald-400 font-semibold">YES</span>
                                ) : (
                                  <span className="text-slate-600">no</span>
                                )}
                              </td>
                              <td className="py-2 px-3">
                                {r.security === 'none' && (
                                  <span className="text-rose-400 font-bold">none</span>
                                )}
                                {r.security === 'vncauth' && (
                                  <span className="text-amber-400">vncauth</span>
                                )}
                                {r.security === 'unsupported' && (
                                  <span className="text-slate-500">unsupported</span>
                                )}
                                {!r.security && <span className="text-slate-600">—</span>}
                              </td>
                              <td className="py-2 px-3">
                                {r.error ? (
                                  <span
                                    className="text-rose-400 font-sans text-[11px] truncate max-w-[140px] block"
                                    title={r.error}
                                  >
                                    {r.error}
                                  </span>
                                ) : isOpen ? (
                                  <span className="text-rose-400 font-bold bg-rose-950/80 px-1.5 py-0.5 rounded border border-rose-800/60">
                                    OPEN (no auth)
                                  </span>
                                ) : isCracked ? (
                                  <span className="text-rose-400 font-bold bg-rose-950/80 px-1.5 py-0.5 rounded border border-rose-800/60">
                                    SUCCESS ({r.winner?.[1] || '<empty>'})
                                  </span>
                                ) : r.detected && r.security === 'vncauth' ? (
                                  <span className="text-amber-400">failed</span>
                                ) : (
                                  <span className="text-slate-600">—</span>
                                )}
                              </td>
                              <td className="py-2 px-3 text-right">
                                <button
                                  type="button"
                                  onClick={() => handleCopyUrl(r.url)}
                                  className="text-slate-400 hover:text-cyan-300 p-1 hover:bg-slate-800 rounded transition"
                                  title="Copy vnc:// URL"
                                >
                                  {copiedUrl === r.url ? (
                                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="h-3.5 w-3.5" />
                                  )}
                                </button>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Bulk Proxy Tester & Manager */}
        {activeTab === 'proxies' && (
          <div className="space-y-6 max-w-6xl mx-auto w-full">
            {/* Top Stats Banner */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
                <span className="text-xs text-slate-400 uppercase font-medium">Tested Proxies</span>
                <div className="text-xl font-bold font-mono text-slate-100 mt-1">
                  {proxyTestResults.length}
                </div>
              </div>
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
                <span className="text-xs text-slate-400 uppercase font-medium">Alive / Working</span>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                  {proxyAliveCount}
                </div>
              </div>
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
                <span className="text-xs text-slate-400 uppercase font-medium">Dead / Failed</span>
                <div className="text-xl font-bold font-mono text-rose-400 mt-1">
                  {proxyDeadCount}
                </div>
              </div>
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm">
                <span className="text-xs text-slate-400 uppercase font-medium">Scanner Pool Active</span>
                <div className="text-xl font-bold font-mono text-purple-400 mt-1">
                  {activeProxyPool.length}
                </div>
              </div>
            </div>

            {/* Split Input & Actions */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              {/* Left Column: File upload & Textarea Input (5 cols) */}
              <div className="lg:col-span-5 space-y-4">
                <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h2 className="font-semibold text-sm text-slate-100 flex items-center space-x-2">
                      <FileText className="h-4 w-4 text-purple-400" />
                      <span>Bulk Proxies Input</span>
                    </h2>
                    <span className="text-xs text-slate-400 font-mono">1 proxy per line</span>
                  </div>

                  {/* File Drag and Drop Zone */}
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setFileDragOver(true);
                    }}
                    onDragLeave={() => setFileDragOver(false)}
                    onDrop={onDropFile}
                    onClick={() => fileInputRef.current?.click()}
                    className={`border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition ${
                      fileDragOver
                        ? 'border-purple-400 bg-purple-950/40'
                        : 'border-slate-700/80 hover:border-purple-500/80 bg-slate-950/40'
                    }`}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".txt,.csv"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files.length > 0) {
                          handleFileUpload(e.target.files[0]);
                        }
                      }}
                    />
                    <Upload className="h-6 w-6 text-purple-400 mx-auto mb-1.5" />
                    <p className="text-xs font-medium text-slate-200">
                      Click to insert proxy file or drag &amp; drop (.txt, .csv)
                    </p>
                    <p className="text-[11px] text-slate-500 mt-0.5">
                      Accepts IP:Port, SOCKS5, HTTP, or SOCKS4 formats
                    </p>
                  </div>

                  {/* Proxifly GitHub SOCKS5 Importer Card */}
                  <div className="bg-gradient-to-br from-purple-950/50 to-slate-900 border border-purple-800/60 rounded-xl p-3.5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Sparkles className="h-4 w-4 text-purple-400" />
                        <span className="text-xs font-semibold text-purple-200">
                          Proxifly SOCKS5 Importer
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-purple-300 bg-purple-900/60 px-2 py-0.5 rounded border border-purple-700/50">
                        proxifly/free-proxy-list (GitHub)
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Import and test live SOCKS5 proxies from Proxifly&apos;s free proxy repository on GitHub.
                    </p>

                    <div className="flex items-center space-x-2">
                      <select
                        value={proxiflyLimit}
                        onChange={(e) => setProxiflyLimit(Number(e.target.value))}
                        className="bg-slate-950 border border-purple-700/60 rounded px-2 py-1.5 text-xs text-purple-200 font-mono"
                        title="Proxy limit"
                      >
                        <option value={50}>50 proxies</option>
                        <option value={100}>100 proxies</option>
                        <option value={200}>200 proxies</option>
                        <option value={500}>500 proxies</option>
                      </select>

                      <button
                        type="button"
                        onClick={() => handleImportProxifly(false)}
                        disabled={isImportingProxifly || isTestingBulkProxies}
                        className="flex-1 py-1.5 px-3 bg-purple-900/70 hover:bg-purple-800 text-purple-100 border border-purple-700/70 rounded-lg text-xs font-medium transition flex items-center justify-center space-x-1.5 disabled:opacity-50"
                      >
                        {isImportingProxifly ? (
                          <RefreshCw className="h-3 w-3 animate-spin" />
                        ) : (
                          <Download className="h-3 w-3 text-purple-300" />
                        )}
                        <span>{isImportingProxifly ? 'Importing...' : 'Import SOCKS5'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleImportProxifly(true)}
                        disabled={isImportingProxifly || isTestingBulkProxies}
                        className="flex-1 py-1.5 px-3 bg-gradient-to-r from-purple-600 to-emerald-600 hover:from-purple-500 hover:to-emerald-500 text-white rounded-lg text-xs font-medium transition flex items-center justify-center space-x-1.5 shadow-md shadow-purple-900/30 disabled:opacity-50"
                      >
                        {isImportingProxifly ? (
                          <RefreshCw className="h-3 w-3 animate-spin" />
                        ) : (
                          <Play className="h-3 w-3 fill-white" />
                        )}
                        <span>Import &amp; Test All</span>
                      </button>
                    </div>

                    {proxiflySourceInfo && (
                      <div className="text-[10px] text-emerald-400 font-mono truncate flex items-center space-x-1 bg-emerald-950/40 p-1.5 rounded border border-emerald-900/40">
                        <CheckCircle2 className="h-3 w-3 shrink-0" />
                        <span>{proxiflySourceInfo}</span>
                      </div>
                    )}
                  </div>

                  {/* Textarea */}
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-xs font-medium text-slate-300">Proxy List</label>
                      <button
                        type="button"
                        onClick={() =>
                          setBulkProxiesText(
                            '127.0.0.1:1080\nsocks5://127.0.0.1:9050\nhttp://127.0.0.1:8080\n10.0.0.1:1080\n192.168.1.1:8080'
                          )
                        }
                        className="text-[11px] text-purple-400 hover:text-purple-300 underline"
                      >
                        Insert Sample List
                      </button>
                    </div>
                    <textarea
                      rows={6}
                      value={bulkProxiesText}
                      onChange={(e) => setBulkProxiesText(e.target.value)}
                      placeholder="127.0.0.1:1080&#10;socks5://user:pass@host:1080&#10;http://host:8080"
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-purple-500"
                    />
                  </div>

                  {/* Settings */}
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Default Type</label>
                      <select
                        value={proxyType}
                        onChange={(e) => setProxyType(e.target.value as any)}
                        className="w-full bg-slate-950 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-200"
                      >
                        <option value="socks5">SOCKS5</option>
                        <option value="http">HTTP</option>
                        <option value="socks4">SOCKS4</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Timeout</label>
                      <input
                        type="number"
                        min={1}
                        max={10}
                        step={0.5}
                        value={proxyTimeoutSec}
                        onChange={(e) => setProxyTimeoutSec(Number(e.target.value))}
                        className="w-full bg-slate-950 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-200 font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Concurrency</label>
                      <input
                        type="number"
                        min={1}
                        max={40}
                        value={proxyConcurrency}
                        onChange={(e) => setProxyConcurrency(Number(e.target.value))}
                        className="w-full bg-slate-950 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-200 font-mono"
                      />
                    </div>
                  </div>

                  {/* Primary Test Action */}
                  <button
                    type="button"
                    onClick={handleTestAllProxies}
                    disabled={isTestingBulkProxies}
                    className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium text-xs flex items-center justify-center space-x-2 shadow-lg shadow-purple-900/20 transition disabled:opacity-50"
                  >
                    {isTestingBulkProxies ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Radio className="h-4 w-4" />
                    )}
                    <span>{isTestingBulkProxies ? 'Testing All Proxies...' : 'Test All Proxies'}</span>
                  </button>
                </div>
              </div>

              {/* Right Column: Tested Proxies Table & Pool Activation (7 cols) */}
              <div className="lg:col-span-7 space-y-4">
                <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
                  {/* Table Header and Filter Toolbar */}
                  <div className="p-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center space-x-2">
                      <h3 className="font-semibold text-sm text-slate-200">Proxy Test Results</h3>
                      <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                        {filteredProxyResults.length} / {proxyTestResults.length}
                      </span>
                    </div>

                    {/* Filter buttons */}
                    <div className="flex items-center space-x-2">
                      <div className="flex bg-slate-800/80 rounded-lg p-0.5 text-xs">
                        <button
                          onClick={() => setBulkFilter('all')}
                          className={`px-2 py-1 rounded ${
                            bulkFilter === 'all'
                              ? 'bg-slate-700 text-white font-medium'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          All ({proxyTestResults.length})
                        </button>
                        <button
                          onClick={() => setBulkFilter('alive')}
                          className={`px-2 py-1 rounded ${
                            bulkFilter === 'alive'
                              ? 'bg-slate-700 text-emerald-400 font-medium'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Alive ({proxyAliveCount})
                        </button>
                        <button
                          onClick={() => setBulkFilter('dead')}
                          className={`px-2 py-1 rounded ${
                            bulkFilter === 'dead'
                              ? 'bg-slate-700 text-rose-400 font-medium'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Dead ({proxyDeadCount})
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Actions Toolbar: Use in Scanner, Export, Clear */}
                  <div className="px-3.5 py-2.5 bg-slate-900/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <button
                        type="button"
                        onClick={handleUseAliveInScanner}
                        disabled={proxyAliveCount === 0}
                        className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-medium flex items-center space-x-1.5 shadow transition"
                      >
                        <CheckCheck className="h-3.5 w-3.5" />
                        <span>Use Alive Proxies in Scanner ({proxyAliveCount})</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleClearDead}
                        disabled={proxyDeadCount === 0}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 text-xs flex items-center space-x-1 transition"
                      >
                        <Trash2 className="h-3 w-3 text-rose-400" />
                        <span>Remove Dead</span>
                      </button>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        type="button"
                        onClick={handleExportAlive}
                        disabled={proxyAliveCount === 0}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 text-xs flex items-center space-x-1 transition"
                      >
                        <Download className="h-3 w-3 text-cyan-400" />
                        <span>Alive (.txt)</span>
                      </button>
                      <button
                        type="button"
                        onClick={handleExportAllProxyCsv}
                        disabled={proxyTestResults.length === 0}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 text-xs flex items-center space-x-1 transition"
                      >
                        <FileSpreadsheet className="h-3 w-3 text-emerald-400" />
                        <span>CSV Report</span>
                      </button>
                    </div>
                  </div>

                  {/* Search Bar */}
                  <div className="px-3 py-2 bg-slate-950/60 border-b border-slate-800 flex items-center space-x-2">
                    <Search className="h-3.5 w-3.5 text-slate-500" />
                    <input
                      type="text"
                      value={bulkSearch}
                      onChange={(e) => setBulkSearch(e.target.value)}
                      placeholder="Search tested proxies by host, port, or error..."
                      className="bg-transparent text-xs w-full focus:outline-none text-slate-200 placeholder:text-slate-600"
                    />
                    {bulkSearch && (
                      <button
                        onClick={() => setBulkSearch('')}
                        className="text-xs text-slate-500 hover:text-slate-300"
                      >
                        Clear
                      </button>
                    )}
                  </div>

                  {/* Results Table */}
                  <div className="overflow-x-auto max-h-[380px] overflow-y-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400 font-medium border-b border-slate-800 sticky top-0 z-10">
                        <tr>
                          <th className="py-2 px-3">Proxy Endpoint</th>
                          <th className="py-2 px-3">Protocol</th>
                          <th className="py-2 px-3">Status</th>
                          <th className="py-2 px-3">Latency</th>
                          <th className="py-2 px-3">Verification Details / Error</th>
                          <th className="py-2 px-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {filteredProxyResults.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                              {proxyTestResults.length === 0
                                ? 'No proxies tested yet. Click "Test All Proxies" to verify your list.'
                                : 'No proxies match filter criteria.'}
                            </td>
                          </tr>
                        ) : (
                          filteredProxyResults.map((p, idx) => (
                            <tr
                              key={p.id || idx}
                              className={`hover:bg-slate-800/40 transition ${
                                p.status === 'alive' ? 'bg-emerald-950/10' : ''
                              }`}
                            >
                              <td className="py-2 px-3 text-slate-200 font-medium truncate max-w-[180px]">
                                {p.raw}
                              </td>
                              <td className="py-2 px-3 text-purple-300 uppercase text-[11px]">
                                {p.protocol}
                              </td>
                              <td className="py-2 px-3">
                                {p.status === 'alive' ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                                    ALIVE
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">
                                    DEAD
                                  </span>
                                )}
                              </td>
                              <td className="py-2 px-3">
                                {p.latencyMs !== undefined ? (
                                  <span
                                    className={`font-semibold ${
                                      p.latencyMs < 200
                                        ? 'text-emerald-400'
                                        : p.latencyMs < 600
                                        ? 'text-amber-400'
                                        : 'text-rose-400'
                                    }`}
                                  >
                                    {p.latencyMs}ms
                                  </span>
                                ) : (
                                  <span className="text-slate-600">—</span>
                                )}
                              </td>
                              <td className="py-2 px-3 text-slate-400 font-sans text-[11px] truncate max-w-[200px]" title={p.error || p.details}>
                                {p.error ? (
                                  <span className="text-rose-400">{p.error}</span>
                                ) : (
                                  <span className="text-emerald-400">{p.details || 'Handshake verified'}</span>
                                )}
                              </td>
                              <td className="py-2 px-3 text-right">
                                <div className="flex items-center justify-end space-x-1">
                                  <button
                                    type="button"
                                    onClick={() => handleTestSingleRowProxy(p)}
                                    disabled={testingSingleId === p.id}
                                    className="p-1 text-slate-400 hover:text-purple-300 hover:bg-slate-800 rounded transition"
                                    title="Re-test this proxy"
                                  >
                                    <RefreshCw className={`h-3 w-3 ${testingSingleId === p.id ? 'animate-spin text-purple-400' : ''}`} />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleCopyUrl(p.raw)}
                                    className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition"
                                    title="Copy proxy string"
                                  >
                                    {copiedUrl === p.raw ? (
                                      <Check className="h-3 w-3 text-emerald-400" />
                                    ) : (
                                      <Copy className="h-3 w-3" />
                                    )}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Passwords & Wordlist Management */}
        {activeTab === 'passwords' && (
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 shadow-sm max-w-3xl mx-auto w-full space-y-5">
            <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-base text-slate-100 flex items-center space-x-2">
                  <KeyRound className="h-5 w-5 text-amber-400" />
                  <span>VNC Authentication Wordlist</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Classic VNC Authentication is password-only (no username) and only evaluates the first 8 characters.
                </p>
              </div>
              <span className="px-2.5 py-1 bg-amber-950/60 border border-amber-800/60 text-amber-400 text-xs font-mono rounded-lg">
                {passwords.length} Passwords Loaded
              </span>
            </div>

            {/* Add Password Form */}
            <form onSubmit={handleAddPassword} className="flex gap-2">
              <input
                type="text"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter password to test (e.g. password, admin, 123456)..."
                className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition"
              >
                Add Password
              </button>
            </form>

            {/* Password Tags List */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-400">Current Dictionary Entries:</label>
              <div className="flex flex-wrap gap-2 p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg min-h-[100px]">
                {passwords.map((pwd) => (
                  <span
                    key={pwd}
                    className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono bg-slate-800 text-slate-200 border border-slate-700/80 group"
                  >
                    <span>{pwd}</span>
                    <button
                      type="button"
                      onClick={() => handleRemovePassword(pwd)}
                      className="ml-2 text-slate-500 group-hover:text-rose-400 hover:scale-110 transition"
                      title="Remove password"
                    >
                      &times;
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Presets / Reset */}
            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => setPasswords(['password', 'admin', '123456', 'root', '1234', 'secret', 'vnc'])}
                className="text-xs text-slate-400 hover:text-slate-200 underline"
              >
                Reset to default wordlist (creds/vnc.txt)
              </button>
              <button
                type="button"
                onClick={() => setPasswords([])}
                className="text-xs text-rose-400 hover:text-rose-300"
              >
                Clear all passwords
              </button>
            </div>
          </div>
        )}

        {/* Tab 4: RFB Protocol & Proxy Documentation */}
        {activeTab === 'docs' && (
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-6 shadow-sm max-w-4xl mx-auto w-full space-y-6">
            <div className="border-b border-slate-800 pb-4">
              <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
                <ShieldAlert className="h-5 w-5 text-cyan-400" />
                <span>VNC RFB Protocol, Port Skipping &amp; Bulk Proxy Guide</span>
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Detailed reference for port syntax skipping, proxy pooling, and RFB security handshakes.
              </p>
            </div>

            {/* Port Skipping Guide */}
            <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-xl space-y-3">
              <h3 className="font-semibold text-cyan-400 text-sm flex items-center space-x-2">
                <Layers className="h-4 w-4" />
                <span>Skipping Ports with Comma (,) Syntax</span>
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                When auditing VNC servers, you frequently want to probe specific display numbers or ports while skipping intervening numbers.
                In RFB, Display <code className="text-cyan-300 font-mono">:0</code> corresponds to TCP port 5900, Display <code className="text-cyan-300 font-mono">:1</code> is 5901, and Display <code className="text-cyan-300 font-mono">:N</code> is <code className="text-cyan-300 font-mono">5900 + N</code>.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <div className="text-cyan-300 font-bold mb-1">5900, 5902, 5905</div>
                  <div className="text-slate-400 text-[11px] font-sans">
                    Explicitly probes 5900, 5902, and 5905 — skipping 5901, 5903, and 5904.
                  </div>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <div className="text-cyan-300 font-bold mb-1">:0, :2, :5</div>
                  <div className="text-slate-400 text-[11px] font-sans">
                    Display offset shorthand that resolves to ports 5900, 5902, and 5905.
                  </div>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <div className="text-cyan-300 font-bold mb-1">5900-5902, 5905</div>
                  <div className="text-slate-400 text-[11px] font-sans">
                    Probes range 5900 to 5902, skips 5903-5904, and also probes 5905.
                  </div>
                </div>
                <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <div className="text-cyan-300 font-bold mb-1">5900, 5901, 5910</div>
                  <div className="text-slate-400 text-[11px] font-sans">
                    Tests primary displays and skips right to display :10 (port 5910).
                  </div>
                </div>
              </div>
            </div>

            {/* Bulk Proxy Guide */}
            <div className="bg-slate-950/70 border border-slate-800 p-4 rounded-xl space-y-3">
              <h3 className="font-semibold text-purple-400 text-sm flex items-center space-x-2">
                <Globe className="h-4 w-4" />
                <span>Bulk Proxy File Upload &amp; Load Balancing</span>
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                The scanner includes a bulk proxy tester where you can upload a file (.txt or .csv) or paste a list of proxies.
                Once verified, the scanner distributes your parallel VNC probe jobs across all working proxies via round-robin routing:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="font-bold text-purple-300 font-mono">1. File Upload / Paste</span>
                  <p className="text-slate-400 mt-1 text-[11px]">
                    Drag and drop your proxy file or paste raw lists in IP:Port, SOCKS5, HTTP, or SOCKS4 formats.
                  </p>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="font-bold text-purple-300 font-mono">2. Concurrent Verification</span>
                  <p className="text-slate-400 mt-1 text-[11px]">
                    Tests each proxy concurrently, identifying dead proxies, measuring latency, and validating handshakes.
                  </p>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="font-bold text-purple-300 font-mono">3. One-Click Scanner Pool</span>
                  <p className="text-slate-400 mt-1 text-[11px]">
                    Click &quot;Use Alive Proxies in Scanner&quot; to distribute VNC connections round-robin across alive proxies.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-3 text-center text-xs text-slate-500">
        VNC RFB Service Scanner &amp; Security Auditor &bull; Authorized Security Auditing Only
      </footer>
    </div>
  );
}
