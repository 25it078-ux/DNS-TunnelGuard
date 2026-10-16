import { useState, useEffect } from "react";
import "./App.css";
import {
  analyzeCsv,
  checkBackendHealth,
  fetchModelInfo
} from "./services/api";

import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";


function App() {
  const [activePage, setActivePage] = useState("Home");
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [backendStatus, setBackendStatus] = useState("CHECKING");
  const [modelMeta, setModelMeta] = useState(null);

  // Analysis result state
  const [totalRecords, setTotalRecords] = useState(0);
  const [normalRecords, setNormalRecords] = useState(0);
  const [suspiciousDomains, setSuspiciousDomains] = useState([]);
  const [suspiciousItems, setSuspiciousItems] = useState([]);
  const [prediction, setPrediction] = useState(null);
  const [confidence, setConfidence] = useState(null);
  const [detectionRate, setDetectionRate] = useState(null);
  const [detectionReasons, setDetectionReasons] = useState([]);
  const [analysisSource, setAnalysisSource] = useState(null);
  const [allRecords, setAllRecords] = useState([]);

  // First record feature display
  const [domainLength, setDomainLength] = useState(null);
  const [subdomainCount, setSubdomainCount] = useState(null);
  const [queryLength, setQueryLength] = useState(null);
  const [entropy, setEntropy] = useState(null);
  const [requestFrequency, setRequestFrequency] = useState(null);
  const [numericRatio, setNumericRatio] = useState(null);
  
  const scatterData = allRecords
    .map((record) => {
      const metrics = record.display_metrics || {};

      return {
        domain: record.domain || "Unknown",
        queryLength: Number(
          metrics.queryLength ?? record.domain?.length
        ),
        entropy: Number(
          metrics.entropy ?? record.shannon_entropy
        ),
        prediction: record.prediction || "NORMAL",
      };
    })
    .filter(
      (record) =>
        Number.isFinite(record.queryLength) &&
        Number.isFinite(record.entropy)
    );


  // Check backend health on initial load
  useEffect(() => {
    let isMounted = true;
    checkBackendHealth().then((health) => {
      if (!isMounted) return;
      if (health.online) {
        setBackendStatus("ONLINE");
        fetchModelInfo().then((meta) => {
          if (isMounted) setModelMeta(meta);
        });
      } else {
        setBackendStatus("OFFLINE");
      }
    });
    return () => {
      isMounted = false;
    };
  }, []);

  const processAnalysisResult = (result) => {
    const summary = result.summary || {};
    setAllRecords(Array.isArray(result.records) ? result.records : []);
    const firstRec = result.first_record_features || {};
    const metrics = firstRec.display_metrics || {};

    setTotalRecords(summary.total_records || 0);
    setNormalRecords(summary.normal_count || 0);
    setDetectionRate(summary.detection_rate_pct ?? 0);
    setAnalysisSource(result.source || "LOCAL_RULES");

    // Suspicious lists
    const suspItems = result.suspicious_domains || [];
    setSuspiciousItems(suspItems);
    setSuspiciousDomains(suspItems.map((item) => item.domain));

    // First record metrics
    setQueryLength(metrics.queryLength ?? firstRec.domain?.length ?? null);
    setDomainLength(metrics.domainLength ?? firstRec.domain?.length ?? null);
    setSubdomainCount(metrics.subdomainCount ?? 0);
    setEntropy(metrics.entropy !== undefined ? Number(metrics.entropy).toFixed(2) : null);
    setNumericRatio(metrics.numericRatio !== undefined ? Number(metrics.numericRatio).toFixed(2) : null);
    setRequestFrequency(summary.total_records || 0);

    // Global prediction
    setPrediction(summary.overall_status || (suspItems.length > 0 ? "DNS TUNNELING" : "NORMAL"));
    setConfidence(firstRec.confidence ? `${firstRec.confidence}%` : `${summary.avg_confidence || 95.0}%`);
    setDetectionReasons(firstRec.reasons || []);
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setIsAnalyzing(true);
    setSelectedFile(file);

    try {
      const result = await analyzeCsv(file);
      processAnalysisResult(result, file.name);
    } catch (err) {
      alert("Error analyzing CSV: " + err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUseDemoDataset = async () => {
    setIsAnalyzing(true);
    try {
      const response = await fetch("/dns_traffic_demo.csv");
      if (!response.ok) {
        throw new Error("Could not load demo dataset file.");
      }
      const text = await response.text();
      const demoFile = new File([text], "dns_traffic_demo.csv", { type: "text/csv" });
      setSelectedFile(demoFile);
      const result = await analyzeCsv(demoFile);
      processAnalysisResult(result, "dns_traffic_demo.csv");
    } catch (err) {
      alert("Failed to load demo dataset: " + err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const navItems = [
    "Home",
    "Dashboard",
    "Traffic Analyzer",
    "Threats",
    "Analytics",
    "ML Model",
    "Learn",
  ];

  return (
    <div className="app">
      {/* NAVBAR */}
      <nav className="navbar">
        <div className="brand" onClick={() => setActivePage("Home")}>
          <div className="brand-icon">◈</div>
          <div>
            <h2>DNS TUNNELGUARD</h2>
            <span>AI-POWERED DNS SECURITY</span>
          </div>
        </div>

        <div className="nav-links">
          {navItems.map((item) => (
            <button
              key={item}
              className={activePage === item ? "nav-active" : ""}
              onClick={() => setActivePage(item)}
            >
              {item}
            </button>
          ))}
        </div>
      </nav>

      {/* HOME */}
      {activePage === "Home" && (
        <main>
          <section className="hero">
            <div className="hero-content">
              <div className="status-badge">
                <span className="pulse"></span>
                ML-POWERED DNS SECURITY
              </div>

              <h1>
                Detect Hidden Threats
                <br />
                <span>Inside DNS Traffic</span>
              </h1>

              <p>
                DNS TUNNELGUARD uses machine learning and DNS traffic
                characteristics to identify suspicious DNS tunneling attacks
                before they become a serious security threat.
              </p>

              <div className="hero-buttons">
                <button
                  className="primary-btn"
                  onClick={() => setActivePage("Dashboard")}
                >
                  Open Security Dashboard →
                </button>

                <button
                  className="secondary-btn"
                  onClick={() => setActivePage("Learn")}
                >
                  Learn About DNS Tunneling
                </button>
              </div>
            </div>

            <div className="hero-visual">
              <div className="radar">
                <div className="radar-circle circle1"></div>
                <div className="radar-circle circle2"></div>
                <div className="radar-circle circle3"></div>
                <div className="radar-line"></div>
                <div className="radar-center">DNS</div>
              </div>
              <div className="scan-text">● LIVE THREAT MONITORING</div>
            </div>
          </section>

          {/* FEATURES */}
          <section className="section">
            <div className="section-heading">
              <span>SECURITY CAPABILITIES</span>
              <h2>Built to Detect DNS Tunneling</h2>
              <p>
                Analyze DNS traffic patterns and identify abnormal behavior
                using machine learning.
              </p>
            </div>

            <div className="feature-grid">
              <FeatureCard
                icon="⌁"
                title="DNS Traffic Analysis"
                text="Extract important characteristics from DNS requests and analyze suspicious traffic patterns."
              />

              <FeatureCard
                icon="◉"
                title="Machine Learning Detection"
                text="Classify DNS requests as normal or potential DNS tunneling activity."
              />

              <FeatureCard
                icon="⚠"
                title="Threat Detection"
                text="Generate security alerts when suspicious DNS behavior is detected."
              />

              <FeatureCard
                icon="◫"
                title="Security Analytics"
                text="Visualize traffic trends, suspicious domains, entropy and model confidence."
              />
            </div>
          </section>

          {/* WORKFLOW */}
          <section className="workflow-section">
            <div className="section-heading">
              <span>HOW IT WORKS</span>
              <h2>From DNS Traffic to Threat Detection</h2>
            </div>

            <div className="workflow">
              <WorkflowStep
                number="01"
                title="DNS Traffic"
                text="Collect DNS request information."
              />

              <div className="arrow">→</div>

              <WorkflowStep
                number="02"
                title="Feature Extraction"
                text="Calculate DNS traffic characteristics."
              />

              <div className="arrow">→</div>

              <WorkflowStep
                number="03"
                title="ML Prediction"
                text="Classify normal or tunneling traffic."
              />

              <div className="arrow">→</div>

              <WorkflowStep
                number="04"
                title="Threat Alert"
                text="Display risk and suspicious activity."
              />
            </div>
          </section>

          {/* DEMO STATS */}
          <section className="stats-section">
            <div className="stat-card">
              <span>Total DNS Requests</span>
              <strong>{totalRecords > 0 ? totalRecords.toLocaleString() : "12,480"}</strong>
              <small>{totalRecords > 0 ? "ANALYZED DATA" : "DEMO DATA"}</small>
            </div>

            <div className="stat-card">
              <span>Normal Traffic</span>
              <strong className="green">
                {totalRecords > 0 ? normalRecords.toLocaleString() : "11,932"}
              </strong>
              <small>{totalRecords > 0 ? "VERIFIED CLEAN" : "DEMO DATA"}</small>
            </div>

            <div className="stat-card">
              <span>Suspicious Traffic</span>
              <strong className="red">
                {totalRecords > 0 ? suspiciousDomains.length.toLocaleString() : "548"}
              </strong>
              <small>{totalRecords > 0 ? "THREATS FLAGGED" : "DEMO DATA"}</small>
            </div>

            <div className="stat-card">
              <span>Detection Rate</span>
              <strong className="cyan">
                {detectionRate !== null ? `${detectionRate}%` : "94.8%"}
              </strong>
              <small>{totalRecords > 0 ? "ACCURACY METRIC" : "DEMO DATA"}</small>
            </div>
          </section>
        </main>
      )}

      {/* DASHBOARD */}
      {activePage === "Dashboard" && (
        <main className="dashboard-page">
          <div className="dashboard-header">
            <div>
              <div className="status-badge">
                <span className="pulse"></span>
                SECURITY OPERATIONS CENTER
              </div>

              <h1>DNS Security Dashboard</h1>

              <p>
                Real-time overview of DNS traffic and machine-learning threat
                detection.
              </p>
            </div>

            <div className="demo-badge">
              {backendStatus === "ONLINE"
                ? "● ML BACKEND ONLINE"
                : totalRecords > 0
                ? "● ACTIVE DATASET"
                : "● DEMO DATA"}
            </div>
          </div>

          {/* STAT CARDS */}
          <section className="dashboard-stats">
            <div className="dashboard-stat">
              <span>Total DNS Requests</span>
              <strong>{totalRecords > 0 ? totalRecords.toLocaleString() : "—"}</strong>
              <small>Last 24 hours</small>
            </div>

            <div className="dashboard-stat normal-stat">
              <span>Normal Requests</span>
              <strong>
                {totalRecords > 0 ? normalRecords.toLocaleString() : "—"}
              </strong>
              <small>
                {totalRecords > 0
                  ? analysisSource === "ML_BACKEND"
                    ? "Classified clean by ML model"
                    : "Based on local detection rules"
                  : "Awaiting analysis"}
              </small>
            </div>

            <div className="dashboard-stat suspicious-stat">
              <span>Suspicious Requests</span>
              <strong>
                {totalRecords > 0 ? suspiciousDomains.length : "—"}
              </strong>
              <small>
                {analysisSource === "ML_BACKEND"
                  ? "Flagged by Random Forest model"
                  : "Flagged by detection rules"}
              </small>
            </div>

            <div className="dashboard-stat threat-stat">
              <span>Tunneling Detected</span>
              <strong>
                {totalRecords > 0 ? suspiciousDomains.length : "—"}
              </strong>
              <small>Potential suspicious domains</small>
            </div>
          </section>

          {/* MAIN DASHBOARD GRID */}
          <section className="dashboard-grid">
            <div className="dashboard-panel traffic-panel">
              <div className="panel-header">
                <div>
                  <h2>DNS Traffic Overview</h2>
                  <p>Requests analyzed over the last 24 hours</p>
                </div>

                <span className="live-label">● LIVE</span>
              </div>

              <div className="traffic-chart">
                <div className="chart-y">
                  <span>600</span>
                  <span>400</span>
                  <span>200</span>
                  <span>0</span>
                </div>

                <div className="chart-area">
                  <div className="grid-line"></div>
                  <div className="grid-line"></div>
                  <div className="grid-line"></div>
                  <div className="grid-line"></div>

                  <div className="chart-bars">
                    <i style={{ height: "35%" }}></i>
                    <i style={{ height: "50%" }}></i>
                    <i style={{ height: "42%" }}></i>
                    <i style={{ height: "65%" }}></i>
                    <i style={{ height: "55%" }}></i>
                    <i style={{ height: "78%" }}></i>
                    <i style={{ height: "70%" }}></i>
                    <i style={{ height: "90%" }}></i>
                    <i style={{ height: "62%" }}></i>
                    <i style={{ height: "82%" }}></i>
                    <i style={{ height: "73%" }}></i>
                    <i style={{ height: "95%" }}></i>
                  </div>
                </div>
              </div>
            </div>

            {/* DETECTION SUMMARY */}
            <div className="dashboard-panel detection-panel">
              <div className="panel-header">
                <div>
                  <h2>Detection Summary</h2>
                  <p>ML classification results</p>
                </div>
              </div>

              <div className="detection-circle">
                <div>
                  <strong>
                    {totalRecords > 0
                      ? `${detectionRate}%`
                      : "94.8%"}
                  </strong>
                  <span>{totalRecords > 0 ? "Tunneling %" : "Detection Rate"}</span>
                </div>
              </div>

              <div className="legend">
                <div>
                  <span className="legend-dot normal-dot"></span>
                  Normal
                  <strong>
                    {totalRecords > 0
                      ? `${(100 - (detectionRate || 0)).toFixed(1)}%`
                      : "95.6%"}
                  </strong>
                </div>

                <div>
                  <span className="legend-dot suspicious-dot"></span>
                  Suspicious
                  <strong>
                    {totalRecords > 0
                      ? `${detectionRate || 0}%`
                      : "4.4%"}
                  </strong>
                </div>
              </div>
            </div>
          </section>

          {/* ALERTS */}
          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Recent Threat Alerts</h2>
                <p>Latest suspicious DNS activity</p>
              </div>

              <button
                className="view-btn"
                onClick={() => setActivePage("Threats")}
              >
                View All →
              </button>
            </div>

            <div className="alert-list">
              {suspiciousItems.length > 0 ? (
                suspiciousItems.slice(0, 3).map((item) => (
                  <div className="alert-row" key={item.domain}>
                    <div className="alert-icon high">!</div>
                    <div className="alert-info">
                      <strong>
                        {item.reasons && item.reasons[0]
                          ? item.reasons[0]
                          : "Suspicious DNS Tunneling Detected"}
                      </strong>
                      <span>{item.domain}</span>
                    </div>
                    <span className={`risk ${item.risk_level === "HIGH" ? "high-risk" : "medium-risk"}`}>
                      {item.risk_level}
                    </span>
                    <span className="confidence">{item.threat_percentage}%</span>
                  </div>
                ))
              ) : (
                <>
                  <div className="alert-row">
                    <div className="alert-icon high">!</div>
                    <div className="alert-info">
                      <strong>Suspicious DNS Query Detected</strong>
                      <span>data-transfer.example.net</span>
                    </div>
                    <span className="risk high-risk">HIGH</span>
                    <span className="confidence">98.2%</span>
                  </div>

                  <div className="alert-row">
                    <div className="alert-icon medium">!</div>
                    <div className="alert-info">
                      <strong>High Entropy Domain</strong>
                      <span>jx8k2m9q7x.example.org</span>
                    </div>
                    <span className="risk medium-risk">MEDIUM</span>
                    <span className="confidence">91.7%</span>
                  </div>

                  <div className="alert-row">
                    <div className="alert-icon high">!</div>
                    <div className="alert-info">
                      <strong>Abnormal Query Frequency</strong>
                      <span>tunnel-data.example.com</span>
                    </div>
                    <span className="risk high-risk">HIGH</span>
                    <span className="confidence">96.4%</span>
                  </div>
                </>
              )}
            </div>
          </section>

          {/* BOTTOM PANELS */}
          <section className="dashboard-grid bottom-grid">
            <div className="dashboard-panel">
              <div className="panel-header">
                <div>
                  <h2>Top Suspicious Domains</h2>
                  <p>Ranked by threat score</p>
                </div>
              </div>

              <div className="domain-list">
                {suspiciousItems.length > 0 ? (
                  suspiciousItems.slice(0, 4).map((item, idx) => (
                    <div className="domain-row" key={item.domain}>
                      <span>{String(idx + 1).padStart(2, "0")}</span>
                      <strong>{item.domain}</strong>
                      <b>{item.threat_percentage}%</b>
                    </div>
                  ))
                ) : (
                  <>
                    <div className="domain-row">
                      <span>01</span>
                      <strong>data-transfer.example.net</strong>
                      <b>98%</b>
                    </div>
                    <div className="domain-row">
                      <span>02</span>
                      <strong>jx8k2m9q7x.example.org</strong>
                      <b>92%</b>
                    </div>
                    <div className="domain-row">
                      <span>03</span>
                      <strong>tunnel-data.example.com</strong>
                      <b>89%</b>
                    </div>
                    <div className="domain-row">
                      <span>04</span>
                      <strong>encoded.example.net</strong>
                      <b>84%</b>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div className="dashboard-panel">
              <div className="panel-header">
                <div>
                  <h2>ML Model Status</h2>
                  <p>Current detection pipeline</p>
                </div>

                <span className="online-status">
                  {backendStatus === "ONLINE" ? "● ONLINE" : "● LOCAL ENGINE"}
                </span>
              </div>

              <div className="model-status">
                <div>
                  <span>Model</span>
                  <strong>
                    {modelMeta?.model_name || "Random Forest Classifier"}
                  </strong>
                </div>

                <div>
                  <span>Features</span>
                  <strong>10 DNS Features</strong>
                </div>

                <div>
                  <span>Classes</span>
                  <strong>Normal / Tunneling</strong>
                </div>

                <div>
                  <span>Status</span>
                  <strong className="online-text">
                    {backendStatus === "ONLINE"
                      ? "FastAPI ML Pipeline Active"
                      : "Ready for Analysis"}
                  </strong>
                </div>
              </div>
            </div>
          </section>
        </main>
      )}

      {/* THREATS PAGE */}
      {activePage === "Threats" && (
        <main className="dashboard-page">
          <div className="dashboard-header">
            <div>
              <div className="status-badge">THREAT MONITORING</div>
              <h1>Security Threats</h1>
              <p>
                Potentially suspicious domains identified by machine-learning analysis.
              </p>
            </div>
          </div>

          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Detected Suspicious Domains</h2>
                <p>Total flagged: {suspiciousItems.length || suspiciousDomains.length}</p>
              </div>
            </div>

            {suspiciousItems.length > 0 ? (
              suspiciousItems.map((item) => (
                <div className="alert-row" key={item.domain}>
                  <div className="alert-icon high">!</div>
                  <div className="alert-info">
                    <strong>
                      {item.reasons && item.reasons[0]
                        ? item.reasons[0]
                        : "Suspicious DNS Characteristics"}
                    </strong>
                    <span>{item.domain}</span>
                  </div>
                  <span className={`risk ${item.risk_level === "HIGH" ? "high-risk" : "medium-risk"}`}>
                    {item.risk_level || "REVIEW"}
                  </span>
                  <span className="confidence">{item.threat_percentage}%</span>
                </div>
              ))
            ) : suspiciousDomains.length > 0 ? (
              suspiciousDomains.map((domain) => (
                <div className="alert-row" key={domain}>
                  <div className="alert-icon high">!</div>
                  <div className="alert-info">
                    <strong>Suspicious DNS Characteristics</strong>
                    <span>{domain}</span>
                  </div>
                  <span className="risk high-risk">REVIEW</span>
                </div>
              ))
            ) : (
              <p>Upload a DNS CSV file in Traffic Analyzer to display flagged domains.</p>
            )}
          </section>
        </main>
      )}

      {/* ANALYTICS PAGE */}
      {activePage === "Analytics" && (
        <main className="dashboard-page">
          <div className="dashboard-header">
            <div>
              <div className="status-badge">DNS SECURITY INSIGHTS</div>
              <h1>Traffic Analytics</h1>
              <p>Summary of the DNS records analyzed by DNS TunnelGuard.</p>
            </div>
          </div>

          <section className="dashboard-stats">
            <div className="dashboard-stat">
              <span>Total DNS Records</span>
              <strong>{totalRecords}</strong>
              <small>Uploaded records</small>
            </div>

            <div className="dashboard-stat normal-stat">
              <span>Normal Records</span>
              <strong>{normalRecords}</strong>
              <small>Verified non-tunneling</small>
            </div>

            <div className="dashboard-stat suspicious-stat">
              <span>Flagged Domains</span>
              <strong>{suspiciousDomains.length}</strong>
              <small>Tunneling threats</small>
            </div>
          </section>

          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Analysis Summary</h2>
                <p>Current CSV analysis results</p>
              </div>
            </div>

            {totalRecords > 0 ? (
              <p>
                Analyzed {totalRecords} DNS records. The detection engine flagged{" "}
                {suspiciousDomains.length} domain(s) as potential DNS tunneling channels.
              </p>
            ) : (
              <p>Upload a CSV file in Traffic Analyzer to view analytics.</p>
            )}

            <p>
              {analysisSource === "ML_BACKEND"
                ? "Powered by Python FastAPI + Random Forest ML Model (10 DNS Traffic Features)."
                : "Note: Currently using local test-rule detection."}
            </p>
            
          <section className="dashboard-panel">
            <div className="panel-header">
              <div>
                <h2>DNS Traffic Scatter Plot</h2>
                <p>Query Length vs Shannon Entropy for analyzed records</p>
              </div>
            </div>

            {scatterData.length > 0 ? (
              <div style={{ width: "100%", height: 350 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 10 }}>
                    <CartesianGrid />
                    <XAxis
                      type="number"
                      dataKey="queryLength"
                      name="Query Length"
                      label={{ value: "Query Length", position: "insideBottom", offset: -10 }}
                    />
                    <YAxis
                      type="number"
                      dataKey="entropy"
                      name="Shannon Entropy"
                      label={{ value: "Shannon Entropy", angle: -90, position: "insideLeft" }}
                    />
                    <ZAxis range={[50, 50]} />
                    <Tooltip
                      cursor={{ strokeDasharray: "3 3" }}
                      formatter={(value, name) => [value, name]}
                      labelFormatter={() => ""}
                    />
                    <Legend />
                    <Scatter
  name="Normal"
  data={scatterData.filter((record) => record.prediction === "NORMAL")}
  fill="#38bdf8"
/>
<Scatter
  name="Suspicious"
  data={scatterData.filter((record) => record.prediction !== "NORMAL")}
  fill="#ef4444"
/>
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <p>Upload and analyze a CSV file to display DNS traffic points.</p>
            )}
            </section>
          </section>
        </main>
      )}

      {/* ML MODEL PAGE */}
      {activePage === "ML Model" && (
        <main className="dashboard-page">
          <div className="dashboard-header">
            <div>
              <div className="status-badge">MODEL INFORMATION</div>
              <h1>DNS Detection Model</h1>
              <p>Overview of the current DNS analysis pipeline.</p>
            </div>
          </div>

          <section className="dashboard-stats">
            <div className="dashboard-stat">
              <span>Analysis Method</span>
              <strong>
                {backendStatus === "ONLINE" ? "Random Forest ML" : "Test Rules + ML"}
              </strong>
              <small>
                {backendStatus === "ONLINE"
                  ? "FastAPI Service Active"
                  : "Local Fallback Ready"}
              </small>
            </div>

            <div className="dashboard-stat normal-stat">
              <span>Input Type</span>
              <strong>CSV</strong>
              <small>10 DNS Traffic Characteristics</small>
            </div>

            <div className="dashboard-stat suspicious-stat">
              <span>Trained ML Model</span>
              <strong className="green">
                {backendStatus === "ONLINE" ? "Online (100% Acc)" : "Available"}
              </strong>
              <small>Supervised Random Forest</small>
            </div>
          </section>

          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Detection Pipeline</h2>
              </div>
            </div>

            <div className="model-status">
              <div>
                <span>Step 1</span>
                <strong>Upload DNS Traffic CSV</strong>
              </div>
              <div>
                <span>Step 2</span>
                <strong>Extract 10 DNS Characteristics (Entropy, TTL, Length, Ratios)</strong>
              </div>
              <div>
                <span>Step 3</span>
                <strong>Evaluate via Random Forest Classifier</strong>
              </div>
              <div>
                <span>Step 4</span>
                <strong>Classify Threat Level & Display Contributing Risk Factors</strong>
              </div>
            </div>
          </section>
                    {/* DNS SCATTER PLOT */}
          <section className="dashboard-panel">
            <div className="panel-header">
              <div>
                <h2>DNS Traffic Scatter Plot</h2>
                <p>Query Length vs Shannon Entropy</p>
              </div>
            </div>

            {totalRecords > 0 ? (
              <div style={{ width: "100%", height: 340 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart
                    margin={{ top: 20, right: 25, bottom: 20, left: 10 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#263449" />
                    <XAxis
                      type="number"
                      dataKey="queryLength"
                      name="Query Length"
                      stroke="#94a3b8"
                      label={{
                        value: "Query Length",
                        position: "insideBottom",
                        offset: -10,
                        fill: "#94a3b8",
                      }}
                    />
                    <YAxis
                      type="number"
                      dataKey="entropy"
                      name="Shannon Entropy"
                      stroke="#94a3b8"
                      label={{
                        value: "Shannon Entropy",
                        angle: -90,
                        position: "insideLeft",
                        fill: "#94a3b8",
                      }}
                    />
                    <ZAxis range={[80, 80]} />
                    <Tooltip
  cursor={{ strokeDasharray: "3 3" }}
  content={({ active, payload }) => {
    if (active && payload && payload.length) {
      const record = payload[0].payload;

      return (
        <div
          style={{
            backgroundColor: "#0b1524",
            border: "1px solid #164e63",
            padding: "12px",
            borderRadius: "8px",
            color: "#e2e8f0",
          }}
        >
          <p><strong>Domain:</strong> {record.domain}</p>
          <p><strong>Query Length:</strong> {record.queryLength}</p>
          <p><strong>Shannon Entropy:</strong> {record.entropy}</p>
          <p><strong>Prediction:</strong> {record.prediction}</p>
        </div>
      );
    }

    return null;
  }}
/>
                    <Legend verticalAlign="top" />
                    <Scatter
  name="Normal"
  data={scatterData.filter((record) => record.prediction === "NORMAL")}
  fill="#38bdf8"
/>
<Scatter
  name="Suspicious"
  data={scatterData.filter((record) => record.prediction !== "NORMAL")}
  fill="#ef4444"
/>
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <p>Upload and analyze a CSV file to view the scatter plot.</p>
            )}
          </section>
        </main>
      )}

      {/* LEARN PAGE */}
      {activePage === "Learn" && (
        <main className="dashboard-page">
          <div className="dashboard-header">
            <div>
              <div className="status-badge">CYBERSECURITY AWARENESS</div>
              <h1>Learn About DNS Tunneling</h1>
              <p>Understand how DNS can be misused to hide data inside DNS requests.</p>
            </div>
          </div>

          <section className="dashboard-grid">
            <div className="dashboard-panel">
              <h2>What is DNS?</h2>
              <p>
                The Domain Name System (DNS) translates domain names, such as
                example.com, into information computers use to connect to services.
              </p>
            </div>

            <div className="dashboard-panel">
              <h2>What is DNS Tunneling?</h2>
              <p>
                DNS tunneling can encode data inside DNS queries and responses
                to create a hidden communication channel. Attackers may misuse
                it to move data or communicate with compromised systems.
              </p>
            </div>

            <div className="dashboard-panel">
              <h2>Warning Signs</h2>
              <ul>
                <li>Unusually long domain names</li>
                <li>High-entropy or random-looking subdomains</li>
                <li>Unusual amounts of DNS requests</li>
                <li>Unexpected DNS traffic patterns</li>
              </ul>
            </div>

            <div className="dashboard-panel">
              <h2>How TunnelGuard Helps</h2>
              <p>
                TunnelGuard analyzes domain characteristics and flags
                potential suspicious domains using machine learning. It checks
                Shannon entropy, numeric density, label counts, TTL, and response sizes.
              </p>
            </div>
          </section>
        </main>
      )}

      {/* TRAFFIC ANALYZER */}
      {activePage === "Traffic Analyzer" && (
        <main className="analyzer-page">
          <section className="analyzer-header">
            <div>
              <span className="section-label">TRAFFIC ANALYSIS</span>
              <h1>DNS Traffic Analyzer</h1>
              <p>
                Analyze DNS traffic characteristics and detect potential
                DNS tunneling activity.
              </p>
            </div>

            <span className="demo-badge">
              {backendStatus === "ONLINE"
                ? "● ML BACKEND ONLINE"
                : "● LOCAL DETECTION"}
            </span>
          </section>

          <section className="analyzer-upload">
            <div className="upload-icon">↥</div>

            <h2>Upload DNS Traffic CSV</h2>

            <p>
              Upload a CSV file containing DNS traffic data for analysis.
            </p>

            <div className="upload-actions">
              <label className="upload-btn">
                {isAnalyzing ? "Analyzing..." : "Choose CSV File"}
                <input
                  type="file"
                  accept=".csv"
                  disabled={isAnalyzing}
                  onChange={(e) => {
                    const file = e.target.files[0];
                    if (file) handleFileUpload(file);
                  }}
                />
              </label>

              <button
                className="demo-btn"
                disabled={isAnalyzing}
                onClick={handleUseDemoDataset}
              >
                {isAnalyzing ? "Processing..." : "Use Demo Dataset"}
              </button>
            </div>

            <span className="file-info">
              {selectedFile
                ? `Selected: ${selectedFile.name} (${totalRecords} records)`
                : "Supported format: .CSV (containing domain, query_type, response_size, ttl)"}
            </span>
          </section>

          <section className="analyzer-grid">
            {/* FEATURE EXTRACTION */}
            <div className="analyzer-panel">
              <div className="panel-header">
                <div>
                  <span className="panel-label">FEATURE EXTRACTION</span>
                  <h2>DNS Traffic Characteristics</h2>
                </div>

                <span className="status-dot">READY</span>
              </div>

              <div className="feature-list">
                <div className="feature-item">
                  <span>Query Length</span>
                  <strong>{queryLength !== null ? queryLength : "—"}</strong>
                </div>

                <div className="feature-item">
                  <span>Domain Length</span>
                  <strong>{domainLength !== null ? domainLength : "—"}</strong>
                </div>

                <div className="feature-item">
                  <span>Subdomain Count</span>
                  <strong>{subdomainCount !== null ? subdomainCount : "—"}</strong>
                </div>

                <div className="feature-item">
                  <span>Shannon Entropy</span>
                  <strong>{entropy !== null ? entropy : "—"}</strong>
                </div>

                <div className="feature-item">
                  <span>Request Frequency</span>
                  <strong>{requestFrequency !== null ? requestFrequency : "—"}</strong>
                </div>

                <div className="feature-item">
                  <span>Numeric Ratio</span>
                  <strong>{numericRatio !== null ? numericRatio : "—"}</strong>
                </div>
              </div>
            </div>

            {/* ML PREDICTION */}
            <div className="analyzer-panel prediction-panel">
              <div className="panel-header">
                <div>
                  <span className="panel-label">ML PREDICTION</span>
                  <h2>Detection Result</h2>
                </div>

                <span className="status-dot">READY</span>
              </div>

              <div className="prediction-result">
                <div className="prediction-icon">
                  {prediction === "NORMAL" || prediction === "NORMAL DNS TRAFFIC"
                    ? "✓"
                    : prediction
                    ? "!"
                    : "?"}
                </div>

                <h3>
                  {prediction
                    ? prediction === "NORMAL" || prediction === "NORMAL DNS TRAFFIC"
                      ? "NORMAL DNS TRAFFIC"
                      : "DNS TUNNELING DETECTED"
                    : "Awaiting Analysis"}
                </h3>

                <p>
                  {prediction
                    ? prediction === "NORMAL" || prediction === "NORMAL DNS TRAFFIC"
                      ? "No suspicious tunneling characteristics were detected in the traffic."
                      : "Suspicious DNS traffic characteristics were flagged by the machine-learning model."
                    : "Upload DNS traffic or use the demo dataset to generate a prediction."}
                </p>
              </div>

              <div className="prediction-details">
                <div>
                  <span>Confidence</span>
                  <strong>{confidence ? confidence : "—"}</strong>
                </div>

                <div>
                  <span>Risk Level</span>
                  <strong>
                    {prediction
                      ? prediction === "NORMAL" || prediction === "NORMAL DNS TRAFFIC"
                        ? "Low Risk"
                        : "High Risk"
                      : "—"}
                  </strong>
                </div>
              </div>
            </div>
          </section>

          {/* ANALYSIS REASONS */}
          <section className="analyzer-panel reasons-panel">
            <div className="panel-header">
              <div>
                <span className="panel-label">ANALYSIS</span>
                <h2>Detection Reasons & Factors</h2>
              </div>
            </div>

            <div className="empty-analysis">
              {!prediction ? (
                <>
                  <span>◈</span>
                  <p>
                    No analysis performed yet. Upload a dataset or use
                    the demo dataset to begin.
                  </p>
                </>
              ) : (
                <div className="detection-reasons">
                  <p>
                    Total DNS records analyzed: <strong>{totalRecords}</strong>
                  </p>
                  <p>
                    Total suspicious domains: <strong>{suspiciousDomains.length}</strong>
                  </p>

                  {prediction.includes("TUNNELING") ? (
                    <>
                      <p>
                        ⚠ The detection engine identified anomalous DNS tunneling behavior.
                      </p>

                      {suspiciousItems.length > 0 ? (
                        suspiciousItems.map((item) => (
                          <div key={item.domain} style={{ marginBottom: "8px" }}>
                            <p>
                              <strong>⚠ Flagged domain:</strong> {item.domain} (Threat Score: {item.threat_percentage}%)
                            </p>
                            {item.reasons && item.reasons.map((r, i) => (
                              <p key={i} style={{ paddingLeft: "15px", color: "#8b9bb4" }}>
                                • {r}
                              </p>
                            ))}
                          </div>
                        ))
                      ) : (
                        suspiciousDomains.map((domain) => (
                          <p key={domain}>⚠ Flagged domain: {domain}</p>
                        ))
                      )}
                    </>
                  ) : (
                    <div>
                      <p>
                        ✓ The analyzed DNS records are within normal baseline thresholds.
                      </p>
                      {detectionReasons.map((reason, idx) => (
                        <p key={idx} style={{ color: "#38bdf8", paddingLeft: "15px" }}>
                          • {reason}
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        </main>
      )}

      {/* FOOTER */}
      <footer>
        <div>
          <strong>DNS TUNNELGUARD</strong>
          <span>Machine Learning-Based DNS Security</span>
        </div>

        <div>
          <span>Cybersecurity Department</span>
          <span>© 2026 DNS TunnelGuard</span>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({ icon, title, text }) {
  return (
    <div className="feature-card">
      <div className="feature-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{text}</p>
      <span className="card-arrow">→</span>
    </div>
  );
}

function WorkflowStep({ number, title, text }) {
  return (
    <div className="workflow-step">
      <div className="step-number">{number}</div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

export default App;