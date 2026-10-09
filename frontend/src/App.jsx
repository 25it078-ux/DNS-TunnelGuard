import { useState } from "react";
import "./App.css";

function App() {
  const [activePage, setActivePage] = useState("Home");
  const [demoAnalyzed, setDemoAnalyzed] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [domainLength, setDomainLength] = useState(null);
  const [subdomainCount, setSubdomainCount] = useState(null);
  const [queryLength, setQueryLength] = useState(null);
  const [entropy, setEntropy] = useState(null);
  const [requestFrequency, setRequestFrequency] = useState(null);
  const [numericRatio, setNumericRatio] = useState(null);
  const [prediction, setPrediction] = useState(null);
  const [suspiciousDomains, setSuspiciousDomains] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  
const handleFileUpload = (file) => {
  if (!file) return;

  const reader = new FileReader();

  reader.onload = (event) => {
    const csvData = event.target.result;

    const rows = csvData
      .trim()
      .split(/\r?\n/)
      .map((row) => row.split(","));

    if (rows.length < 2) {
      alert("The CSV file contains no DNS records.");
      return;
    }

    const headers = rows[0].map((header) =>
      header.trim().toLowerCase()
    );

    const domainIndex = headers.indexOf("domain");

    if (domainIndex === -1) {
      alert('CSV must contain a column named "domain".');
      return;
    }

    const domains = rows
      .slice(1)
      .filter((row) => row[domainIndex]?.trim())
      .map((row) => row[domainIndex].trim());

    if (domains.length === 0) {
      alert("No valid domains found in the CSV.");
      return;
    }

    const analyzeDomain = (domain) => {
      const parts = domain.split(".");
      const length = domain.length;

      const frequencies = {};

      for (const char of domain) {
        frequencies[char] = (frequencies[char] || 0) + 1;
      }

      let entropyValue = 0;

      for (const char in frequencies) {
        const probability = frequencies[char] / length;
        entropyValue -= probability * Math.log2(probability);
      }

      const numericCount = (domain.match(/[0-9]/g) || []).length;
      const numericRatioValue = numericCount / length;

      const suspicious =
        entropyValue > 3.5 ||
        length > 50 ||
        numericRatioValue > 0.3;

      return {
        domain,
        length,
        subdomains: Math.max(parts.length - 2, 0),
        entropy: entropyValue,
        numericRatio: numericRatioValue,
        suspicious,
      };
    };

    const results = domains.map(analyzeDomain);
    const first = results[0];
    const suspiciousResults = results.filter(
      (result) => result.suspicious
    );
    setSuspiciousDomains(
  suspiciousResults.map((result) => result.domain)
);

    setQueryLength(first.length);
    setDomainLength(first.length);
    setSubdomainCount(first.subdomains);
    setEntropy(first.entropy.toFixed(2));
    setNumericRatio(first.numericRatio.toFixed(2));
    setRequestFrequency(results.length);
    setTotalRecords(results.length);
    console.log("Total DNS records analyzed:", results.length);
console.log("Suspicious domains detected:", suspiciousResults.length);

    setPrediction(
      suspiciousResults.length > 0
        ? "DNS TUNNELING"
        : "NORMAL"
    );

    console.log("TOTAL RECORDS ANALYZED:", results.length);
    console.log("SUSPICIOUS RECORDS:", suspiciousResults);
    console.log("ALL DOMAIN RESULTS:", results);
  };

  reader.readAsText(file);
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
              <strong>12,480</strong>
              <small>DEMO DATA</small>
            </div>

            <div className="stat-card">
              <span>Normal Traffic</span>
              <strong className="green">11,932</strong>
              <small>DEMO DATA</small>
            </div>

            <div className="stat-card">
              <span>Suspicious Traffic</span>
              <strong className="red">548</strong>
              <small>DEMO DATA</small>
            </div>

            <div className="stat-card">
              <span>Detection Rate</span>
              <strong className="cyan">94.8%</strong>
              <small>DEMO DATA</small>
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

            <div className="demo-badge">● DEMO DATA</div>
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
    {totalRecords > 0
      ? (totalRecords - suspiciousDomains.length).toLocaleString()
      : "—"}
  </strong>
  <small>
    {totalRecords > 0
      ? "Based on current test rules"
      : "Awaiting analysis"}
  </small>
</div>

            <div className="dashboard-stat suspicious-stat">
  <span>Suspicious Requests</span>
  <strong>
    {totalRecords > 0 ? suspiciousDomains.length : "—"}
  </strong>
  <small>Flagged by current test rules</small>
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
                  <strong>94.8%</strong>
                  <span>Detection Rate</span>
                </div>
              </div>

              <div className="legend">
                <div>
                  <span className="legend-dot normal-dot"></span>
                  Normal
                  <strong>95.6%</strong>
                </div>

                <div>
                  <span className="legend-dot suspicious-dot"></span>
                  Suspicious
                  <strong>4.4%</strong>
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
              </div>
            </div>

            <div className="dashboard-panel">
              <div className="panel-header">
                <div>
                  <h2>ML Model Status</h2>
                  <p>Current detection pipeline</p>
                </div>

                <span className="online-status">● ONLINE</span>
              </div>

              <div className="model-status">
                <div>
                  <span>Model</span>
                  <strong>DNS Tunnel Classifier</strong>
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
                  <strong className="online-text">Ready for Analysis</strong>
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
              <p>Potentially suspicious domains identified by the current test rules.</p>
            </div>
          </div>

          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Detected Suspicious Domains</h2>
                <p>Total flagged: {suspiciousDomains.length}</p>
              </div>
            </div>

            {suspiciousDomains.length > 0 ? (
              suspiciousDomains.map((domain, index) => (
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
              <strong>{Math.max(0, totalRecords - suspiciousDomains.length)}</strong>
              <small>Not flagged by test rules</small>
            </div>

            <div className="dashboard-stat suspicious-stat">
              <span>Flagged Domains</span>
              <strong>{suspiciousDomains.length}</strong>
              <small>Requires review</small>
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
                Analyzed {totalRecords} DNS records. The current test rules
                flagged {suspiciousDomains.length} domain(s) for review.
              </p>
            ) : (
              <p>Upload a CSV file in Traffic Analyzer to view analytics.</p>
            )}

            <p>
              Note: These results use test rules, not a trained machine-learning model.
            </p>
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
              <strong>Test Rules</strong>
              <small>Current implementation</small>
            </div>

            <div className="dashboard-stat normal-stat">
              <span>Input Type</span>
              <strong>CSV</strong>
              <small>DNS domain records</small>
            </div>

            <div className="dashboard-stat suspicious-stat">
              <span>Trained ML Model</span>
              <strong>Not Yet</strong>
              <small>Future development</small>
            </div>
          </section>

          <section className="dashboard-panel alerts-panel">
            <div className="panel-header">
              <div>
                <h2>Detection Pipeline</h2>
              </div>
            </div>

            <div className="model-status">
              <div><span>Step 1</span><strong>Upload DNS CSV</strong></div>
              <div><span>Step 2</span><strong>Extract domain characteristics</strong></div>
              <div><span>Step 3</span><strong>Apply test-rule thresholds</strong></div>
              <div><span>Step 4</span><strong>Display potential suspicious domains</strong></div>
            </div>
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
                This prototype analyzes domain characteristics and flags
                potential suspicious domains using test rules. A production
                system would require validated data and a trained model.
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

            <span className="demo-badge">DEMO MODE</span>
          </section>

          <section className="analyzer-upload">
            <div className="upload-icon">↥</div>

            <h2>Upload DNS Traffic CSV</h2>

            <p>
              Upload a CSV file containing DNS traffic data for analysis.
            </p>

            <div className="upload-actions">
              <label className="upload-btn">
                Choose CSV File
                <input 
  type="file" 
  accept=".csv" 
  onChange={(e) => {
  const file = e.target.files[0];
  setSelectedFile(file);
  handleFileUpload(file);
}}
/>
              </label>

              <button className="demo-btn"onClick={() => setDemoAnalyzed(true)}>
                Use Demo Dataset
              </button>
            </div>

            <span className="file-info">
  {selectedFile
    ? `Selected: ${selectedFile.name}`
    : "Supported format: .CSV"}
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
    {prediction === "NORMAL" ? "✓" : prediction ? "!" : "?"}
  </div>

  <h3>
  {prediction
    ? prediction === "NORMAL"
      ? "NORMAL DNS TRAFFIC"
      : "DNS TUNNELING DETECTED"
    : "Awaiting Analysis"}
</h3>

  <p>
  {prediction
    ? prediction === "NORMAL"
      ? "No suspicious characteristics were detected by the current test rules."
      : "Suspicious DNS traffic characteristics were detected by the current test rules."
    : "Upload DNS traffic or use the demo dataset to generate a prediction."}
</p>
</div>

              <div className="prediction-details">
  <div>
    <span>Confidence</span>
    <strong>{prediction ? "Not calculated" : "—"}</strong>
  </div>

  <div>
    <span>Risk Level</span>
    <strong>
  {prediction
    ? prediction === "NORMAL"
      ? "Low (test rules)"
      : "High (test rules)"
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
                <h2>Detection Reasons</h2>
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
      Total DNS records analyzed: {totalRecords}
    </p>
      <p>
        Total suspicious domains: {suspiciousDomains.length}
      </p>

      {prediction === "DNS TUNNELING" ? (
        <>
          <p>
            ⚠ The current test rules flagged suspicious DNS characteristics.
          </p>

          {suspiciousDomains.map((domain) => (
            <p key={domain}>⚠ Flagged domain: {domain}</p>
          ))}

          {Number(entropy) > 3.5 && (
            <p>⚠ High Shannon entropy detected in the analyzed domain.</p>
          )}

          {Number(queryLength) > 50 && (
            <p>⚠ Unusually long DNS query detected.</p>
          )}

          {Number(numericRatio) > 0.3 && (
            <p>⚠ High numeric character ratio detected.</p>
          )}
        </>
      ) : (
        <p>
          ✓ The analyzed domains did not exceed the current test-rule thresholds.
        </p>
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