"""HTML Report Jinja2 template for PECFF forensic analysis audits."""

from __future__ import annotations

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PECFF Forensic Report - {{ analysis.pcap_filename }}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --weak: #eab308;
      --acceptable: #10b981;
      --secure: #06b6d4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }
    h1 { font-size: 1.875rem; font-weight: 700; color: var(--text); }
    .subtitle { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.25rem; }
    .meta-box {
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; }
    .meta-value { font-size: 1.125rem; font-weight: 600; margin-top: 0.25rem; word-break: break-all; }
    .score-badge {
      display: inline-flex;
      align-items: center;
      padding: 0.5rem 1rem;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 1.125rem;
    }
    .band-CRITICAL { background-color: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .band-HIGH { background-color: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .band-WEAK { background-color: rgba(234, 179, 8, 0.2); color: var(--weak); border: 1px solid var(--weak); }
    .band-ACCEPTABLE { background-color: rgba(16, 185, 129, 0.2); color: var(--acceptable); border: 1px solid var(--acceptable); }
    .band-SECURE { background-color: rgba(6, 182, 212, 0.2); color: var(--secure); border: 1px solid var(--secure); }

    .section { margin-bottom: 2.5rem; }
    .section-title { font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem; border-left: 4px solid var(--accent); padding-left: 0.75rem; }

    table {
      width: 100%;
      border-collapse: collapse;
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    th, td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.875rem;
    }
    th {
      background-color: rgba(0, 0, 0, 0.2);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover { background-color: rgba(255, 255, 255, 0.02); }

    .tag {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 0.25rem;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .tag-protocol { background-color: #0284c7; color: white; }
    .tag-tls { background-color: #475569; color: white; }
    .tag-vuln { background-color: #dc2626; color: white; }
    .tag-warn { background-color: #d97706; color: white; }

    .finding-card {
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1rem 1.25rem;
      margin-bottom: 0.75rem;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .finding-title { font-weight: 600; font-size: 0.95rem; color: #fff; }
    .finding-rule { font-family: monospace; font-size: 0.75rem; color: var(--text-muted); }
    .finding-desc { font-size: 0.85rem; color: var(--text-muted); }
    .finding-evidence {
      background-color: rgba(0, 0, 0, 0.3);
      padding: 0.5rem;
      border-radius: 0.25rem;
      font-family: monospace;
      font-size: 0.75rem;
      margin-top: 0.5rem;
      overflow-x: auto;
    }
    .footer {
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      margin-top: 3rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>PECFF Forensic Analysis Audit</h1>
        <div class="subtitle">Passive Email Cryptographic Forensics Framework &bull; Deterministic Risk Audit</div>
      </div>
      <div>
        <span class="score-badge band-{{ analysis.overall_risk_band }}">
          Risk Score: {{ "%.1f"|format(analysis.overall_risk_score) }} / 100 ({{ analysis.overall_risk_band }})
        </span>
      </div>
    </header>

    <div class="meta-box">
      <div class="meta-item">
        <span class="meta-label">Capture File</span>
        <span class="meta-value">{{ analysis.pcap_filename }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">SHA-256 Hash</span>
        <span class="meta-value" style="font-size: 0.85rem; font-family: monospace;">{{ analysis.pcap_sha256 }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Total Packets</span>
        <span class="meta-value">{{ "{:,}".format(analysis.total_packets) }}</span>
      </div>
      <div class="meta-item">
        <span class="meta-label">Reconstructed Sessions</span>
        <span class="meta-value">{{ analysis.total_sessions }}</span>
      </div>
    </div>

    <!-- Findings Section -->
    <div class="section">
      <h2 class="section-title">Cryptographic Flaws & Forensic Findings ({{ analysis.findings|length }})</h2>
      {% if analysis.findings %}
        {% for f in analysis.findings %}
          <div class="finding-card">
            <div class="finding-header">
              <span class="finding-title">{{ f.title }}</span>
              <span class="tag {% if f.severity in ['CRITICAL', 'HIGH'] %}tag-vuln{% else %}tag-warn{% endif %}">{{ f.severity }}</span>
            </div>
            <div class="finding-rule">Rule: {{ f.rule_id }} &bull; Standards Ref: {{ f.standards_ref }}</div>
            <div class="finding-desc">{{ f.description }}</div>
            {% if f.evidence %}
              <div class="finding-evidence">{{ f.evidence }}</div>
            {% endif %}
          </div>
        {% endfor %}
      {% else %}
        <p style="color: var(--text-muted); font-size: 0.875rem;">No security findings or cryptographic vetoes observed in capture.</p>
      {% endif %}
    </div>

    <!-- Sessions Section -->
    <div class="section">
      <h2 class="section-title">Reconstructed Mail Sessions ({{ analysis.sessions|length }})</h2>
      <table>
        <thead>
          <tr>
            <th>Session ID</th>
            <th>Client Endpoint</th>
            <th>Server Endpoint</th>
            <th>Proto / Mode</th>
            <th>STARTTLS State</th>
            <th>JA3 / JA4</th>
            <th>Risk Score</th>
            <th>Anomaly</th>
          </tr>
        </thead>
        <tbody>
          {% for s in analysis.sessions %}
            <tr>
              <td style="font-family: monospace; font-size: 0.75rem;">{{ s.id }}</td>
              <td>{{ s.client_ip }}:{{ s.client_port }}</td>
              <td>{{ s.server_ip }}:{{ s.server_port }}</td>
              <td><span class="tag tag-protocol">{{ s.protocol }}</span> <span class="tag tag-tls">{{ s.mode }}</span></td>
              <td>{{ s.starttls_state }}</td>
              <td style="font-family: monospace; font-size: 0.7rem;">
                {% if s.ja3 %}JA3: {{ s.ja3[:12] }}...<br>{% endif %}
                {% if s.ja4 %}JA4: {{ s.ja4[:14] }}...{% endif %}
                {% if not s.ja3 and not s.ja4 %}-{% endif %}
              </td>
              <td>
                <span class="score-badge band-{{ s.risk_band }}" style="font-size: 0.8rem; padding: 0.2rem 0.6rem;">
                  {{ "%.1f"|format(s.risk_score) }}
                </span>
              </td>
              <td>
                {% if s.is_anomaly %}
                  <span class="tag tag-vuln">ANOMALOUS</span>
                {% else %}
                  <span style="color: var(--text-muted); font-size: 0.75rem;">Normal</span>
                {% endif %}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Standards Compliance Matrix -->
    <div class="section">
      <h2 class="section-title">Standards Compliance Matrix</h2>
      <table>
        <thead>
          <tr>
            <th>Standard Reference</th>
            <th>Requirement Title</th>
            <th>Forensic Verification Method</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>NIST SP 800-52r2 §3.1</td>
            <td>Protocol Version Threshold</td>
            <td>TLS 1.2+ mandatory; SSLv2/SSLv3/TLS1.0/1.1 disallowed</td>
            <td><span class="tag {% if analysis.overall_risk_score > 60 %}tag-vuln{% else %}tag-tls{% endif %}">Audited</span></td>
          </tr>
          <tr>
            <td>NIST SP 800-57 Part 1</td>
            <td>Effective Strength Gate (&ge; 112 bits)</td>
            <td>Minimum bits computed across symmetric, asymmetric, and hash primitives</td>
            <td><span class="tag tag-tls">Audited</span></td>
          </tr>
          <tr>
            <td>RFC 7457 / RFC 8314</td>
            <td>Opportunistic STARTTLS Stripping Detection</td>
            <td>Passive tracking of EHLO/CAPABILITY advertisement tampering</td>
            <td><span class="tag tag-tls">Audited</span></td>
          </tr>
          <tr>
            <td>RFC 8446 §4.1.3</td>
            <td>Downgrade Sentinel Detection</td>
            <td>ServerHello.random sentinel byte inspection</td>
            <td><span class="tag tag-tls">Audited</span></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="footer">
      <div>Generated by PECFF Passive Cryptographic Forensics Framework (Deterministic Engine)</div>
      <div>NIST SP 800-57 Auditable Forensic Report</div>
    </div>
  </div>
</body>
</html>
"""
