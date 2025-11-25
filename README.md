# VulnHunter - Advanced Web Vulnerability Scanner

A professional web application for comprehensive OWASP Top 10 2021 vulnerability detection with a modern, clean interface.

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![Flask](https://img.shields.io/badge/flask-2.0+-red.svg)
![License](https://img.shields.io/badge/license-Educational-yellow.svg)

## 🛡️ Overview

This comprehensive security scanner provides automated detection of the most critical web application vulnerabilities as defined by the **OWASP Top 10 2021**. Built with Flask and featuring a clean, minimalist web interface with real-time progress tracking and professional reporting.

## ✨ Key Features

### 🔍 Complete OWASP Top 10 2021 Coverage

- **A01: Broken Access Control** - Directory traversal, privilege escalation, force browsing
- **A02: Cryptographic Failures** - Weak SSL/TLS, insecure protocols, encryption issues
- **A03: Injection** - SQL injection, XSS (reflected & stored), command injection
- **A04: Insecure Design** - Missing security controls, design flaws
- **A05: Security Misconfiguration** - Missing headers, default configs, verbose errors
- **A06: Vulnerable Components** - Outdated libraries, vulnerable dependencies
- **A07: Authentication Failures** - Weak passwords, session flaws, auth bypass
- **A08: Data Integrity Failures** - Insecure deserialization, CI/CD issues
- **A09: Security Logging Failures** - Missing logging, inadequate monitoring
- **A10: Server-Side Request Forgery** - SSRF, internal access, metadata exposure

### 🚀 Advanced Scanning Engine

- **Intelligent Web Crawling** - Automatic URL and form discovery
- **Multi-threaded Processing** - Background scan execution with real-time updates
- **CVSS 3.1 Scoring** - Professional vulnerability assessment with detailed vectors
- **Pattern Recognition** - Advanced regex and signature-based detection
- **Session Management** - Persistent HTTP sessions for authenticated testing
- **Comprehensive Reporting** - Detailed findings with evidence and remediation guidance

### 📊 Professional Report Generation

- **Executive Summary** - High-level risk assessment and key findings
- **PDF Reports** - Professional, printable documents suitable for executives and compliance
- **Word Documents** - Editable reports for collaborative review and annotation
- **HTML Reports** - Interactive web-based reports with modern styling
- **Machine-readable JSON** - Structured data export for integration and automation
- **Risk Matrix Analysis** - CVSS-based risk scoring and prioritization
- **Remediation Guidance** - Actionable recommendations with timelines
- **OWASP Coverage Report** - Complete Top 10 assessment breakdown

### 🎨 Modern Web Interface

- **Clean Design** - Minimalist, professional interface without clutter
- **Real-time Progress** - Live scan status updates and progress tracking
- **Responsive Layout** - Works seamlessly on desktop, tablet, and mobile
- **Scan Management** - Easy configuration and history management
- **Export Functionality** - Download detailed vulnerability reports

## 🔧 Quick Start

### Prerequisites
- **Python 3.7+**
- **Modern web browser**

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd web_vuln_scanner
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the application:**
   ```bash
   python app.py
   ```

4. **Open your browser:**
   ```
   http://localhost:5000
   ```

## 🚀 Usage Guide

### Web Interface Workflow

1. **Home Dashboard** - Access main navigation and quick actions
2. **Start New Scan** - Configure target URL and scan parameters
3. **Monitor Progress** - Real-time scan status with live updates
4. **Review Results** - Detailed vulnerability reports with CVSS scores
5. **Scan History** - Manage and review previous assessments

### Scan Configuration

- **Target URL**: Enter the web application URL to test
- **Scan Type**: 
  - Comprehensive (Full OWASP Top 10)
  - Enhanced (Extended vulnerability checks)
- **Crawl Depth**: Shallow/Medium/Deep URL discovery
- **Speed Settings**: Fast/Normal/Slow (respectful to target systems)

### Report Generation

After completing a scan, generate comprehensive security reports in multiple formats:

- **PDF Reports**: Professional, printable documents with executive summaries, detailed findings, and remediation guidance
- **Word Documents**: Editable Microsoft Word format for collaborative review, annotation, and customization
- **HTML Reports**: Interactive web-based reports with modern styling and responsive design
- **JSON Export**: Machine-readable structured data for integration with security tools and workflows

### API Endpoints for Report Generation

- `/report/<scan_id>` - View interactive HTML report in browser
- `/api/scan/<scan_id>/report/pdf` - Download professional PDF report
- `/api/scan/<scan_id>/report/word` - Download editable Word document
- `/api/scan/<scan_id>/report/html` - Download HTML report file
- `/api/scan/<scan_id>/report/json` - Download JSON data export

### Installation Requirements

For full report generation functionality, install additional dependencies:

```bash
# For PDF generation (cross-platform compatible)
pip install reportlab

# For Word document generation  
pip install python-docx

# Note: Using reportlab instead of weasyprint for better Windows compatibility
```

### Severity Classification

- **🔴 Critical (9.0-10.0)** - Immediate action required
- **🟠 High (7.0-8.9)** - High priority remediation
- **🟡 Medium (4.0-6.9)** - Standard remediation timeline
- **🟢 Low (0.1-3.9)** - Low priority improvements

