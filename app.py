#!/usr/bin/env python3
"""
VulnHunter - Advanced Web Vulnerability Scanner
Complete web interface for OWASP Top 10 vulnerability detection
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import os
import json
import logging
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse
from scanner import OWASPTop10Scanner

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'vulnhunter-secret-key-change-in-production'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Global scan storage
scan_results = {}
scan_status = {}
scan_threads = {}

def create_scan_id():
    """Generate unique scan ID"""
    return str(uuid.uuid4())

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def run_scan_thread(scan_id, url, scan_type, options):
    """Run vulnerability scan in background thread"""
    try:
        logger.info(f"Starting {scan_type} scan {scan_id} for {url}")
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'running',
            'target_url': url,
            'scan_type': scan_type,
            'current_step': 'Initializing scan...',
            'progress': 0,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerabilities': 0,
            'owasp_categories': {
                'A01': {'name': 'Broken Access Control', 'status': 'pending', 'vulnerabilities': 0},
                'A02': {'name': 'Cryptographic Failures', 'status': 'pending', 'vulnerabilities': 0},
                'A03': {'name': 'Injection', 'status': 'pending', 'vulnerabilities': 0},
                'A04': {'name': 'Insecure Design', 'status': 'pending', 'vulnerabilities': 0},
                'A05': {'name': 'Security Misconfiguration', 'status': 'pending', 'vulnerabilities': 0},
                'A06': {'name': 'Vulnerable Components', 'status': 'pending', 'vulnerabilities': 0},
                'A07': {'name': 'Authentication Failures', 'status': 'pending', 'vulnerabilities': 0},
                'A08': {'name': 'Software Integrity Failures', 'status': 'pending', 'vulnerabilities': 0},
                'A09': {'name': 'Security Logging Failures', 'status': 'pending', 'vulnerabilities': 0},
                'A10': {'name': 'Server-Side Request Forgery', 'status': 'pending', 'vulnerabilities': 0}
            }
        }
        
        # Initialize scanner
        max_depth = options.get('max_depth', 2)
        delay = options.get('delay', 1.0)
        scanner = OWASPTop10Scanner(url, max_depth, delay)
        
        vulnerabilities = []
        
        if scan_type == 'enhanced':
            # Enhanced scan with individual testing
            scan_status[scan_id]['current_step'] = 'Starting enhanced OWASP scan...'
            scan_status[scan_id]['progress'] = 10
            
            # Run comprehensive scan
            vulnerabilities = scanner.comprehensive_scan()
            scan_status[scan_id]['progress'] = 70
            
            # Run individual scanner tests
            scan_status[scan_id]['current_step'] = 'Running individual scanner tests...'
            individual_vulns = scanner.test_individual_scanners()
            scan_status[scan_id]['progress'] = 90
            
        elif scan_type == 'comprehensive':
            # Standard comprehensive OWASP scan
            scan_status[scan_id]['current_step'] = 'Running comprehensive OWASP scan...'
            scan_status[scan_id]['progress'] = 20
            
            vulnerabilities = scanner.comprehensive_scan()
            scan_status[scan_id]['progress'] = 90
        
        # Complete scan
        scan_status[scan_id]['current_step'] = 'Finalizing results...'
        scan_status[scan_id]['progress'] = 95
        
        # Store results
        scan_results[scan_id] = {
            'scan_id': scan_id,
            'target_url': url,
            'scan_type': scan_type,
            'vulnerabilities': scanner.vulnerabilities,
            'total_vulnerabilities': len(scanner.vulnerabilities),
            'severity_counts': {
                'Critical': sum(1 for v in scanner.vulnerabilities if v.get('severity') == 'Critical'),
                'High': sum(1 for v in scanner.vulnerabilities if v.get('severity') == 'High'),
                'Medium': sum(1 for v in scanner.vulnerabilities if v.get('severity') == 'Medium'),
                'Low': sum(1 for v in scanner.vulnerabilities if v.get('severity') == 'Low')
            },
            'vulnerability_types': {},
            'scan_completed': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Group vulnerabilities by type and OWASP category
        owasp_category_counts = {
            'A01': 0, 'A02': 0, 'A03': 0, 'A04': 0, 'A05': 0,
            'A06': 0, 'A07': 0, 'A08': 0, 'A09': 0, 'A10': 0
        }
        
        for vuln in scanner.vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in scan_results[scan_id]['vulnerability_types']:
                scan_results[scan_id]['vulnerability_types'][vuln_type] = 0
            scan_results[scan_id]['vulnerability_types'][vuln_type] += 1
            
            # Map vulnerability to OWASP category
            category = vuln.get('category', '')
            if category in owasp_category_counts:
                owasp_category_counts[category] += 1
        
        # Update OWASP category status
        for category, count in owasp_category_counts.items():
            if category in scan_status[scan_id]['owasp_categories']:
                scan_status[scan_id]['owasp_categories'][category]['vulnerabilities'] = count
                scan_status[scan_id]['owasp_categories'][category]['status'] = 'completed'
        
        # Update final status
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['current_step'] = 'Scan completed successfully'
        scan_status[scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_status[scan_id]['total_vulnerabilities'] = len(scanner.vulnerabilities)
        
        logger.info(f"Scan {scan_id} completed successfully with {len(scanner.vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scan_status[scan_id] = {
            'status': 'error',
            'error': str(e),
            'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

@app.route('/')
def index():
    """Dashboard page"""
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    """Scan configuration page"""
    return render_template('scan.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url'].strip()
    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Generate scan ID and get options
    scan_id = create_scan_id()
    scan_type = data.get('scan_type', 'comprehensive')
    options = {
        'max_depth': data.get('max_depth', 2),
        'delay': data.get('delay', 1.0)
    }
    
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, url, scan_type, options)
    )
    thread.daemon = True
    thread.start()
    
    scan_threads[scan_id] = thread
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

@app.route('/scan/status/<scan_id>')
def scan_status_page(scan_id):
    """Scan status page"""
    if scan_id not in scan_status:
        return render_template('scan_status.html', 
                             scan_id=scan_id, 
                             status={'status': 'not_found'})
    
    status = scan_status[scan_id]
    return render_template('scan_status.html', scan_id=scan_id, status=status)

@app.route('/api/scan/status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status via API"""
    if scan_id not in scan_status:
        return jsonify({'status': 'not_found'}), 404
    
    return jsonify(scan_status[scan_id])

@app.route('/results/<scan_id>')
def results_page(scan_id):
    """Scan results page"""
    if scan_id not in scan_results:
        flash('Scan results not found', 'error')
        return redirect(url_for('index'))
    
    results = scan_results[scan_id]
    return render_template('results.html', results=results, scan_id=scan_id)

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    """Get scan results via API"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/scans')
def scan_history():
    """Scan history page"""
    # Get recent scans
    recent_scans = []
    for scan_id, results in list(scan_results.items())[-10:]:  # Last 10 scans
        recent_scans.append({
            'scan_id': scan_id,
            'target_url': results['target_url'],
            'scan_type': results['scan_type'],
            'total_vulnerabilities': results['total_vulnerabilities'],
            'scan_completed': results['scan_completed'],
            'status': 'completed',
            'severity_counts': results.get('severity_counts', {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0})
        })
    
    # Add running scans
    for scan_id, status in scan_status.items():
        if status['status'] == 'running':
            recent_scans.append({
                'scan_id': scan_id,
                'target_url': status['target_url'],
                'scan_type': status.get('scan_type', 'unknown'),
                'total_vulnerabilities': status.get('total_vulnerabilities', 0),
                'scan_completed': status.get('current_step', 'Running...'),
                'status': 'running',
                'severity_counts': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            })
    
    return render_template('scan_history.html', scans=recent_scans)

@app.route('/api/scan/<scan_id>/export')
def export_scan_results(scan_id):
    """Export enhanced scan results with CVSS data"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    from scanner import OWASPTop10Scanner
    results = scan_results[scan_id]
    scanner = OWASPTop10Scanner(results['target_url'])
    scanner.vulnerabilities = results['vulnerabilities']
    enhanced_data = scanner.export_enhanced_results()
    
    return jsonify(enhanced_data)

@app.route('/api/scan/<scan_id>/report/html')
def generate_html_report(scan_id):
    """Generate comprehensive HTML report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    from scanner import OWASPTop10Scanner
    results = scan_results[scan_id]
    scanner = OWASPTop10Scanner(results['target_url'])
    scanner.vulnerabilities = results['vulnerabilities']
    
    html_report = scanner.generate_html_report()
    
    from flask import Response
    return Response(
        html_report,
        mimetype='text/html',
        headers={
            'Content-Disposition': f'attachment; filename="security_report_{scan_id[:8]}.html"'
        }
    )

@app.route('/api/scan/<scan_id>/report/json')
def generate_json_report(scan_id):
    """Generate comprehensive JSON report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    from scanner import OWASPTop10Scanner
    results = scan_results[scan_id]
    scanner = OWASPTop10Scanner(results['target_url'])
    scanner.vulnerabilities = results['vulnerabilities']
    
    json_report = scanner.generate_json_report()
    
    from flask import Response
    return Response(
        json.dumps(json_report, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="security_report_{scan_id[:8]}.json"'
        }
    )

@app.route('/api/scan/<scan_id>/report/pdf')
def generate_pdf_report(scan_id):
    """Generate PDF report with improved error handling"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    try:
        from scanner import OWASPTop10Scanner
        results = scan_results[scan_id]
        scanner = OWASPTop10Scanner(results['target_url'])
        scanner.vulnerabilities = results['vulnerabilities']
        
        pdf_report = scanner.generate_pdf_report()
        
        from flask import Response
        
        # Check if it's actual PDF or HTML fallback
        if pdf_report.startswith(b'<!DOCTYPE html') or pdf_report.startswith(b'<html'):
            # HTML fallback
            return Response(
                pdf_report,
                mimetype='text/html',
                headers={
                    'Content-Disposition': f'inline; filename="security_report_{scan_id[:8]}.html"'
                }
            )
        else:
            # Actual PDF
            return Response(
                pdf_report,
                mimetype='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename="security_report_{scan_id[:8]}.pdf"'
                }
            )
    except Exception as e:
        logger.error(f"PDF generation failed for scan {scan_id}: {str(e)}")
        return jsonify({
            'error': 'PDF generation failed',
            'message': 'Try downloading the HTML report instead',
            'details': str(e)
        }), 500

@app.route('/api/scan/<scan_id>/report/word')
def generate_word_report(scan_id):
    """Generate Word document report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    from scanner import OWASPTop10Scanner
    results = scan_results[scan_id]
    scanner = OWASPTop10Scanner(results['target_url'])
    scanner.vulnerabilities = results['vulnerabilities']
    
    word_report = scanner.generate_word_report()
    
    from flask import Response
    return Response(
        word_report,
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        headers={
            'Content-Disposition': f'attachment; filename="security_report_{scan_id[:8]}.docx"'
        }
    )

@app.route('/report/<scan_id>')
def view_html_report(scan_id):
    """View HTML report in browser"""
    if scan_id not in scan_results:
        flash('Scan results not found', 'error')
        return redirect(url_for('index'))
    
    from scanner import OWASPTop10Scanner
    results = scan_results[scan_id]
    scanner = OWASPTop10Scanner(results['target_url'])
    scanner.vulnerabilities = results['vulnerabilities']
    
    html_report = scanner.generate_html_report()
    
    from flask import Response
    return Response(html_report, mimetype='text/html')

@app.route('/about')
def about():
    """About page with OWASP information"""
    return render_template('about.html')

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Get port from environment variable for Heroku deployment
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)