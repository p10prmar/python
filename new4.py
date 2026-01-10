#!/usr/bin/env python3
"""
VAST - Vulnerability Assessment & Scanning Tool
"""

impor sys
import os
import requests
import re
import time
import subprocess
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# CONFIGURATION MODULE
# ============================================================================

class Config:
    """Configuration management"""
    def __init__(self):
        self.target = None
        self.cookie = None
        self.auth_header = None
        self.threads = 5
        self.timeout = 10
        self.user_agent = 'VAST/1.0 (Vulnerability Assessment Scanner)'
        self.confidence_threshold = 70
        self.max_redirects = 3
        
    def set_auth(self, cookie=None, auth_header=None):
        """Set authentication credentials"""
        self.cookie = cookie
        self.auth_header = auth_header
        
    def get_headers(self):
        """Get HTTP headers for requests"""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        if self.cookie:
            headers['Cookie'] = self.cookie
            
        if self.auth_header:
            headers['Authorization'] = self.auth_header
            
        return headers

# ============================================================================
# VERIFICATION MODULE
# ============================================================================

class Verifier:
    """Reduces false positives through evidence-based verification"""
    
    def __init__(self):
        # SQL error patterns
        self.sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"Microsoft SQL Native Client error",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
        ]
        
        # Command injection output patterns
        self.cmd_patterns = [
            r"uid=\d+\([a-zA-Z0-9]+\)",
            r"root:.*:0:0:",
            r"bin.*bash",
            r"Microsoft Windows",
            r"\[.*\] \[.*\] \[.*\]",
        ]
        
        # LFI patterns
        self.lfi_patterns = [
            r"root:.*:0:0:",
            r"\[boot loader\]",
            r"\[extensions\]",
            r"for 16-bit app support",
        ]
        
    def verify_xss(self, response_text, payload):
        """Verify XSS - Returns confidence score 0-100"""
        confidence = 0
        
        if payload not in response_text:
            return 0
            
        confidence += 40
        
        dangerous_contexts = [
            '<script', '<iframe', 'onerror=', 'onload=',
            'javascript:', '<img', '<svg'
        ]
        
        for context in dangerous_contexts:
            if context in response_text.lower() and payload.lower() in response_text.lower():
                confidence += 30
                break
                
        encoded_patterns = ['&lt;', '&gt;', '&quot;', '&#']
        payload_idx = response_text.find(payload)
        if payload_idx != -1:
            payload_area = response_text[max(0, payload_idx-50):min(len(response_text), payload_idx+50)]
            has_encoding = any(pattern in payload_area for pattern in encoded_patterns)
            
            if not has_encoding:
                confidence += 30
            else:
                confidence -= 20
            
        return max(0, min(100, confidence))
        
    def verify_sqli_error(self, response_text):
        """Verify SQL injection error-based"""
        confidence = 0
        matches = 0
        
        for pattern in self.sql_errors:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches += 1
                confidence += 40
                
        if matches >= 2:
            confidence += 20
            
        if len(response_text) > 5000:
            confidence += 10
            
        return min(100, confidence)
        
    def verify_sqli_time_based(self, elapsed_time, expected_delay):
        """Verify time-based SQL injection"""
        time_diff = abs(elapsed_time - expected_delay)
        
        if time_diff < 0.5:
            return 95
        elif time_diff < 1.0:
            return 85
        elif time_diff < 1.5:
            return 70
        elif time_diff < 2.0:
            return 60
        else:
            return 40
            
    def verify_command_injection(self, response_text):
        """Verify command injection"""
        confidence = 0
        matches = 0
        
        for pattern in self.cmd_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches += 1
                confidence += 35
                
        if matches >= 2:
            confidence += 30
            
        return min(100, confidence)
        
    def verify_lfi(self, response_text):
        """Verify Local File Inclusion"""
        confidence = 0
        matches = 0
        
        for pattern in self.lfi_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches += 1
                confidence += 40
                
        if matches >= 2:
            confidence += 20
            
        return min(100, confidence)
        
    def verify_ssrf(self, response_text, payload):
        """Verify SSRF"""
        confidence = 0
        
        internal_indicators = [
            'localhost', '127.0.0.1', 'instance-id',
            'ami-id', 'security-credentials', 'meta-data',
        ]
        
        matches = 0
        for indicator in internal_indicators:
            if indicator.lower() in response_text.lower():
                matches += 1
                confidence += 30
                
        if 'latest/meta-data' in payload and len(response_text) > 100:
            confidence += 40
            
        return min(100, confidence)
        
    def verify_open_redirect(self, response, payload):
        """Verify open redirect"""
        confidence = 0
        
        if response.status_code in [301, 302, 303, 307, 308]:
            confidence += 40
            
            location = response.headers.get('Location', '')
            payload_domain = payload.replace('http://', '').replace('https://', '').replace('//', '').split('/')[0]
            
            if payload_domain in location:
                confidence += 60
                
        return min(100, confidence)

# ============================================================================
# VULNERABILITY SCANNER MODULE
# ============================================================================

class VulnerabilityScanner:
    """Custom Python-based vulnerability detection engine"""
    
    def __init__(self, config):
        self.config = config
        self.verifier = Verifier()
        self.session = requests.Session()
        self.session.headers.update(config.get_headers())
        
    def scan_all(self):
        """Run all vulnerability scans"""
        all_results = []
        
        scan_functions = [
            self.scan_xss,
            self.scan_sqli,
            self.scan_command_injection,
            self.scan_csrf,
            self.scan_ssrf,
            self.scan_directory_traversal,
            self.scan_open_redirect,
            self.scan_security_headers,
        ]
        
        for scan_func in scan_functions:
            try:
                results = scan_func()
                all_results.extend(results)
            except Exception as e:
                print(f"[!] Error in {scan_func.__name__}: {str(e)}")
                
        return all_results
        
    def _make_request(self, url, method='GET', data=None, allow_redirects=True):
        """Safe HTTP request wrapper"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            else:
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.config.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            return response
        except requests.exceptions.RequestException:
            return None
            
    def _get_forms(self, url):
        """Extract all forms from a page"""
        try:
            response = self._make_request(url)
            if not response:
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action'),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_details = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)
                    
                forms.append(form_details)
                
            return forms
        except Exception:
            return []
            
    def scan_xss(self):
        """Scan for Cross-Site Scripting vulnerabilities"""
        print("[*] Scanning for XSS...")
        results = []
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            'javascript:alert("XSS")',
        ]
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in xss_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._make_request(test_url)
                    if response and payload in response.text:
                        confidence = self.verifier.verify_xss(response.text, payload)
                        
                        if confidence > 50:
                            results.append({
                                'name': 'Cross-Site Scripting (XSS)',
                                'severity': 'HIGH' if confidence >= self.config.confidence_threshold else 'MEDIUM',
                                'confidence': confidence,
                                'verified': confidence >= self.config.confidence_threshold,
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f"Payload reflected: {payload[:50]}",
                                'source': 'custom',
                                'cvss': 7.1 if confidence >= 70 else 5.4,
                                'impact': 'Execute arbitrary JavaScript in victim browsers',
                                'remediation': 'Implement input validation and output encoding. Use CSP.'
                            })
                            break
                            
        forms = self._get_forms(self.config.target)
        for form in forms[:3]:  # Limit forms
            action = urljoin(self.config.target, form['action'] or '')
            
            for payload in xss_payloads[:3]:
                form_data = {}
                for input_field in form['inputs']:
                    if input_field['name']:
                        form_data[input_field['name']] = payload if input_field['type'] != 'submit' else input_field['value']
                        
                response = self._make_request(action, method=form['method'], data=form_data)
                
                if response and payload in response.text:
                    confidence = self.verifier.verify_xss(response.text, payload)
                    
                    if confidence > 50:
                        results.append({
                            'name': 'Cross-Site Scripting (XSS) in Form',
                            'severity': 'HIGH' if confidence >= 70 else 'MEDIUM',
                            'confidence': confidence,
                            'verified': confidence >= 70,
                            'url': action,
                            'method': form['method'],
                            'payload': payload,
                            'evidence': f"Payload reflected in form response",
                            'source': 'custom',
                            'cvss': 7.1 if confidence >= 70 else 5.4,
                            'impact': 'Execute arbitrary JavaScript in victim browsers',
                            'remediation': 'Implement input validation and output encoding.'
                        })
                        break
                        
        return results
        
    def scan_sqli(self):
        """Scan for SQL Injection vulnerabilities"""
        print("[*] Scanning for SQL Injection...")
        results = []
        
        error_payloads = ["'", "1' OR '1'='1", "1' OR '1'='1' --", "' OR '1'='1' /*"]
        time_payloads = ["1' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"]
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            # Error-based
            for param in params:
                for payload in error_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._make_request(test_url)
                    if response:
                        confidence = self.verifier.verify_sqli_error(response.text)
                        
                        if confidence > 50:
                            results.append({
                                'name': 'SQL Injection (Error-based)',
                                'severity': 'CRITICAL' if confidence >= 70 else 'HIGH',
                                'confidence': confidence,
                                'verified': confidence >= 70,
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'SQL error patterns detected',
                                'source': 'custom',
                                'cvss': 9.1 if confidence >= 70 else 7.5,
                                'impact': 'Read, modify, or delete database contents',
                                'remediation': 'Use parameterized queries (prepared statements).'
                            })
                            break
                            
            # Time-based (limited to 1 test per param)
            for param in list(params.keys())[:2]:
                payload = time_payloads[0]
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                start_time = time.time()
                response = self._make_request(test_url)
                elapsed = time.time() - start_time
                
                if elapsed >= 4.5:
                    confidence = self.verifier.verify_sqli_time_based(elapsed, 5)
                    
                    if confidence > 50:
                        results.append({
                            'name': 'SQL Injection (Time-based Blind)',
                            'severity': 'CRITICAL' if confidence >= 70 else 'HIGH',
                            'confidence': confidence,
                            'verified': confidence >= 70,
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Response delayed {elapsed:.2f}s',
                            'source': 'custom',
                            'cvss': 9.1 if confidence >= 70 else 7.5,
                            'impact': 'Extract database through timing attacks',
                            'remediation': 'Use parameterized queries.'
                        })
                        break
                        
        return results
        
    def scan_command_injection(self):
        """Scan for Command Injection"""
        print("[*] Scanning for Command Injection...")
        results = []
        
        cmd_payloads = ["; ls", "| whoami", "`whoami`", "$(whoami)"]
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in cmd_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self._make_request(test_url)
                    if response:
                        confidence = self.verifier.verify_command_injection(response.text)
                        
                        if confidence > 50:
                            results.append({
                                'name': 'Command Injection',
                                'severity': 'CRITICAL' if confidence >= 70 else 'HIGH',
                                'confidence': confidence,
                                'verified': confidence >= 70,
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'Command output patterns detected',
                                'source': 'custom',
                                'cvss': 9.8 if confidence >= 70 else 7.8,
                                'impact': 'Execute arbitrary system commands',
                                'remediation': 'Avoid system calls. Use whitelisting.'
                            })
                            break
                            
        return results
        
    def scan_csrf(self):
        """Scan for CSRF vulnerabilities"""
        print("[*] Scanning for CSRF...")
        results = []
        
        forms = self._get_forms(self.config.target)
        
        for form in forms:
            if form['method'] == 'post':
                has_token = False
                token_names = ['csrf', 'token', '_token', 'csrf_token', 'authenticity_token']
                
                for input_field in form['inputs']:
                    if input_field['name'] and any(t in input_field['name'].lower() for t in token_names):
                        has_token = True
                        break
                        
                if not has_token:
                    results.append({
                        'name': 'Missing CSRF Protection',
                        'severity': 'MEDIUM',
                        'confidence': 85,
                        'verified': True,
                        'url': self.config.target,
                        'form_action': form['action'],
                        'evidence': 'POST form without CSRF token',
                        'source': 'custom',
                        'cvss': 6.5,
                        'impact': 'Perform actions on behalf of authenticated users',
                        'remediation': 'Implement CSRF tokens for state-changing operations.'
                    })
                    
        return results
        
    def scan_ssrf(self):
        """Scan for Server-Side Request Forgery"""
        print("[*] Scanning for SSRF...")
        results = []
        
        ssrf_payloads = ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/']
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(kw in param.lower() for kw in ['url', 'uri', 'path', 'link', 'src']):
                    for payload in ssrf_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self._make_request(test_url)
                        if response:
                            confidence = self.verifier.verify_ssrf(response.text, payload)
                            
                            if confidence > 50:
                                results.append({
                                    'name': 'Server-Side Request Forgery (SSRF)',
                                    'severity': 'HIGH' if confidence >= 70 else 'MEDIUM',
                                    'confidence': confidence,
                                    'verified': confidence >= 70,
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'Internal resource access detected',
                                    'source': 'custom',
                                    'cvss': 8.6 if confidence >= 70 else 6.4,
                                    'impact': 'Access internal resources and cloud metadata',
                                    'remediation': 'Validate and whitelist URLs.'
                                })
                                break
                                
        return results
        
    def scan_directory_traversal(self):
        """Scan for Directory Traversal / LFI"""
        print("[*] Scanning for Directory Traversal...")
        results = []
        
        lfi_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\win.ini',
        ]
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(kw in param.lower() for kw in ['file', 'path', 'page', 'include', 'doc']):
                    for payload in lfi_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self._make_request(test_url)
                        if response:
                            confidence = self.verifier.verify_lfi(response.text)
                            
                            if confidence > 50:
                                results.append({
                                    'name': 'Directory Traversal / LFI',
                                    'severity': 'HIGH' if confidence >= 70 else 'MEDIUM',
                                    'confidence': confidence,
                                    'verified': confidence >= 70,
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': 'System file patterns detected',
                                    'source': 'custom',
                                    'cvss': 7.5 if confidence >= 70 else 5.3,
                                    'impact': 'Read sensitive server files',
                                    'remediation': 'Use whitelisting for file access.'
                                })
                                break
                                
        return results
        
    def scan_open_redirect(self):
        """Scan for Open Redirect vulnerabilities"""
        print("[*] Scanning for Open Redirect...")
        results = []
        
        redirect_payloads = ['http://evil.com', 'https://evil.com', '//evil.com']
        
        parsed = urlparse(self.config.target)
        if parsed.query:
            params = parse_qs(parsed.query)
            
            for param in params:
                if any(kw in param.lower() for kw in ['url', 'redirect', 'return', 'next', 'continue']):
                    for payload in redirect_payloads:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        response = self._make_request(test_url, allow_redirects=False)
                        if response:
                            confidence = self.verifier.verify_open_redirect(response, payload)
                            
                            if confidence > 50:
                                results.append({
                                    'name': 'Open Redirect',
                                    'severity': 'MEDIUM' if confidence >= 70 else 'LOW',
                                    'confidence': confidence,
                                    'verified': confidence >= 70,
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'Redirect to external domain',
                                    'source': 'custom',
                                    'cvss': 6.1 if confidence >= 70 else 4.3,
                                    'impact': 'Redirect users to malicious sites',
                                    'remediation': 'Validate redirect destinations.'
                                })
                                break
                                
        return results
        
    def scan_security_headers(self):
        """Check for missing security headers"""
        print("[*] Checking Security Headers...")
        results = []
        
        response = self._make_request(self.config.target)
        if not response:
            return results
            
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'impact': 'Vulnerable to clickjacking attacks',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'impact': 'Browser may perform MIME-sniffing',
                'remediation': 'Add X-Content-Type-Options: nosniff'
            },
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'impact': 'Vulnerable to protocol downgrade attacks',
                'remediation': 'Add Strict-Transport-Security header'
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'impact': 'No CSP protection against XSS',
                'remediation': 'Implement Content-Security-Policy'
            },
        }
        
        for header, details in security_headers.items():
            if header not in headers:
                results.append({
                    'name': f'Missing Security Header: {header}',
                    'severity': details['severity'],
                    'confidence': 100,
                    'verified': True,
                    'url': self.config.target,
                    'evidence': f'{header} not present',
                    'source': 'custom',
                    'cvss': 5.3 if details['severity'] == 'MEDIUM' else 3.1,
                    'impact': details['impact'],
                    'remediation': details['remediation']
                })
                
        return results

# ============================================================================
# EXTERNAL TOOLS INTEGRATION MODULE
# ============================================================================

class ExternalTools:
    """Integration with Nmap, Nikto, and OWASP ZAP"""
    
    def run_all_tools(self, target):
        """Run all external tools"""
        results = []
        
        results.extend(self.run_nmap(target))
        results.extend(self.run_nikto(target))
        results.extend(self.run_zap(target))
        
        return results
        
    def run_nmap(self, target):
        """Run Nmap scan"""
        print("[*] Running Nmap...")
        results = []
        
        try:
            # Extract hostname/IP
            parsed = urlparse(target)
            host = parsed.netloc.split(':')[0]
            
            # Basic port scan
            cmd = ['nmap', '-sV', '-T4', '--top-ports', '100', host]
            
            # Check if nmap is available
            result = subprocess.run(
                ['which', 'nmap'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                print("[!] Nmap not found. Skipping...")
                return results
                
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = process.stdout
            
            # Parse open ports
            open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
            
            for port, service in open_ports:
                results.append({
                    'name': f'Open Port: {port}/{service}',
                    'severity': 'INFO',
                    'confidence': 100,
                    'verified': True,
                    'url': target,
                    'evidence': f'Port {port} running {service}',
                    'source': 'nmap',
                    'cvss': 0.0,
                    'impact': f'Service {service} is publicly accessible',
                    'remediation': 'Review if this port should be publicly accessible'
                })
                
        except subprocess.TimeoutExpired:
            print("[!] Nmap scan timed out")
        except FileNotFoundError:
            print("[!] Nmap not installed")
        except Exception as e:
            print(f"[!] Nmap error: {str(e)}")
            
        return results
        
    def run_nikto(self, target):
        """Run Nikto web scanner"""
        print("[*] Running Nikto...")
        results = []
        
        try:
            # Check if nikto is available
            result = subprocess.run(
                ['which', 'nikto'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                print("[!] Nikto not found. Skipping...")
                return results
                
            cmd = ['nikto', '-h', target, '-Tuning', '1', '-timeout', '10']
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            output = process.stdout
            
            # Parse Nikto findings
            findings = re.findall(r'\+\s+(.*?)(?:\n|$)', output)
            
            for finding in findings[:10]:  # Limit results
                if 'OSVDB' in finding or 'vulnerability' in finding.lower():
                    results.append({
                        'name': 'Nikto Finding',
                        'severity': 'MEDIUM',
                        'confidence': 70,
                        'verified': False,
                        'url': target,
                        'evidence': finding[:200],
                        'source': 'nikto',
                        'cvss': 5.0,
                        'impact': 'Potential web server misconfiguration',
                        'remediation': 'Review and fix identified issue'
                    })
                    
        except subprocess.TimeoutExpired:
            print("[!] Nikto scan timed out")
        except FileNotFoundError:
            print("[!] Nikto not installed")
        except Exception as e:
            print(f"[!] Nikto error: {str(e)}")
            
        return results
        
    def run_zap(self, target):
        """Run OWASP ZAP quick scan"""
        print("[*] Running OWASP ZAP...")
        results = []
        
        try:
            # Check if ZAP is available
            zap_paths = [
                '/usr/share/zaproxy/zap.sh',
                '/opt/zaproxy/zap.sh',
                'zap.sh'
            ]
            
            zap_cmd = None
            for path in zap_paths:
                if os.path.exists(path):
                    zap_cmd = path
                    break
                    
            if not zap_cmd:
                print("[!] OWASP ZAP not found. Skipping...")
                return results
                
            # Quick scan mode
            cmd = [zap_cmd, '-cmd', '-quickurl', target, '-quickout', '/tmp/zap_report.json']
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Try to parse ZAP JSON report
            if os.path.exists('/tmp/zap_report.json'):
                with open('/tmp/zap_report.json', 'r') as f:
                    zap_data = json.load(f)
                    
                for alert in zap_data.get('site', [{}])[0].get('alerts', [])[:10]:
                    severity_map = {
                        '0': 'INFO',
                        '1': 'LOW',
                        '2': 'MEDIUM',
                        '3': 'HIGH'
                    }
                    
                    results.append({
                        'name': f"ZAP: {alert.get('name', 'Unknown')}",
                        'severity': severity_map.get(str(alert.get('riskcode', 1)), 'MEDIUM'),
                        'confidence': alert.get('confidence', 50),
                        'verified': False,
                        'url': alert.get('url', target),
                        'evidence': alert.get('desc', 'No description')[:200],
                        'source': 'zap',
                        'cvss': float(alert.get('cweid', 0)) % 10,
                        'impact': alert.get('desc', 'Unknown impact')[:100],
                        'remediation': alert.get('solution', 'Review ZAP documentation')[:150]
                    })
                    
        except subprocess.TimeoutExpired:
            print("[!] ZAP scan timed out")
        except Exception as e:
            print(f"[!] ZAP error: {str(e)}")
            
        return results

# ============================================================================
# REPORT GENERATOR MODULE
# ============================================================================

class ReportGenerator:
    """Generate professional PDF reports"""
    
    def generate_pdf_report(self, target, results, filename):
        """Generate PDF report using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            doc = SimpleDocTemplate(filename, pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            story.append(Paragraph("VAST - Vulnerability Assessment Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Target info
            info_data = [
                ['Target URL:', target],
                ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Total Findings:', str(len(results))],
            ]
            
            # Count by severity
            severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for result in results:
                severity = result.get('severity', 'INFO')
                severity_count[severity] = severity_count.get(severity, 0) + 1
                
            for severity, count in severity_count.items():
                if count > 0:
                    info_data.append([f'{severity}:', str(count)])
                    
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            summary_text = f"""
            This vulnerability assessment identified {len(results)} potential security issues 
            in the target application. The findings range from informational observations to 
            critical vulnerabilities that require immediate attention. This report details 
            each finding with evidence, impact analysis, and remediation recommendations.
            """
            story.append(Paragraph(summary_text, styles['BodyText']))
            story.append(Spacer(1, 0.3*inch))
            
            # Detailed Findings
            story.append(PageBreak())
            story.append(Paragraph("Detailed Findings", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            for idx, result in enumerate(results, 1):
                # Finding title
                finding_title = f"{idx}. {result['name']}"
                story.append(Paragraph(finding_title, styles['Heading3']))
                story.append(Spacer(1, 0.1*inch))
                
                # Finding details
                details_data = [
                    ['Severity:', result['severity']],
                    ['Confidence:', f"{result['confidence']}%"],
                    ['Status:', 'VERIFIED' if result['verified'] else 'POTENTIAL'],
                    ['CVSS Score:', str(result.get('cvss', 'N/A'))],
                    ['Source:', result['source'].upper()],
                ]
                
                if result.get('url'):
                    details_data.append(['URL:', result['url'][:80]])
                if result.get('parameter'):
                    details_data.append(['Parameter:', result['parameter']])
                    
                details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
                details_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                
                story.append(details_table)
                story.append(Spacer(1, 0.2*inch))
                
                # Impact
                story.append(Paragraph("<b>Impact:</b>", styles['BodyText']))
                story.append(Paragraph(result.get('impact', 'Not specified'), styles['BodyText']))
                story.append(Spacer(1, 0.1*inch))
                
                # Evidence
                if result.get('evidence'):
                    story.append(Paragraph("<b>Evidence:</b>", styles['BodyText']))
                    evidence_text = result['evidence'][:300]
                    story.append(Paragraph(evidence_text, styles['BodyText']))
                    story.append(Spacer(1, 0.1*inch))
                
                # Remediation
                story.append(Paragraph("<b>Remediation:</b>", styles['BodyText']))
                story.append(Paragraph(result.get('remediation', 'Consult security documentation'), styles['BodyText']))
                story.append(Spacer(1, 0.3*inch))
                
            # Disclaimer
            story.append(PageBreak())
            story.append(Paragraph("Disclaimer", styles['Heading2']))
            disclaimer_text = """
            This report is generated by VAST (Vulnerability Assessment & Scanning Tool) 
            for educational and authorized security testing purposes only. The findings 
            should be verified by security professionals. This tool performs detection 
            only and does not exploit vulnerabilities. Use of this tool against systems 
            without explicit authorization is illegal.
            """
            story.append(Paragraph(disclaimer_text, styles['BodyText']))
            
            # Build PDF
            doc.build(story)
            
        except ImportError:
            # Fallback: Generate text report
            print("[!] ReportLab not installed. Generating text report...")
            self.generate_text_report(target, results, filename.replace('.pdf', '.txt'))
            
    def generate_text_report(self, target, results, filename):
        """Generate text report as fallback"""
        with open(filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("VAST - VULNERABILITY ASSESSMENT REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Target: {target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Findings: {len(results)}\n\n")
            
            # Summary
            severity_count = {}
            for result in results:
                sev = result.get('severity', 'INFO')
                severity_count[sev] = severity_count.get(sev, 0) + 1
                
            f.write("SEVERITY BREAKDOWN:\n")
            for sev, count in sorted(severity_count.items()):
                f.write(f"  {sev}: {count}\n")
                
            f.write("\n" + "="*60 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("="*60 + "\n\n")
            
            for idx, result in enumerate(results, 1):
                f.write(f"[{idx}] {result['name']}\n")
                f.write(f"    Severity: {result['severity']}\n")
                f.write(f"    Confidence: {result['confidence']}%\n")
                f.write(f"    Status: {'VERIFIED' if result['verified'] else 'POTENTIAL'}\n")
                f.write(f"    CVSS: {result.get('cvss', 'N/A')}\n")
                f.write(f"    Source: {result['source']}\n")
                if result.get('url'):
                    f.write(f"    URL: {result['url']}\n")
                f.write(f"    Impact: {result.get('impact', 'N/A')}\n")
                f.write(f"    Remediation: {result.get('remediation', 'N/A')}\n")
                if result.get('evidence'):
                    f.write(f"    Evidence: {result['evidence'][:200]}\n")
                f.write("\n")
                
        print(f"[+] Text report generated: {filename}")

# ============================================================================
# MAIN CLI APPLICATION
# ============================================================================

class VAST:
    """Main VAST Application"""
    
    def __init__(self):
        self.scanner = None
        self.ext_tools = ExternalTools()
        self.report_gen = ReportGenerator()
        self.config = Config()
        self.results = []
        
    def show_banner(self):
        """Display tool banner"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    VAST - Vulnerability Assessment & Scanning Tool        ║    
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
        print(banner)
        
    def show_main_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Configure Target")
        print("2. Run Full Automated Scan")
        print("3. Run Custom Vulnerability Scan")
        print("4. Run External Tools Only")
        print("5. View Last Scan Results")
        print("6. Generate Report")
        print("7. Exit")
        print("="*60)
        
    def configure_target(self):
        """Configure scan target and options"""
        print("\n[*] Target Configuration")
        print("-" * 60)
        
        target = input("Enter Target URL (e.g., http://testphp.vulnweb.com): ").strip()
        if not target.startswith(('http://', 'https://')):
            print("[!] Invalid URL. Must start with http:// or https://")
            return False
            
        self.config.target = target
        
        # Optional authentication
        auth_choice = input("\nAuthentication required? (y/n): ").lower()
        if auth_choice == 'y':
            cookie = input("Enter Cookie (optional): ").strip()
            auth_header = input("Enter Authorization Header (optional): ").strip()
            self.config.set_auth(cookie, auth_header)
        
        # Scan options
        print("\n[*] Scan Options:")
        threads = input("Number of threads (default 5): ").strip()
        self.config.threads = int(threads) if threads.isdigit() else 5
        
        timeout = input("Request timeout in seconds (default 10): ").strip()
        self.config.timeout = int(timeout) if timeout.isdigit() else 10
        
        print("\n[+] Configuration saved!")
        print(f"[+] Target: {self.config.target}")
        print(f"[+] Threads: {self.config.threads}")
        print(f"[+] Timeout: {self.config.timeout}s")
        
        # Initialize scanner
        self.scanner = VulnerabilityScanner(self.config)
        return True
        
    def run_full_scan(self):
        """Run comprehensive automated scan"""
        if not self.scanner:
            print("[!] Please configure target first (Option 1)")
            return
            
        print("\n[*] Starting Full Automated Scan...")
        print("[*] This may take several minutes...")
        print("-" * 60)
        
        # Custom vulnerability scans
        print("\n[*] Running Custom Vulnerability Detection...")
        self.results = self.scanner.scan_all()
        
        # External tools
        run_ext = input("\n[?] Run external tools (Nmap, Nikto, ZAP)? (y/n): ").lower()
        if run_ext == 'y':
            print("\n[*] Running External Security Tools...")
            ext_results = self.ext_tools.run_all_tools(self.config.target)
            self.results.extend(ext_results)
        
        self.display_results_summary()
        
    def run_custom_scan(self):
        """Run user-selected vulnerability scans"""
        if not self.scanner:
            print("[!] Please configure target first (Option 1)")
            return
            
        print("\n[*] Custom Vulnerability Scan")
        print("-" * 60)
        print("Select vulnerabilities to scan:")
        print("1. Cross-Site Scripting (XSS)")
        print("2. SQL Injection")
        print("3. Command Injection")
        print("4. CSRF Detection")
        print("5. SSRF Detection")
        print("6. Directory Traversal (LFI)")
        print("7. Open Redirect")
        print("8. Security Headers Check")
        print("9. All of the above")
        print("-" * 60)
        
        choice = input("Enter choice (comma-separated, e.g., 1,2,5): ").strip()
        
        scan_map = {
            '1': ('XSS', self.scanner.scan_xss),
            '2': ('SQL Injection', self.scanner.scan_sqli),
            '3': ('Command Injection', self.scanner.scan_command_injection),
            '4': ('CSRF', self.scanner.scan_csrf),
            '5': ('SSRF', self.scanner.scan_ssrf),
            '6': ('Directory Traversal', self.scanner.scan_directory_traversal),
            '7': ('Open Redirect', self.scanner.scan_open_redirect),
            '8': ('Security Headers', self.scanner.scan_security_headers),
        }
        
        self.results = []
        
        if '9' in choice:
            choices = scan_map.keys()
        else:
            choices = [c.strip() for c in choice.split(',') if c.strip() in scan_map]
        
        if not choices:
            print("[!] Invalid selection")
            return
            
        print("\n[*] Running selected scans...")
        for c in choices:
            vuln_name, scan_func = scan_map[c]
            print(f"[*] Scanning for {vuln_name}...")
            results = scan_func()
            self.results.extend(results)
            
        self.display_results_summary()
        
    def run_external_tools(self):
        """Run only external security tools"""
        if not self.config.target:
            print("[!] Please configure target first (Option 1)")
            return
            
        print("\n[*] Running External Security Tools")
        print("-" * 60)
        print("1. Nmap Port & Service Scan")
        print("2. Nikto Web Scanner")
        print("3. OWASP ZAP Quick Scan")
        print("4. All Tools")
        print("-" * 60)
        
        choice = input("Enter choice: ").strip()
        
        self.results = []
        
        if choice == '1' or choice == '4':
            print("\n[*] Running Nmap...")
            nmap_results = self.ext_tools.run_nmap(self.config.target)
            self.results.extend(nmap_results)
            
        if choice == '2' or choice == '4':
            print("\n[*] Running Nikto...")
            nikto_results = self.ext_tools.run_nikto(self.config.target)
            self.results.extend(nikto_results)
            
        if choice == '3' or choice == '4':
            print("\n[*] Running OWASP ZAP...")
            zap_results = self.ext_tools.run_zap(self.config.target)
            self.results.extend(zap_results)
            
        self.display_results_summary()
        
    def display_results_summary(self):
        """Display scan results summary"""
        if not self.results:
            print("\n[+] No vulnerabilities detected!")
            print("[+] Target appears to be secure (within scan scope)")
            return
            
        print("\n" + "="*60)
        print("SCAN RESULTS SUMMARY")
        print("="*60)
        
        # Count by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in self.results:
            severity = result.get('severity', 'INFO')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
        print(f"\nTotal Findings: {len(self.results)}")
        print("-" * 60)
        for severity, count in severity_count.items():
            if count > 0:
                print(f"{severity}: {count}")
                
        print("\n" + "="*60)
        print("DETAILED FINDINGS")
        print("="*60)
        
        for idx, result in enumerate(self.results, 1):
            print(f"\n[{idx}] {result['name']}")
            print(f"    Severity: {result['severity']}")
            print(f"    Confidence: {result['confidence']}%")
            print(f"    Status: {'VERIFIED' if result['verified'] else 'POTENTIAL'}")
            print(f"    Source: {result['source'].upper()}")
            print(f"    CVSS: {result.get('cvss', 'N/A')}")
            if result.get('url'):
                url_display = result['url'][:80] + '...' if len(result['url']) > 80 else result['url']
                print(f"    URL: {url_display}")
            if result.get('evidence'):
                evidence = result['evidence'][:100] + '...' if len(result['evidence']) > 100 else result['evidence']
                print(f"    Evidence: {evidence}")
                
    def view_last_results(self):
        """View results from last scan"""
        if not self.results:
            print("\n[!] No scan results available. Run a scan first.")
            return
            
        self.display_results_summary()
        
    def generate_report(self):
        """Generate PDF report"""
        if not self.results:
            print("\n[!] No scan results available. Run a scan first.")
            return
            
        print("\n[*] Generating Report...")
        
        report_name = f"VAST_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        try:
            self.report_gen.generate_pdf_report(
                target=self.config.target,
                results=self.results,
                filename=report_name
            )
            print(f"[+] Report generated: {report_name}")
        except Exception as e:
            print(f"[!] Report generation failed: {str(e)}")
            print("[*] Generating text report instead...")
            text_report = report_name.replace('.pdf', '.txt')
            self.report_gen.generate_text_report(
                target=self.config.target,
                results=self.results,
                filename=text_report
            )
            
    def run(self):
        """Main execution loop"""
        self.show_banner()
        
        while True:
            try:
                self.show_main_menu()
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.configure_target()
                elif choice == '2':
                    self.run_full_scan()
                elif choice == '3':
                    self.run_custom_scan()
                elif choice == '4':
                    self.run_external_tools()
                elif choice == '5':
                    self.view_last_results()
                elif choice == '6':
                    self.generate_report()
                elif choice == '7':
                    print("\n[*] 👋 Thank you for using VAST!")
                    print("[*] Remember: Use ethically and legally!")
                    print("[*] 🔏 Stay curious, stay secure!")
                    sys.exit(0)
                else:
                    print("[!] Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\n[!] Operation interrupted by user.")
                continue
            except Exception as e:
                print(f"\n[!] Error: {str(e)}")
                continue

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("\n")
    print("")
    
    # Check required dependencies
    try:
        import requests
        import bs4
        print("")
    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        print("[!] Install with: pip install requests beautifulsoup4")
        sys.exit(1)
    
    # Check optional dependencies
    try:
        import reportlab
        print("")
    except ImportError:
        print("[!] ReportLab not found - Text reports only")
        print("[i] Install with: pip install reportlab")
    
    print("\n")
    
    vast = VAST()

    vast.run()


