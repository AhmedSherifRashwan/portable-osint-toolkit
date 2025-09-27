from flask import Flask, render_template, request, jsonify, Response
import whois
from ipwhois import IPWhois
import socket
import dns.resolver
from xhtml2pdf import pisa
import io
import requests
import re
import json
from datetime import datetime
import hashlib
import os

app = Flask(__name__)

# Utility functions
def extract_emails(text):
    """Extract email addresses from text using regex"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return list(set(re.findall(email_pattern, text)))

def extract_phone_numbers(text):
    """Extract phone numbers from text using regex"""
    phone_pattern = r'(\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4})'
    return list(set(re.findall(phone_pattern, text)))

def extract_crypto_addresses(text):
    """Extract cryptocurrency addresses from text"""
    # Bitcoin address pattern (simplified)
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    # Ethereum address pattern
    eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
    
    btc_addresses = re.findall(btc_pattern, text)
    eth_addresses = re.findall(eth_pattern, text)
    
    return {
        'bitcoin': btc_addresses,
        'ethereum': eth_addresses
    }

def get_ip_geolocation(ip):
    """Get geolocation data for an IP address"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

# Routes
@app.route("/")
def index():
    return render_template("index.html", title="Dashboard")

@app.route("/about")
def about():
    return render_template("about.html", title="About")

@app.route("/domains", methods=["GET", "POST"])
def domains():
    whois_data = None
    rdap_result = None
    subdomains_result = None
    dns_records = None
    error = None

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if not domain:
            error = "Please provide a domain."
        else:
            # Normalize domain (remove scheme if provided)
            domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

            # WHOIS lookup
            try:
                w = whois.whois(domain)
                whois_data = {
                    'domain': domain,
                    'registrar': getattr(w, 'registrar', None),
                    'creation_date': getattr(w, 'creation_date', None),
                    'expiration_date': getattr(w, 'expiration_date', None),
                    'updated_date': getattr(w, 'updated_date', None),
                    'name_servers': getattr(w, 'name_servers', None),
                    'emails': getattr(w, 'emails', None),
                    'raw': str(w)
                }
            except Exception as e:
                whois_data = {"error": f"WHOIS error: {e}"}

            # RDAP lookup (resolve domain to an IP then RDAP on IP)
            try:
                ip = socket.gethostbyname(domain)
                obj = IPWhois(ip)
                rdap = obj.lookup_rdap(asn_methods=["whois", "http"])
                rdap["query"] = ip
                rdap_result = rdap
            except Exception as e:
                rdap_result = {"error": f"RDAP error: {e}"}

            # Enhanced subdomain enumeration
            try:
                default_subs = [
                    "www", "mail", "ftp", "test", "dev", "stage", "api", "admin", "portal",
                    "smtp", "imap", "ns1", "ns2", "blog", "shop", "app", "cdn", "assets",
                    "static", "media", "images", "files", "docs", "support", "help"
                ]
                found = []
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 3.0
                resolver.timeout = 2.0
                
                for sub in default_subs:
                    try:
                        qname = f"{sub}.{domain}"
                        answers = resolver.resolve(qname, "A")
                        for rdata in answers:
                            found.append({"subdomain": qname, "address": rdata.to_text()})
                    except Exception:
                        continue
                subdomains_result = found if found else []
            except Exception as e:
                subdomains_result = []

            # DNS Records lookup
            try:
                dns_records = {}
                record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 3.0
                resolver.timeout = 2.0
                
                for record_type in record_types:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        dns_records[record_type] = [str(rdata) for rdata in answers]
                    except Exception:
                        dns_records[record_type] = []
            except Exception as e:
                dns_records = {}

    return render_template(
        "domains.html",
        title="Domains / Infrastructure",
        whois_data=whois_data,
        rdap_result=rdap_result,
        subdomains_result=subdomains_result,
        dns_records=dns_records,
        error=error
    )

@app.route("/ip-intelligence", methods=["GET", "POST"])
def ip_intelligence():
    ip_data = None
    geolocation = None
    error = None

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if not ip:
            error = "Please provide an IP address."
        else:
            # IP WHOIS lookup
            try:
                obj = IPWhois(ip)
                rdap = obj.lookup_rdap(asn_methods=["whois", "http"])
                rdap["query"] = ip
                ip_data = rdap
            except Exception as e:
                ip_data = {"error": f"IP lookup error: {e}"}

            # Geolocation
            geolocation = get_ip_geolocation(ip)

    return render_template(
        "ip_intelligence.html",
        title="IP Intelligence",
        ip_data=ip_data,
        geolocation=geolocation,
        error=error
    )

@app.route("/file-analysis", methods=["GET", "POST"])
def file_analysis():
    file_info = None
    hash_info = None
    metadata = None
    error = None

    if request.method == "POST":
        if 'file' not in request.files:
            error = "No file uploaded."
        else:
            file = request.files['file']
            if file.filename == '':
                error = "No file selected."
            else:
                try:
                    # Read file content
                    content = file.read()
                    
                    # Calculate hashes
                    hash_info = {
                        'md5': hashlib.md5(content).hexdigest(),
                        'sha1': hashlib.sha1(content).hexdigest(),
                        'sha256': hashlib.sha256(content).hexdigest()
                    }
                    
                    # Basic file info
                    file_info = {
                        'filename': file.filename,
                        'size': len(content),
                        'type': file.content_type
                    }
                    
                    # Extract text content for analysis
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                        metadata = {
                            'emails': extract_emails(text_content),
                            'phone_numbers': extract_phone_numbers(text_content),
                            'crypto_addresses': extract_crypto_addresses(text_content)
                        }
                    except:
                        metadata = {}
                        
                except Exception as e:
                    error = f"File analysis error: {e}"

    return render_template(
        "file_analysis.html",
        title="File / Metadata Analysis",
        file_info=file_info,
        hash_info=hash_info,
        metadata=metadata,
        error=error
    )

@app.route("/regex-search", methods=["GET", "POST"])
def regex_search():
    results = None
    error = None

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        search_type = request.form.get("search_type", "emails")
        
        if not text:
            error = "Please provide text to search."
        else:
            try:
                if search_type == "emails":
                    results = extract_emails(text)
                elif search_type == "phones":
                    results = extract_phone_numbers(text)
                elif search_type == "crypto":
                    results = extract_crypto_addresses(text)
                elif search_type == "custom":
                    pattern = request.form.get("custom_pattern", "")
                    if pattern:
                        results = re.findall(pattern, text)
                    else:
                        error = "Please provide a custom regex pattern."
            except Exception as e:
                error = f"Search error: {e}"

    return render_template(
        "regex_search.html",
        title="Regex Search",
        results=results,
        error=error
    )

@app.route("/quick-search")
def quick_search():
    return render_template("quick_search.html", title="Quick Search Hub")

@app.route("/case-management")
def case_management():
    return render_template("case_management.html", title="Case Management")

@app.route("/domains/export", methods=["POST"])
def export_domains_pdf():
    domain = request.form.get("domain")
    whois_text = request.form.get("whois_text", "")
    rdap_text = request.form.get("rdap_text", "")
    subs_text = request.form.get("subs_text", "")
    
    html_content = render_template(
        "export_domains.html", 
        domain=domain,
        whois_text=whois_text,
        rdap_text=rdap_text,
        subs_text=subs_text,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    )

    pdf = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf)
    pdf.seek(0)

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename={domain}_report.pdf"}
    )

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
