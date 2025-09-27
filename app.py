from flask import Flask, render_template, request
import whois
from ipwhois import IPWhois
import socket
import dns.resolver
from xhtml2pdf import pisa
import io
from flask import Response


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", title="Dashboard")


@app.route("/about")
def about():
    return render_template("about.html", title="About")


@app.route("/domains", methods=["GET", "POST"])
def domains():
    whois_text = None
    rdap_result = None
    subdomains_result = None
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
                w = whois.whois(domain) # type: ignore
                # many whois libs provide .text or dict-like fields
                whois_text = getattr(w, "text", None) or str(w)
            except Exception as e:
                whois_text = f"WHOIS error: {e}"

            # RDAP lookup (resolve domain to an IP then RDAP on IP)
            try:
                ip = socket.gethostbyname(domain)
                obj = IPWhois(ip)
                rdap = obj.lookup_rdap(asn_methods=["whois", "http"])
                rdap["query"] = ip
                rdap_result = rdap  # it's a dict-like object; template will json-format it
            except Exception as e:
                rdap_result = {"error": f"RDAP error: {e}"}

            # Basic subdomain enumeration (lightweight)
            try:
                # small sensible default list — later we can expand or load from wordlist file
                default_subs = [
                    "www", "mail", "ftp", "test", "dev", "stage", "api", "admin", "portal",
                    "smtp", "imap", "ns1", "ns2", "blog", "shop"
                ]
                found = []
                resolver = dns.resolver.Resolver()
                # short timeouts to keep UI responsive
                resolver.lifetime = 3.0
                resolver.timeout = 2.0
                for sub in default_subs:
                    try:
                        qname = f"{sub}.{domain}"
                        answers = resolver.resolve(qname, "A")
                        for rdata in answers:
                            found.append({"subdomain": qname, "address": rdata.to_text()})
                    except Exception:
                        # ignore NXDOMAIN/timeouts etc.
                        continue
                subdomains_result = found if found else []
            except Exception as e:
                subdomains_result = []
                # not fatal — keep going

    return render_template(
        "domains.html",
        title="Domains / Infra",
        whois_text=whois_text,
        rdap_result=rdap_result,
        subdomains_result=subdomains_result,
        error=error
    )

@app.route("/domains/export", methods=["POST"])
def export_domains_pdf():
    domain = request.form.get("domain")
    html_content = render_template("export_domains.html", domain=domain)

    pdf = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf)
    pdf.seek(0)

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename={domain}_report.pdf"}
    )

if __name__ == "__main__":
    app.run(debug=True)
