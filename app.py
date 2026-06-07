"""
NightHawk — Cybersecurity Intelligence Platform  v1.0
30 modules:
  ORIGINAL (16): URL Check, Port Scan, DNS, SSL, WHOIS, Tech Detect,
                 Email Security, Headers, CORS, WAF, Subdomains, IP Geo,
                 Hash Tools, Password Analyzer, Robots.txt, CVE Search
  NEW (14):      Traceroute, Dir Fuzzer, XSS/SQLi/LFI Scanner, Open Redirect,
                 Cookie Analyzer, JWT Analyzer, TLS Deep Scan, Firewall Detect,
                 Email Header Forensics, CIDR Scanner, Banner Grabber,
                 API Security Tester, Network Fingerprinter, SSRF/Cloud Probe
"""

from flask import Flask, render_template, request, jsonify, Response
import requests as http
import ssl, socket, sqlite3, time, threading, concurrent.futures
import json, csv, io, re, os, hashlib, base64, math, ipaddress
from datetime import datetime
from urllib.parse import urlparse, urljoin

# optional packages — degrade gracefully if absent
try:
    import dns.resolver, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

app = Flask(__name__)
app.config['APP_NAME'] = 'NightHawk'
DB_PATH = os.environ.get('DB_PATH', 'history.db')

# ─────────────────────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    d = os.path.dirname(DB_PATH)
    if d: os.makedirs(d, exist_ok=True)
    with get_db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            module      TEXT NOT NULL,
            target      TEXT NOT NULL,
            result_json TEXT,
            severity    TEXT,
            scanned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        c.commit()

init_db()

def save_scan(module, target, result, severity='info'):
    try:
        with get_db() as c:
            c.execute('INSERT INTO scans (module,target,result_json,severity) VALUES (?,?,?,?)',
                      (module, target, json.dumps(result, default=str), severity))
            c.commit()
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
#  SHARED UTILITIES
# ─────────────────────────────────────────────────────────────
SERVICES = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
    110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',995:'POP3S',
    1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',
    6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',8888:'Jupyter',
    9200:'Elasticsearch',27017:'MongoDB',6443:'Kubernetes',9090:'Prometheus'
}
RISKY_PORTS = {23:'Telnet (unencrypted)',3389:'RDP (brute-force target)',
               6379:'Redis (often unauthenticated)',27017:'MongoDB (often unauthenticated)',
               9200:'Elasticsearch (often unauthenticated)',5900:'VNC (brute-force target)',
               21:'FTP (unencrypted)',9090:'Prometheus (metrics exposure)'}

SECURITY_HEADERS = ['strict-transport-security','x-frame-options','x-content-type-options',
                    'content-security-policy','x-xss-protection','referrer-policy','permissions-policy']

def clean_host(host):
    host = host.strip().lower()
    if host.startswith(('http://','https://')):
        host = urlparse(host).hostname
    return host

def ensure_scheme(url):
    url = url.strip()
    if not url.startswith(('http://','https://')):
        url = 'https://' + url
    return url

def resolve_ip(host):
    try: return socket.gethostbyname(host)
    except Exception: return None

def check_ssl_cert(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5); s.connect((hostname,443))
            cert = s.getpeercert()
        exp  = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days = (exp - datetime.utcnow()).days
        iss  = dict(x[0] for x in cert.get('issuer',[]))
        sub  = dict(x[0] for x in cert.get('subject',[]))
        sans = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
        return {'valid':True,'days_left':days,'expires':exp.strftime('%Y-%m-%d'),
                'issuer':iss.get('organizationName',iss.get('commonName','Unknown')),
                'subject':sub.get('commonName',hostname),'sans':sans[:10],'error':None}
    except ssl.SSLCertVerificationError as e:
        return {'valid':False,'days_left':None,'error':str(e)[:100]}
    except Exception as e:
        return {'valid':None,'days_left':None,'error':str(e)[:100]}

def grade_security(score, max_score):
    pct = score/max_score if max_score else 0
    return 'A' if pct>=0.86 else 'B' if pct>=0.71 else 'C' if pct>=0.43 else 'F'

def http_get(url, timeout=10, allow_redirects=True, method='GET', extra_headers=None):
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'}
    if extra_headers: headers.update(extra_headers)
    return http.request(method, url, timeout=timeout, allow_redirects=allow_redirects,
                        headers=headers)

def extract_title(html):
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', html[:8000], re.I)
    return m.group(1).strip() if m else None

# ─────────────────────────────────────────────────────────────
#  MODULE 1 — URL CHECKER
# ─────────────────────────────────────────────────────────────
def run_url_check(url):
    url = ensure_scheme(url)
    parsed = urlparse(url); host = parsed.hostname
    result = dict(url=url,status=None,status_code=None,response_time=None,
                  redirect_url=None,redirect_chain=[],content_type=None,
                  content_length=None,page_title=None,ip_address=None,
                  ssl=None,security_headers=None,server=None,error=None,is_valid=False)
    if host:
        result['ip_address'] = resolve_ip(host)
    if url.startswith('https://') and host:
        result['ssl'] = check_ssl_cert(host)
    try:
        t0 = time.time()
        r  = http_get(url)
        ms = round((time.time()-t0)*1000,2)
        result.update(status_code=r.status_code,response_time=ms,
                      content_type=r.headers.get('Content-Type',''),
                      server=r.headers.get('Server'),is_valid=r.status_code<400)
        cl = r.headers.get('Content-Length')
        result['content_length'] = int(cl) if cl else len(r.content)
        if r.history:
            result['redirect_chain']=[x.url for x in r.history]
            result['redirect_url']=r.url
        if 'text/html' in (result['content_type'] or ''):
            result['page_title'] = extract_title(r.text)
        h = {k.lower():v for k,v in r.headers.items()}
        present=[s for s in SECURITY_HEADERS if s in h]
        missing=[s for s in SECURITY_HEADERS if s not in h]
        score=len(present)
        result['security_headers']={'score':score,'max':7,'grade':grade_security(score,7),
                                    'present':present,'missing':missing}
        sc=r.status_code
        result['status']=('success' if sc<300 else 'redirect' if sc<400
                          else 'client_error' if sc<500 else 'server_error')
    except http.exceptions.ConnectionError:
        result.update(status='unreachable',error='Connection refused / DNS failed')
    except http.exceptions.Timeout:
        result.update(status='timeout',error='Timed out after 10s')
    except Exception as e:
        result.update(status='error',error=str(e)[:120])
    severity = 'info' if result['is_valid'] else 'high'
    save_scan('URL Checker',url,result,severity)
    return result

# ─────────────────────────────────────────────────────────────
#  MODULE 2 — PORT SCANNER
# ─────────────────────────────────────────────────────────────
def _probe_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((host, port))
        s.close()
        return port, 'open' if result==0 else 'closed'
    except Exception:
        return port, 'filtered'

def run_port_scan(host, ports=None):
    host = clean_host(host)
    ip   = resolve_ip(host)
    if not ip:
        return {'error':f'Cannot resolve {host}','host':host,'ip':None,'ports':[]}
    scan_ports = ports or list(SERVICES.keys())
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(_probe_port, ip, p): p for p in scan_ports}
        for f in concurrent.futures.as_completed(futs):
            port, status = f.result()
            entry = {'port':port,'service':SERVICES.get(port,f'Port {port}'),
                     'status':status,'risky':RISKY_PORTS.get(port) if status=='open' else None}
            results.append(entry)
    results.sort(key=lambda x: x['port'])
    open_ports = [r for r in results if r['status']=='open']
    risky      = [r for r in open_ports if r['risky']]
    severity   = 'critical' if risky else 'low' if open_ports else 'info'
    out = {'host':host,'ip':ip,'total_scanned':len(results),
           'open_count':len(open_ports),'risky_count':len(risky),'ports':results}
    save_scan('Port Scanner', host, out, severity)
    return out

# ─────────────────────────────────────────────────────────────
#  MODULE 3 — DNS LOOKUP
# ─────────────────────────────────────────────────────────────
def run_dns_lookup(domain, record_type='ALL'):
    domain = clean_host(domain)
    if not HAS_DNS:
        return {'error':'dnspython not installed','domain':domain,'records':{}}
    types = ['A','AAAA','MX','TXT','NS','CNAME','SOA'] if record_type=='ALL' else [record_type.upper()]
    records = {}
    for rt in types:
        try:
            answers = dns.resolver.resolve(domain, rt, lifetime=5)
            recs = []
            for a in answers:
                txt = a.to_text()
                recs.append({'value':txt,'ttl':answers.rrset.ttl})
                if rt=='MX':
                    recs[-1]['priority']=a.preference
            records[rt] = recs
        except dns.exception.DNSException:
            records[rt] = []
        except Exception:
            records[rt] = []
    # flag SPF / DMARC
    for r in records.get('TXT',[]):
        v = r['value'].lower()
        r['type_hint'] = ('SPF' if 'v=spf1' in v else
                          'DMARC' if 'v=dmarc1' in v else
                          'DKIM'  if 'v=dkim1' in v else None)
    out = {'domain':domain,'records':records,'ip':resolve_ip(domain)}
    save_scan('DNS Lookup', domain, out, 'info')
    return out

# ─────────────────────────────────────────────────────────────
#  MODULE 4 — SSL/TLS ANALYZER
# ─────────────────────────────────────────────────────────────
def _test_tls_version(host, protocol_const):
    try:
        ctx = ssl.SSLContext(protocol_const)
        ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(4); s.connect((host,443))
            return True, s.version(), s.cipher()
    except Exception:
        return False, None, None

def run_ssl_analyze(host):
    host = clean_host(host)
    cert = check_ssl_cert(host)
    # Test protocol support
    protos = {}
    for name, const in [('TLS 1.0', ssl.PROTOCOL_TLS_CLIENT),
                        ('TLS 1.2', ssl.PROTOCOL_TLS_CLIENT),
                        ('TLS 1.3', ssl.PROTOCOL_TLS_CLIENT)]:
        pass  # We use a simpler approach below
    # Get best available connection info
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5); s.connect((host,443))
            ver    = s.version()
            cipher = s.cipher()
            tls13  = ver == 'TLSv1.3'
            tls12  = ver in ('TLSv1.2','TLSv1.3')
            protos = {
                'TLS 1.3': tls13,
                'TLS 1.2': tls12,
                'TLS 1.1': False,
                'TLS 1.0': False,
            }
            cipher_info = {'name':cipher[0],'protocol':cipher[1],'bits':cipher[2]}
    except Exception as e:
        protos = {}; cipher_info = None; ver = None
    # HSTS check
    hsts = False
    try:
        r = http_get(f'https://{host}', timeout=5)
        hsts = 'strict-transport-security' in {k.lower() for k in r.headers}
    except Exception:
        pass
    # Score
    score = 0
    if cert.get('valid'): score+=30
    if cert.get('days_left') and cert['days_left']>30: score+=10
    if protos.get('TLS 1.3'): score+=20
    if protos.get('TLS 1.2'): score+=15
    if hsts: score+=15
    if cipher_info and cipher_info.get('bits',0)>=256: score+=10
    score = min(score,100)
    grade = 'A+' if score>=95 else 'A' if score>=85 else 'B' if score>=70 else 'C' if score>=50 else 'F'
    out = {'host':host,'cert':cert,'protocols':protos,'cipher':cipher_info,
           'hsts':hsts,'score':score,'grade':grade,'tls_version':ver}
    sev = 'critical' if not cert.get('valid') else 'high' if score<50 else 'medium' if score<70 else 'info'
    save_scan('SSL Analyzer', host, out, sev)
    return out

# ─────────────────────────────────────────────────────────────
#  MODULE 5 — WHOIS LOOKUP
# ─────────────────────────────────────────────────────────────
def run_whois(domain):
    domain = clean_host(domain)
    if not HAS_WHOIS:
        return {'error':'python-whois not installed','domain':domain}
    try:
        w = whois_lib.whois(domain)
        def dt(v):
            if isinstance(v, list): v=v[0]
            if isinstance(v, datetime): return v.isoformat()
            return str(v) if v else None
        def lst(v):
            if v is None: return []
            return [str(x) for x in (v if isinstance(v,list) else [v])]
        exp = None
        if w.expiration_date:
            ed = w.expiration_date if not isinstance(w.expiration_date,list) else w.expiration_date[0]
            if isinstance(ed,datetime): exp=(ed-datetime.utcnow()).days
        out = {'domain':domain,'registrar':str(w.registrar or ''),'org':str(w.org or ''),
               'country':str(w.country or ''),'creation_date':dt(w.creation_date),
               'expiration_date':dt(w.expiration_date),'updated_date':dt(w.updated_date),
               'days_until_expiry':exp,'name_servers':lst(w.name_servers),
               'status':lst(w.status),'emails':lst(w.emails),'dnssec':str(w.dnssec or '')}
        sev = 'high' if exp and exp<30 else 'medium' if exp and exp<90 else 'info'
        save_scan('WHOIS', domain, out, sev)
        return out
    except Exception as e:
        return {'error':str(e),'domain':domain}

# ─────────────────────────────────────────────────────────────
#  MODULE 6 — TECHNOLOGY DETECTOR
# ─────────────────────────────────────────────────────────────
TECH_SIGS = {
    'CMS':     [('WordPress',  [r'wp-content',r'wp-includes',r'wordpress']),
                ('Drupal',     [r'drupal',r'sites/default/files']),
                ('Joomla',     [r'/components/com_',r'joomla']),
                ('Shopify',    [r'cdn\.shopify\.com',r'myshopify\.com']),
                ('Ghost',      [r'ghost\.io',r'content/themes']),
                ('Wix',        [r'wix\.com',r'wixstatic\.com']),
                ('Squarespace',[r'squarespace\.com',r'static\.squarespace']),
                ('Webflow',    [r'webflow\.com',r'webflow\.io'])],
    'Framework':[('React',     [r'react\.development\.js',r'react\.production\.min',r'__react']),
                 ('Vue.js',    [r'vue\.js',r'vue\.min\.js',r'__vue']),
                 ('Angular',   [r'angular\.js',r'ng-version',r'angular\.min']),
                 ('Next.js',   [r'/_next/',r'__NEXT_DATA__']),
                 ('Nuxt.js',   [r'/__nuxt',r'nuxt\.js']),
                 ('Django',    [r'csrfmiddlewaretoken',r'django']),
                 ('Laravel',   [r'laravel_session',r'laravel']),
                 ('Ruby on Rails',[r'_rails_',r'X-Powered-By: Phusion Passenger'])],
    'Server':  [('Nginx',      [r'nginx']),
                ('Apache',     [r'apache']),
                ('IIS',        [r'Microsoft-IIS',r'iis']),
                ('Caddy',      [r'caddy']),
                ('LiteSpeed',  [r'LiteSpeed',r'litespeed']),
                ('Cloudflare', [r'cloudflare'])],
    'CDN':     [('Cloudflare', [r'cloudflare',r'cf-ray',r'__cfduid']),
                ('AWS CloudFront',[r'x-amz-cf-id',r'cloudfront\.net']),
                ('Fastly',     [r'x-fastly',r'fastly']),
                ('Akamai',     [r'x-akamai',r'akamai']),
                ('jsDelivr',   [r'cdn\.jsdelivr\.net']),
                ('Cloudinary', [r'cloudinary\.com'])],
    'Analytics':[('Google Analytics',[r'google-analytics\.com',r'gtag\(',r'UA-\d+']),
                 ('Google Tag Manager',[r'googletagmanager\.com',r'GTM-']),
                 ('Mixpanel',   [r'mixpanel\.com']),
                 ('Hotjar',     [r'hotjar\.com',r'hjid']),
                 ('Segment',    [r'segment\.com',r'analytics\.js']),
                 ('Amplitude',  [r'amplitude\.com'])],
    'Libraries':[('jQuery',    [r'jquery\.min\.js',r'jquery-\d']),
                 ('Bootstrap',  [r'bootstrap\.min',r'bootstrap\.css']),
                 ('Tailwind',   [r'tailwind',r'tw-']),
                 ('Font Awesome',[r'fontawesome',r'font-awesome']),
                 ('Lodash',     [r'lodash\.min',r'lodash\.js'])]
}

def run_tech_detect(url):
    url = ensure_scheme(url)
    try:
        r    = http_get(url, timeout=10)
        body = r.text[:150000]
        hdrs = {k.lower():v for k,v in r.headers.items()}
        combined = body + ' ' + json.dumps(dict(r.headers))
        found = {}
        for cat, sigs in TECH_SIGS.items():
            found[cat] = []
            for name, patterns in sigs:
                hits = sum(1 for p in patterns if re.search(p, combined, re.I))
                if hits:
                    conf = min(int((hits/len(patterns))*100)+40, 99)
                    found[cat].append({'name':name,'confidence':conf})
        out = {'url':url,'technologies':found,
               'server':r.headers.get('Server',''),
               'powered_by':r.headers.get('X-Powered-By',''),
               'total_found':sum(len(v) for v in found.values())}
        save_scan('Tech Detector', url, out, 'info')
        return out
    except Exception as e:
        return {'error':str(e),'url':url,'technologies':{}}

# ─────────────────────────────────────────────────────────────
#  MODULE 7 — EMAIL SECURITY
# ─────────────────────────────────────────────────────────────
def run_email_security(domain):
    domain = clean_host(domain)
    if not HAS_DNS:
        return {'error':'dnspython required','domain':domain}
    results = {'domain':domain,'spf':None,'dmarc':None,'dkim':None,'mx':[],'grade':'F','findings':[]}
    findings = []
    # SPF
    try:
        for r in dns.resolver.resolve(domain,'TXT',lifetime=5):
            txt = r.to_text().strip('"')
            if txt.startswith('v=spf1'):
                strict = '-all' in txt
                soft   = '~all' in txt
                results['spf'] = {'record':txt,'strict':strict,'softfail':soft,
                                  'pass': strict or soft,
                                  'grade':'A' if strict else 'B' if soft else 'C'}
                if not strict: findings.append({'severity':'medium','msg':'SPF uses ~all (softfail) instead of -all (hardfail)'})
                break
    except Exception: pass
    if not results['spf']:
        results['spf'] = {'record':None,'pass':False,'grade':'F'}
        findings.append({'severity':'high','msg':'No SPF record found — domain vulnerable to email spoofing'})
    # DMARC
    try:
        for r in dns.resolver.resolve(f'_dmarc.{domain}','TXT',lifetime=5):
            txt = r.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                p = re.search(r'p=(\w+)', txt)
                policy = p.group(1) if p else 'none'
                pct    = re.search(r'pct=(\d+)', txt)
                results['dmarc'] = {'record':txt,'policy':policy,
                                    'pct':int(pct.group(1)) if pct else 100,
                                    'pass':policy in ('quarantine','reject'),
                                    'grade':'A' if policy=='reject' else 'B' if policy=='quarantine' else 'C'}
                if policy=='none': findings.append({'severity':'high','msg':'DMARC policy is p=none — no enforcement, only monitoring'})
                break
    except Exception: pass
    if not results['dmarc']:
        results['dmarc'] = {'record':None,'pass':False,'grade':'F'}
        findings.append({'severity':'critical','msg':'No DMARC record found — phishing risk is high'})
    # DKIM (try common selectors)
    dkim_found = False
    for sel in ['default','google','mail','k1','selector1','selector2','dkim']:
        try:
            dns.resolver.resolve(f'{sel}._domainkey.{domain}','TXT',lifetime=3)
            results['dkim'] = {'selector':sel,'found':True,'grade':'A'}
            dkim_found = True; break
        except Exception: pass
    if not dkim_found:
        results['dkim'] = {'selector':None,'found':False,'grade':'F'}
        findings.append({'severity':'high','msg':'No DKIM record found on common selectors'})
    # MX
    try:
        mxs = sorted(dns.resolver.resolve(domain,'MX',lifetime=5), key=lambda x: x.preference)
        results['mx'] = [{'priority':m.preference,'host':str(m.exchange).rstrip('.')} for m in mxs]
    except Exception: pass
    if not results['mx']:
        findings.append({'severity':'medium','msg':'No MX records found — domain may not receive email'})
    # Overall grade
    scores = {'A':4,'B':3,'C':2,'F':0}
    grades = [results['spf']['grade'], results['dmarc']['grade'], results['dkim']['grade']]
    avg = sum(scores.get(g,0) for g in grades)/3
    results['grade'] = 'A' if avg>=3.5 else 'B' if avg>=2.5 else 'C' if avg>=1.5 else 'F'
    results['findings'] = findings
    sev = 'critical' if any(f['severity']=='critical' for f in findings) else \
          'high' if any(f['severity']=='high' for f in findings) else 'medium'
    save_scan('Email Security', domain, results, sev)
    return results

# ─────────────────────────────────────────────────────────────
#  MODULE 8 — HTTP HEADERS INSPECTOR
# ─────────────────────────────────────────────────────────────
HEADER_INFO = {
    'strict-transport-security': ('HSTS enforces HTTPS connections','Prevents protocol downgrade attacks'),
    'x-frame-options':           ('Prevents clickjacking via iframes','Add X-Frame-Options: DENY or SAMEORIGIN'),
    'x-content-type-options':    ('Prevents MIME-type sniffing','Add X-Content-Type-Options: nosniff'),
    'content-security-policy':   ('Controls resource loading origins','Define trusted sources for scripts/styles/images'),
    'x-xss-protection':          ('Legacy XSS filter for older browsers','Add X-XSS-Protection: 1; mode=block'),
    'referrer-policy':           ('Controls referrer information sharing','Add Referrer-Policy: strict-origin-when-cross-origin'),
    'permissions-policy':        ('Controls browser feature access','Restrict camera, microphone, geolocation access'),
}
LEAK_HEADERS = {'server','x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator','x-drupal-cache'}

def run_headers_inspect(url):
    url = ensure_scheme(url)
    try:
        r    = http_get(url, timeout=10)
        hdrs = dict(r.headers)
        hl   = {k.lower():v for k,v in hdrs.items()}
        security = []
        for h in SECURITY_HEADERS:
            security.append({'header':h,'value':hl.get(h),'present':h in hl,
                             'description':HEADER_INFO.get(h,('',''))[0],
                             'recommendation':HEADER_INFO.get(h,('',''))[1]})
        leaks = {k:v for k,v in hl.items() if k in LEAK_HEADERS and v}
        score = sum(1 for s in security if s['present'])
        cookies = []
        for sc in r.cookies:
            cookies.append({'name':sc.name,'secure':sc.secure,'httponly':sc.has_nonstandard_attr('httponly') or 'httponly' in str(sc).lower(),
                            'samesite':sc.get_nonstandard_attr('samesite'),'domain':sc.domain})
        out = {'url':url,'all_headers':hdrs,'security_headers':security,
               'leaked_info':leaks,'cookies':cookies,'score':score,'max':7,
               'grade':grade_security(score,7),'status_code':r.status_code}
        sev = 'high' if score<=2 else 'medium' if score<=4 else 'low'
        save_scan('Headers Inspector', url, out, sev)
        return out
    except Exception as e:
        return {'error':str(e),'url':url}

# ─────────────────────────────────────────────────────────────
#  MODULE 9 — CORS CHECKER
# ─────────────────────────────────────────────────────────────
def run_cors_check(url, origin=None):
    url    = ensure_scheme(url)
    origin = origin or 'https://evil.example.com'
    result = {'url':url,'test_origin':origin,'cors_enabled':False,'findings':[],
              'headers':{},'severity':'safe'}
    findings = []
    try:
        r = http.options(url, timeout=8, headers={
            'Origin':origin,'Access-Control-Request-Method':'GET',
            'Access-Control-Request-Headers':'Authorization',
            'User-Agent':'Mozilla/5.0 CORSCheck/1.0'})
        acao = r.headers.get('Access-Control-Allow-Origin','')
        acac = r.headers.get('Access-Control-Allow-Credentials','')
        acam = r.headers.get('Access-Control-Allow-Methods','')
        acah = r.headers.get('Access-Control-Allow-Headers','')
        result['cors_enabled'] = bool(acao)
        result['headers'] = {'Access-Control-Allow-Origin':acao,'Access-Control-Allow-Credentials':acac,
                             'Access-Control-Allow-Methods':acam,'Access-Control-Allow-Headers':acah}
        if acao=='*' and acac.lower()=='true':
            findings.append({'severity':'critical','msg':'Wildcard origin (*) with credentials=true — critical misconfiguration'})
            result['severity']='critical'
        elif acao==origin:
            findings.append({'severity':'high','msg':f'Origin is reflected back — arbitrary origin allowed'})
            result['severity']='high'
        elif acao=='*':
            findings.append({'severity':'medium','msg':'Wildcard (*) CORS — any origin can read public resources'})
            result['severity']='medium'
        elif acao:
            findings.append({'severity':'info','msg':f'CORS is restricted to specific origin: {acao}'})
        else:
            findings.append({'severity':'info','msg':'No CORS headers — resource is same-origin only'})
        if 'Authorization' in acah or acah=='*':
            findings.append({'severity':'high','msg':'Authorization header allowed in CORS requests'})
    except Exception as e:
        result['error']=str(e)
    result['findings']=findings
    save_scan('CORS Checker', url, result, result['severity'])
    return result

# ─────────────────────────────────────────────────────────────
#  MODULE 10 — WAF DETECTOR
# ─────────────────────────────────────────────────────────────
WAF_SIGS = {
    'Cloudflare':     {'headers':['cf-ray','cf-cache-status'],'server':['cloudflare'],'body':['cloudflare']},
    'AWS WAF':        {'headers':['x-amzn-requestid','x-amz-cf-id'],'server':['awselb'],'body':[]},
    'Akamai':         {'headers':['x-akamai-transformed','x-check-cacheable','akamai-x-get-true-cache-key'],'server':['akamaighost'],'body':[]},
    'Sucuri':         {'headers':['x-sucuri-id','x-sucuri-cache'],'server':['sucuri'],'body':['sucuri']},
    'Imperva/Incapsula':{'headers':['x-iinfo','x-cdn'],'server':['incapsula'],'body':['incapsula incident']},
    'ModSecurity':    {'headers':['x-mod-security','x-modsec'],'server':['mod_security','modsecurity'],'body':[]},
    'F5 BigIP':       {'headers':['x-wa-info','x-cnection'],'server':['bigip'],'body':[]},
    'Fastly':         {'headers':['x-fastly-request-id','fastly-debug-digest'],'server':['fastly'],'body':[]},
    'Barracuda':      {'headers':['x-barracuda-connect'],'server':['barracuda'],'body':[]},
    'Nginx+':         {'headers':['x-nf-request-id'],'server':['netlify'],'body':[]},
}

def run_waf_detect(url):
    url = ensure_scheme(url)
    detected = []
    try:
        r    = http_get(url, timeout=10)
        hdrs = {k.lower():v.lower() for k,v in r.headers.items()}
        srv  = hdrs.get('server','')
        body = r.text[:20000].lower()
        for waf, sigs in WAF_SIGS.items():
            score=0; evidence=[]
            for h in sigs.get('headers',[]):
                if h in hdrs: score+=2; evidence.append(f'Header: {h}')
            for s in sigs.get('server',[]):
                if s in srv: score+=3; evidence.append(f'Server: {srv[:60]}')
            for b in sigs.get('body',[]):
                if b in body: score+=1; evidence.append(f'Body match: {b}')
            if score>0:
                conf = min(score*20, 99)
                detected.append({'waf':waf,'confidence':conf,'evidence':evidence})
        detected.sort(key=lambda x:-x['confidence'])
        out = {'url':url,'waf_detected':bool(detected),'detections':detected,
               'server_header':r.headers.get('Server',''),'status':r.status_code}
        sev = 'info' if detected else 'medium'
        save_scan('WAF Detector', url, out, sev)
        return out
    except Exception as e:
        return {'error':str(e),'url':url,'waf_detected':False,'detections':[]}

# ─────────────────────────────────────────────────────────────
#  MODULE 11 — SUBDOMAIN ENUMERATOR
# ─────────────────────────────────────────────────────────────
SUBDOMAINS = [
    'www','mail','ftp','dev','api','admin','blog','shop','test','staging','m','mobile',
    'cdn','static','assets','img','images','media','files','download','upload','login',
    'auth','portal','app','beta','alpha','demo','docs','help','support','status',
    'monitor','dashboard','vpn','remote','smtp','pop','imap','ns1','ns2','mx','git',
    'gitlab','jenkins','jira','confluence','wiki','intranet','store','payment','checkout',
    'forum','community','backup','old','new','v2','api2','dev2','uat','qa','prod','s3',
    'cloud','server','web','mail2','email','cpanel','webmail','ftp2','secure','ssl'
]

def _check_subdomain(base, sub):
    host = f'{sub}.{base}'
    try:
        ip = socket.gethostbyname(host)
        return {'subdomain':host,'ip':ip,'found':True}
    except Exception:
        return None

def run_subdomain_enum(domain):
    domain = clean_host(domain)
    found  = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(_check_subdomain, domain, sub): sub for sub in SUBDOMAINS}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r: found.append(r)
    found.sort(key=lambda x: x['subdomain'])
    out = {'domain':domain,'total_checked':len(SUBDOMAINS),
           'found_count':len(found),'subdomains':found}
    sev = 'medium' if len(found)>10 else 'low' if found else 'info'
    save_scan('Subdomain Finder', domain, out, sev)
    return out

# ─────────────────────────────────────────────────────────────
#  MODULE 12 — IP GEOLOCATION
# ─────────────────────────────────────────────────────────────
def run_ip_geo(target):
    target = target.strip()
    ip = target
    # If it looks like a domain, resolve it
    try:
        ipaddress.ip_address(target)
    except ValueError:
        ip = resolve_ip(clean_host(target)) or target
    try:
        r = http.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query',
                     timeout=8)
        data = r.json()
        if data.get('status')=='fail':
            return {'error':data.get('message','Lookup failed'),'target':target}
        data['original_target']=target
        data['resolved_ip']=ip
        sev = 'high' if data.get('proxy') else 'medium' if data.get('hosting') else 'info'
        save_scan('IP Geolocation', target, data, sev)
        return data
    except Exception as e:
        return {'error':str(e),'target':target}

# ─────────────────────────────────────────────────────────────
#  MODULE 13 — HASH TOOLS
# ─────────────────────────────────────────────────────────────
HASH_LENGTHS = {32:'MD5',40:'SHA1',56:'SHA224',64:'SHA256',96:'SHA384',
                128:'SHA512',64:'SHA3-256',128:'SHA3-512'}

def run_hash_tools(text=None, hash_val=None, action='generate'):
    if action=='identify' and hash_val:
        h   = hash_val.strip()
        alg = HASH_LENGTHS.get(len(h), f'Unknown ({len(h)} chars)')
        return {'hash':h,'length':len(h),'likely_algorithm':alg,'action':'identify'}
    if action=='b64encode' and text:
        enc = base64.b64encode(text.encode()).decode()
        return {'input':text,'result':enc,'action':'b64encode'}
    if action=='b64decode' and text:
        try:
            dec = base64.b64decode(text.encode()).decode('utf-8','replace')
            return {'input':text,'result':dec,'action':'b64decode'}
        except Exception as e:
            return {'error':str(e),'action':'b64decode'}
    if text:
        enc = text.encode()
        out = {'input':text,'action':'generate','hashes':{
            'MD5':       hashlib.md5(enc).hexdigest(),
            'SHA1':      hashlib.sha1(enc).hexdigest(),
            'SHA224':    hashlib.sha224(enc).hexdigest(),
            'SHA256':    hashlib.sha256(enc).hexdigest(),
            'SHA384':    hashlib.sha384(enc).hexdigest(),
            'SHA512':    hashlib.sha512(enc).hexdigest(),
            'SHA3-256':  hashlib.sha3_256(enc).hexdigest(),
            'SHA3-512':  hashlib.sha3_512(enc).hexdigest(),
            'BLAKE2b':   hashlib.blake2b(enc).hexdigest(),
        }}
        save_scan('Hash Tools', text[:60], out, 'info')
        return out
    return {'error':'No input provided'}

# ─────────────────────────────────────────────────────────────
#  MODULE 14 — PASSWORD ANALYZER
# ─────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    'password','123456','password1','qwerty','abc123','letmein','monkey','1234567890',
    'password123','admin','welcome','login','pass','master','dragon','sunshine','princess',
    'shadow','superman','michael','football','iloveyou','trustno1','batman','access'
}

def run_password_analyze(password):
    p = password
    has_upper   = bool(re.search(r'[A-Z]', p))
    has_lower   = bool(re.search(r'[a-z]', p))
    has_digit   = bool(re.search(r'\d', p))
    has_symbol  = bool(re.search(r'[^A-Za-z0-9]', p))
    is_common   = p.lower() in COMMON_PASSWORDS
    has_seq     = bool(re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|wer|ert)', p.lower()))
    has_repeat  = bool(re.search(r'(.)\1{2,}', p))
    # Charset size
    cs = 0
    if has_upper:  cs+=26
    if has_lower:  cs+=26
    if has_digit:  cs+=10
    if has_symbol: cs+=32
    if cs==0: cs=26
    entropy = len(p)*math.log2(cs) if p else 0
    # Crack time at 1B/s
    combos = cs**len(p) if p else 1
    secs   = combos/1e9
    if secs<60: crack=f'{secs:.1f} seconds'
    elif secs<3600: crack=f'{secs/60:.1f} minutes'
    elif secs<86400: crack=f'{secs/3600:.1f} hours'
    elif secs<2592000: crack=f'{secs/86400:.1f} days'
    elif secs<31536000: crack=f'{secs/2592000:.1f} months'
    else: crack=f'{secs/31536000:.1f} years'
    # Score
    score = 0
    if len(p)>=8:  score+=15
    if len(p)>=12: score+=15
    if len(p)>=16: score+=10
    if has_upper:  score+=10
    if has_lower:  score+=10
    if has_digit:  score+=10
    if has_symbol: score+=20
    if not is_common: score+=5
    if not has_seq:   score+=3
    if not has_repeat:score+=2
    score = min(score,100)
    label = ('Very Weak' if score<20 else 'Weak' if score<40 else
             'Fair' if score<60 else 'Strong' if score<80 else 'Very Strong')
    recommendations=[]
    if len(p)<12:      recommendations.append('Use at least 12 characters')
    if not has_upper:  recommendations.append('Add uppercase letters')
    if not has_lower:  recommendations.append('Add lowercase letters')
    if not has_digit:  recommendations.append('Add numbers')
    if not has_symbol: recommendations.append('Add special characters (!, @, #, $, ...)')
    if is_common:      recommendations.append('Avoid common/dictionary passwords')
    if has_seq:        recommendations.append('Avoid sequential characters (abc, 123...)')
    if has_repeat:     recommendations.append('Avoid repeated characters (aaa, 111...)')
    criteria = [
        {'label':'At least 8 characters','pass':len(p)>=8},
        {'label':'At least 12 characters','pass':len(p)>=12},
        {'label':'Uppercase letters','pass':has_upper},
        {'label':'Lowercase letters','pass':has_lower},
        {'label':'Numbers','pass':has_digit},
        {'label':'Special characters','pass':has_symbol},
        {'label':'Not a common password','pass':not is_common},
        {'label':'No sequential chars','pass':not has_seq},
        {'label':'No repeated chars','pass':not has_repeat},
    ]
    return {'length':len(p),'score':score,'label':label,'entropy':round(entropy,1),
            'crack_time':crack,'criteria':criteria,'recommendations':recommendations,
            'has_upper':has_upper,'has_lower':has_lower,'has_digit':has_digit,
            'has_symbol':has_symbol,'is_common':is_common}

# ─────────────────────────────────────────────────────────────
#  MODULE 15 — ROBOTS.TXT ANALYZER
# ─────────────────────────────────────────────────────────────
SENSITIVE_PATHS = ['/admin','/administrator','/wp-admin','/wp-login','/login','/logout',
                   '/dashboard','/panel','/config','/configuration','/backup','/backups',
                   '/secret','/secrets','/.env','/.git','/database','/db','/api','/graphql',
                   '/swagger','/phpinfo','/server-status','/private','/internal','/dev','/test']

def run_robots(url):
    url = ensure_scheme(url)
    parsed = urlparse(url)
    robots_url = f'{parsed.scheme}://{parsed.netloc}/robots.txt'
    try:
        r = http_get(robots_url, timeout=8)
        if r.status_code!=200:
            return {'url':robots_url,'found':False,'status_code':r.status_code,'raw':'','rules':[],'sitemaps':[]}
        raw   = r.text[:50000]
        rules = []; sitemaps = []; current_ua = '*'
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            if line.lower().startswith('user-agent:'):
                current_ua = line.split(':',1)[1].strip()
            elif line.lower().startswith('disallow:'):
                path = line.split(':',1)[1].strip()
                rules.append({'user_agent':current_ua,'directive':'Disallow','path':path,
                              'sensitive':any(path.lower().startswith(s) for s in SENSITIVE_PATHS)})
            elif line.lower().startswith('allow:'):
                path = line.split(':',1)[1].strip()
                rules.append({'user_agent':current_ua,'directive':'Allow','path':path,'sensitive':False})
            elif line.lower().startswith('sitemap:'):
                sitemaps.append(line.split(':',1)[1].strip())
        sensitive = [r for r in rules if r.get('sensitive')]
        out = {'url':robots_url,'found':True,'raw':raw,'rules':rules,'sitemaps':sitemaps,
               'sensitive_paths':sensitive,'total_rules':len(rules),
               'user_agents':list({r['user_agent'] for r in rules})}
        sev = 'medium' if sensitive else 'info'
        save_scan('Robots.txt', url, out, sev)
        return out
    except Exception as e:
        return {'error':str(e),'url':robots_url,'found':False}

# ─────────────────────────────────────────────────────────────
#  MODULE 16 — CVE SEARCH
# ─────────────────────────────────────────────────────────────
def run_cve_search(query):
    try:
        r = http.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params={'keywordSearch':query,'resultsPerPage':10},
            timeout=12,
            headers={'User-Agent':'CyberScan/2.0'}
        )
        if r.status_code==403:
            return {'error':'NVD API rate limited — try again in a minute','query':query,'results':[]}
        data = r.json()
        vulns = []
        for item in data.get('vulnerabilities',[]):
            cve  = item.get('cve',{})
            cid  = cve.get('id','')
            desc = next((d['value'] for d in cve.get('descriptions',[]) if d.get('lang')=='en'),'')[:300]
            metrics = cve.get('metrics',{})
            score=None; severity='UNKNOWN'
            if metrics.get('cvssMetricV31'):
                m=metrics['cvssMetricV31'][0]['cvssData']
                score=m.get('baseScore'); severity=m.get('baseSeverity','')
            elif metrics.get('cvssMetricV2'):
                m=metrics['cvssMetricV2'][0]['cvssData']
                score=m.get('baseScore')
                severity=('CRITICAL' if score>=9 else 'HIGH' if score>=7 else 'MEDIUM' if score>=4 else 'LOW') if score else 'UNKNOWN'
            refs = [r2['url'] for r2 in cve.get('references',[])[:3]]
            vulns.append({'id':cid,'description':desc,'score':score,'severity':severity,
                          'published':cve.get('published','')[:10],'references':refs})
        out = {'query':query,'total':data.get('totalResults',0),'results':vulns}
        save_scan('CVE Search', query, out, 'info')
        return out
    except Exception as e:
        return {'error':str(e),'query':query,'results':[]}

# ─────────────────────────────────────────────────────────────
#  FLASK ROUTES
# ─────────────────────────────────────────────────────────────
@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/url-check', methods=['POST'])
def api_url_check():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_url_check(url))

@app.route('/api/port-scan', methods=['POST'])
def api_port_scan():
    d=request.get_json() or {}
    host=d.get('host','').strip()
    if not host: return jsonify({'error':'Host required'}),400
    ports=d.get('ports')
    return jsonify(run_port_scan(host, ports))

@app.route('/api/dns-lookup', methods=['POST'])
def api_dns_lookup():
    d=request.get_json() or {}
    domain=d.get('domain','').strip()
    if not domain: return jsonify({'error':'Domain required'}),400
    return jsonify(run_dns_lookup(domain, d.get('type','ALL')))

@app.route('/api/ssl-analyze', methods=['POST'])
def api_ssl_analyze():
    d=request.get_json() or {}
    host=d.get('host','').strip()
    if not host: return jsonify({'error':'Host required'}),400
    return jsonify(run_ssl_analyze(host))

@app.route('/api/whois', methods=['POST'])
def api_whois():
    d=request.get_json() or {}
    domain=d.get('domain','').strip()
    if not domain: return jsonify({'error':'Domain required'}),400
    return jsonify(run_whois(domain))

@app.route('/api/tech-detect', methods=['POST'])
def api_tech_detect():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_tech_detect(url))

@app.route('/api/email-security', methods=['POST'])
def api_email_security():
    d=request.get_json() or {}
    domain=d.get('domain','').strip()
    if not domain: return jsonify({'error':'Domain required'}),400
    return jsonify(run_email_security(domain))

@app.route('/api/headers-inspect', methods=['POST'])
def api_headers_inspect():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_headers_inspect(url))

@app.route('/api/cors-check', methods=['POST'])
def api_cors_check():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_cors_check(url, d.get('origin')))

@app.route('/api/waf-detect', methods=['POST'])
def api_waf_detect():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_waf_detect(url))

@app.route('/api/subdomain-enum', methods=['POST'])
def api_subdomain_enum():
    d=request.get_json() or {}
    domain=d.get('domain','').strip()
    if not domain: return jsonify({'error':'Domain required'}),400
    return jsonify(run_subdomain_enum(domain))

@app.route('/api/ip-geo', methods=['POST'])
def api_ip_geo():
    d=request.get_json() or {}
    target=d.get('target','').strip()
    if not target: return jsonify({'error':'IP/domain required'}),400
    return jsonify(run_ip_geo(target))

@app.route('/api/hash-tools', methods=['POST'])
def api_hash_tools():
    d=request.get_json() or {}
    return jsonify(run_hash_tools(d.get('text'), d.get('hash'), d.get('action','generate')))

@app.route('/api/password', methods=['POST'])
def api_password():
    d=request.get_json() or {}
    pwd=d.get('password','')
    if not pwd: return jsonify({'error':'Password required'}),400
    return jsonify(run_password_analyze(pwd))

@app.route('/api/robots', methods=['POST'])
def api_robots():
    d=request.get_json() or {}
    url=d.get('url','').strip()
    if not url: return jsonify({'error':'URL required'}),400
    return jsonify(run_robots(url))

@app.route('/api/cve-search', methods=['POST'])
def api_cve_search():
    d=request.get_json() or {}
    query=d.get('query','').strip()
    if not query: return jsonify({'error':'Query required'}),400
    return jsonify(run_cve_search(query))

# ─────────────────────────────────────────────────────────────
#  HISTORY / STATS / EXPORT
# ─────────────────────────────────────────────────────────────
@app.route('/history')
def get_history():
    limit  = request.args.get('limit',200,type=int)
    module = request.args.get('module','')
    q      = request.args.get('q','')
    with get_db() as c:
        sql  = 'SELECT id,module,target,severity,scanned_at FROM scans WHERE 1=1'
        args = []
        if module: sql+=' AND module=?'; args.append(module)
        if q:      sql+=' AND target LIKE ?'; args.append(f'%{q}%')
        sql += ' ORDER BY scanned_at DESC LIMIT ?'; args.append(limit)
        rows = c.execute(sql, args).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/history', methods=['DELETE'])
def del_history():
    with get_db() as c:
        c.execute('DELETE FROM scans'); c.commit()
    return jsonify({'ok':True})

@app.route('/stats')
def get_stats():
    with get_db() as c:
        total   = c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        by_mod  = c.execute('SELECT module,COUNT(*) as cnt FROM scans GROUP BY module ORDER BY cnt DESC').fetchall()
        by_sev  = c.execute('SELECT severity,COUNT(*) as cnt FROM scans GROUP BY severity').fetchall()
        recent  = c.execute("SELECT DATE(scanned_at) as d, COUNT(*) as cnt FROM scans WHERE scanned_at>=DATE('now','-7 days') GROUP BY d ORDER BY d ASC").fetchall()
        critical= c.execute("SELECT COUNT(*) FROM scans WHERE severity='critical'").fetchone()[0]
        avg_t   = None
    return jsonify({'total':total,'critical':critical,
                    'by_module':[dict(r) for r in by_mod],
                    'by_severity':[dict(r) for r in by_sev],
                    'recent_activity':[dict(r) for r in recent],
                    'modules_used':len([r for r in by_mod if r['cnt']>0])})

@app.route('/export')
def export():
    fmt = request.args.get('format','csv')
    with get_db() as c:
        rows = c.execute('SELECT * FROM scans ORDER BY scanned_at DESC').fetchall()
    if fmt=='json':
        out = json.dumps([dict(r) for r in rows], indent=2, default=str)
        return Response(out, mimetype='application/json',
                        headers={'Content-Disposition':'attachment; filename=cyberscan-history.json'})
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['ID','Module','Target','Severity','Scanned At'])
    for r in rows:
        w.writerow([r['id'],r['module'],r['target'],r['severity'],r['scanned_at']])
    buf.seek(0)
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition':'attachment; filename=cyberscan-history.csv'})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 17 — NETWORK TRACEROUTE / HOP ANALYZER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_traceroute(host):
    host = clean_host(host)
    hops = []
    dest_ip = resolve_ip(host)
    if not dest_ip:
        return {'error': 'Cannot resolve host', 'hops': []}
    max_ttl = 30
    port = 33434
    reached = False
    for ttl in range(1, max_ttl + 1):
        s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s_recv.settimeout(2)
        s_recv.bind(("", port))
        s_send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        hop = {'ttl': ttl, 'ip': '*', 'hostname': '*', 'rtt_ms': None}
        try:
            t0 = time.time()
            s_send.sendto(b'', (dest_ip, port))
            data, addr = s_recv.recvfrom(512)
            rtt = round((time.time() - t0) * 1000, 2)
            hop_ip = addr[0]
            try:
                hop_host = socket.gethostbyaddr(hop_ip)[0]
            except Exception:
                hop_host = hop_ip
            hop = {'ttl': ttl, 'ip': hop_ip, 'hostname': hop_host, 'rtt_ms': rtt}
            if hop_ip == dest_ip:
                reached = True
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            s_recv.close()
            s_send.close()
        hops.append(hop)
        if reached:
            break
    return {'target': host, 'dest_ip': dest_ip, 'hops': hops,
            'hop_count': len(hops), 'reached': reached}

@app.route('/api/traceroute', methods=['POST'])
def api_traceroute():
    host = (request.json or {}).get('host', '').strip()
    if not host:
        return jsonify(error='Host required'), 400
    r = run_traceroute(host)
    save_scan('Traceroute', host, r, 'info')
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 18 — HTTP FUZZER / DIR BRUTEFORCE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DIR_WORDLIST = [
    'admin','login','dashboard','api','api/v1','api/v2','backup','config',
    '.git','wp-admin','wp-login.php','phpmyadmin','phpinfo.php','test',
    'dev','staging','debug','console','manager','panel','secret','private',
    'uploads','files','static','assets','js','css','images','img','media',
    'docs','documentation','swagger','openapi.json','swagger.json',
    '.env','.htaccess','.htpasswd','web.config','server-status','robots.txt',
    'sitemap.xml','crossdomain.xml','health','metrics','status','version',
    'actuator','actuator/env','actuator/beans','graphql','graphiql',
]

def run_dir_fuzz(base_url, wordlist=None, threads=20):
    base_url = ensure_scheme(base_url).rstrip('/')
    words = wordlist or DIR_WORDLIST
    found = []
    errors = []
    def probe(word):
        url = f"{base_url}/{word}"
        try:
            r = http_get(url, timeout=5, allow_redirects=False)
            status = r.status_code
            size = len(r.content)
            if status not in (404, 400, 410):
                risk = 'high' if word in ['.env','.git','phpmyadmin','phpinfo.php','.htpasswd','actuator/env','graphiql'] else                        'medium' if status in (200, 301, 302) else 'low'
                return {'url': url, 'status': status, 'size': size, 'risk': risk}
        except Exception:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, w): w for w in words}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)
    found.sort(key=lambda x: (x['status'], x['url']))
    severity = 'critical' if any(f['risk']=='high' for f in found) else                'high' if any(f['risk']=='medium' for f in found) else 'info'
    return {'base_url': base_url, 'probed': len(words), 'found': found,
            'found_count': len(found), 'severity': severity}

@app.route('/api/dir-fuzz', methods=['POST'])
def api_dir_fuzz():
    url = (request.json or {}).get('url', '').strip()
    if not url:
        return jsonify(error='URL required'), 400
    r = run_dir_fuzz(url)
    save_scan('Dir Fuzz', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 19 — XSS / SQLi / LFI PARAM SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "'\"onmouseover=alert(1)",
    "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]
SQLI_PAYLOADS = [
    "'", "' OR '1'='1", "' OR 1=1--", '" OR ""="', "1 AND 1=1",
    "' UNION SELECT NULL--", "'; DROP TABLE users--",
]
LFI_PAYLOADS = [
    "../../../../etc/passwd", "..\..\..\windows\win.ini",
    "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
]
SQLI_ERRORS = [
    'sql syntax','mysql_fetch','ORA-','SQLSTATE','syntax error',
    'mysql error','pg_query','Warning: mysql','Unclosed quotation',
]

def run_vuln_scan(url, scan_xss=True, scan_sqli=True, scan_lfi=True):
    url = ensure_scheme(url)
    parsed = urlparse(url)
    params = dict(p.split('=',1) for p in parsed.query.split('&') if '=' in p)
    results = {'url': url, 'params_tested': list(params.keys()),
               'xss': [], 'sqli': [], 'lfi': [], 'total_issues': 0}
    if not params:
        results['note'] = 'No query params found in URL. Append ?param=value to test.'
        return results

    base = parsed._replace(query='').geturl()
    from urllib.parse import urlencode

    def test_payloads(param, payloads, kind, detect_fn):
        hits = []
        for pay in payloads:
            test_params = dict(params)
            test_params[param] = pay
            test_url = base + '?' + urlencode(test_params)
            try:
                r = http_get(test_url, timeout=7)
                body = r.text[:5000]
                if detect_fn(pay, body, r):
                    hits.append({'param': param, 'payload': pay, 'url': test_url})
            except Exception:
                pass
        return hits

    for param in params:
        if scan_xss:
            hits = test_payloads(param, XSS_PAYLOADS, 'xss',
                lambda p, b, r: p in b or p.lower().replace('<','&lt;') not in b.lower() and p in b)
            results['xss'].extend(hits)
        if scan_sqli:
            hits = test_payloads(param, SQLI_PAYLOADS, 'sqli',
                lambda p, b, r: any(e.lower() in b.lower() for e in SQLI_ERRORS))
            results['sqli'].extend(hits)
        if scan_lfi:
            hits = test_payloads(param, LFI_PAYLOADS, 'lfi',
                lambda p, b, r: 'root:' in b or '[extensions]' in b or 'daemon:' in b)
            results['lfi'].extend(hits)

    results['total_issues'] = len(results['xss']) + len(results['sqli']) + len(results['lfi'])
    severity = 'critical' if results['total_issues'] > 3 else                'high' if results['total_issues'] > 0 else 'info'
    results['severity'] = severity
    return results

@app.route('/api/vuln-scan', methods=['POST'])
def api_vuln_scan():
    data = request.json or {}
    url = data.get('url','').strip()
    if not url:
        return jsonify(error='URL with params required (e.g. https://site.com/page?id=1)'), 400
    r = run_vuln_scan(url, data.get('xss',True), data.get('sqli',True), data.get('lfi',True))
    save_scan('Vuln Scan', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 20 — OPEN REDIRECT CHECKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REDIRECT_PAYLOADS = [
    'https://evil.com', '//evil.com', '/\evil.com',
    'https:evil.com', '/%09/evil.com', '//google.com%2F@evil.com',
]

def run_open_redirect(url):
    url = ensure_scheme(url)
    parsed = urlparse(url)
    params = dict(p.split('=',1) for p in parsed.query.split('&') if '=' in p)
    redirect_params = [p for p in params if any(k in p.lower() for k in
        ['url','redirect','next','return','goto','dest','destination','redir','location','back'])]
    vulns = []
    if not redirect_params:
        redirect_params = list(params.keys())
    base = parsed._replace(query='').geturl()
    from urllib.parse import urlencode
    for param in redirect_params:
        for pay in REDIRECT_PAYLOADS:
            test_params = dict(params); test_params[param] = pay
            test_url = base + '?' + urlencode(test_params)
            try:
                r = http.get(test_url, timeout=6, allow_redirects=False,
                    headers={'User-Agent':'CyberScan/2.0'})
                loc = r.headers.get('Location','')
                if any(e in loc for e in ['evil.com','//evil','\evil']):
                    vulns.append({'param': param, 'payload': pay,
                                  'redirect_to': loc, 'status': r.status_code})
            except Exception:
                pass
    severity = 'high' if vulns else 'info'
    return {'url': url, 'tested_params': redirect_params,
            'vulnerabilities': vulns, 'count': len(vulns), 'severity': severity}

@app.route('/api/open-redirect', methods=['POST'])
def api_open_redirect():
    url = (request.json or {}).get('url','').strip()
    if not url:
        return jsonify(error='URL required'), 400
    r = run_open_redirect(url)
    save_scan('Open Redirect', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 21 — COOKIE SECURITY ANALYZER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_cookie_analysis(url):
    url = ensure_scheme(url)
    result = {'url': url, 'cookies': [], 'issues': [], 'score': 0, 'grade': 'A'}
    try:
        r = http_get(url, timeout=8)
        raw_cookies = r.cookies
        set_cookie_hdrs = r.headers.get('Set-Cookie', '')
        for c in raw_cookies:
            info = {
                'name': c.name,
                'value': c.value[:20] + '...' if len(c.value) > 20 else c.value,
                'domain': c.domain, 'path': c.path,
                'secure': c.secure,
                'http_only': 'httponly' in str(c).lower(),
                'same_site': 'SameSite' in set_cookie_hdrs,
                'expires': str(c.expires) if c.expires else 'Session',
                'issues': []
            }
            if not c.secure:
                info['issues'].append('Missing Secure flag')
                result['issues'].append(f"{c.name}: Missing Secure flag")
            if not info['http_only']:
                info['issues'].append('Missing HttpOnly flag')
                result['issues'].append(f"{c.name}: Missing HttpOnly (XSS risk)")
            if not info['same_site']:
                info['issues'].append('Missing SameSite (CSRF risk)')
                result['issues'].append(f"{c.name}: Missing SameSite")
            sensitive_names = ['session','token','auth','jwt','csrf','user','id','key','secret']
            if any(s in c.name.lower() for s in sensitive_names):
                info['sensitive'] = True
            result['cookies'].append(info)
        total = len(result['issues'])
        result['issue_count'] = total
        result['severity'] = 'high' if total > 4 else 'medium' if total > 1 else 'info'
        result['score'] = max(0, 100 - total * 15)
        result['grade'] = grade_security(result['score'], 100)
    except Exception as e:
        result['error'] = str(e)[:100]
    return result

@app.route('/api/cookie-analysis', methods=['POST'])
def api_cookie_analysis():
    url = (request.json or {}).get('url','').strip()
    if not url:
        return jsonify(error='URL required'), 400
    r = run_cookie_analysis(url)
    save_scan('Cookie Analysis', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 22 — JWT DECODER & ANALYZER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_jwt_analyze(token):
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        return {'error': 'Invalid JWT format — expected 3 parts (header.payload.signature)'}
    def b64_decode(s):
        s += '=' * (4 - len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    try:
        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])
    except Exception as e:
        return {'error': f'Decode error: {e}'}
    issues = []
    alg = header.get('alg','')
    if alg.lower() == 'none':
        issues.append({'severity':'critical','msg':'Algorithm is "none" — signature not verified'})
    if alg.upper() in ('HS256','HS384','HS512'):
        issues.append({'severity':'medium','msg':f'Symmetric algorithm {alg} — secret can be brute-forced'})
    exp = payload.get('exp')
    iat = payload.get('iat')
    nbf = payload.get('nbf')
    now = int(time.time())
    exp_info = None
    if exp:
        exp_dt = datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')
        if exp < now:
            issues.append({'severity':'high','msg':f'Token EXPIRED at {exp_dt}'})
        else:
            days_left = (exp - now) // 86400
            if days_left > 365:
                issues.append({'severity':'medium','msg':f'Very long expiry ({days_left} days)'})
        exp_info = exp_dt
    else:
        issues.append({'severity':'high','msg':'No expiration (exp) claim — token never expires'})
    sensitive_claims = ['password','secret','key','token','credential','ssn','cc']
    for k, v in payload.items():
        if any(s in k.lower() for s in sensitive_claims):
            issues.append({'severity':'high','msg':f'Sensitive claim in payload: "{k}"'})
    return {
        'header': header, 'payload': payload,
        'algorithm': alg, 'expires': exp_info,
        'issued_at': datetime.fromtimestamp(iat).strftime('%Y-%m-%d %H:%M:%S') if iat else None,
        'issues': issues, 'issue_count': len(issues),
        'severity': 'critical' if any(i['severity']=='critical' for i in issues) else
                    'high' if any(i['severity']=='high' for i in issues) else
                    'medium' if issues else 'info'
    }

@app.route('/api/jwt-analyze', methods=['POST'])
def api_jwt_analyze():
    token = (request.json or {}).get('token','').strip()
    if not token:
        return jsonify(error='JWT token required'), 400
    r = run_jwt_analyze(token)
    save_scan('JWT Analyzer', token[:30]+'...', r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 23 — TLS/SSL DEEP SCAN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WEAK_CIPHERS = ['RC4','DES','3DES','EXPORT','NULL','ANON','MD5']
TLS_VERSIONS = [
    ('TLSv1',  ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion,'TLSv1')   else None),
    ('TLSv1.1',ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion,'TLSv1_1') else None),
    ('TLSv1.2',ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion,'TLSv1_2') else None),
    ('TLSv1.3',ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion,'TLSv1_3') else None),
]

def probe_tls_version(host, version_const):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version_const:
            ctx.minimum_version = version_const
            ctx.maximum_version = version_const
        with ctx.wrap_socket(socket.create_connection((host, 443), timeout=4),
                             server_hostname=host) as s:
            return True, s.version(), s.cipher()
    except Exception:
        return False, None, None

def run_tls_deep(host):
    host = clean_host(host)
    basic = check_ssl_cert(host)
    supported = []
    issues = []
    for name, const in TLS_VERSIONS:
        ok, ver, cipher = probe_tls_version(host, const)
        if ok:
            is_weak = name in ('TLSv1','TLSv1.1')
            entry = {'version': name, 'supported': True, 'cipher': cipher[0] if cipher else None,
                     'weak': is_weak}
            supported.append(entry)
            if is_weak:
                issues.append(f'{name} supported — deprecated, vulnerable to BEAST/POODLE')
            if cipher and any(w in cipher[0].upper() for w in WEAK_CIPHERS):
                issues.append(f'Weak cipher in use: {cipher[0]}')
    hsts = False
    try:
        r = http_get(f'https://{host}', timeout=6)
        hsts = 'strict-transport-security' in r.headers
        if not hsts:
            issues.append('HSTS not set — downgrade attacks possible')
    except Exception:
        pass
    severity = 'critical' if len(issues) > 3 else 'high' if issues else 'info'
    return {'host': host, 'cert': basic, 'tls_versions': supported,
            'hsts': hsts, 'issues': issues, 'issue_count': len(issues), 'severity': severity}

@app.route('/api/tls-deep', methods=['POST'])
def api_tls_deep():
    host = (request.json or {}).get('host','').strip()
    if not host:
        return jsonify(error='Host required'), 400
    r = run_tls_deep(host)
    save_scan('TLS Deep Scan', host, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 24 — FIREWALL / RATE LIMIT DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK_SIGNATURES = [
    ("'","sqli"), ("<script>","xss"), ("../","lfi"), ("1 AND 1=1","sqli"),
]

def run_firewall_detect(url):
    url = ensure_scheme(url)
    results = {'url': url, 'waf_detected': False, 'rate_limit': False,
               'blocked_payloads': [], 'allowed_payloads': [], 'waf_name': None}
    # Rate limit test — rapid requests
    times = []
    block_codes = set()
    for i in range(10):
        try:
            t0 = time.time()
            r = http_get(url, timeout=5)
            times.append(round((time.time()-t0)*1000,2))
            block_codes.add(r.status_code)
        except Exception:
            pass
    if 429 in block_codes or 503 in block_codes:
        results['rate_limit'] = True
        results['rate_limit_status'] = list(block_codes)
    # Payload reflection test
    parsed = urlparse(url); base = parsed._replace(query='').geturl()
    for pay, typ in ATTACK_SIGNATURES:
        test_url = base + f'?test={pay}'
        try:
            r = http_get(test_url, timeout=5)
            if r.status_code in (403, 406, 419, 429, 503):
                results['blocked_payloads'].append({'payload': pay, 'type': typ,
                                                    'status': r.status_code})
                results['waf_detected'] = True
            else:
                results['allowed_payloads'].append({'payload': pay, 'type': typ,
                                                    'status': r.status_code})
        except Exception:
            pass
    # WAF fingerprint from headers
    try:
        r = http_get(url, timeout=5)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        server = hdrs.get('server','')
        waf_indicators = {
            'cloudflare': 'Cloudflare', 'sucuri': 'Sucuri', 'aws': 'AWS WAF',
            'akamai': 'Akamai', 'incapsula': 'Imperva Incapsula',
            'barracuda': 'Barracuda', 'f5': 'F5 BIG-IP', 'modsec': 'ModSecurity',
        }
        for key, name in waf_indicators.items():
            if key in server.lower() or key in str(hdrs):
                results['waf_name'] = name
                results['waf_detected'] = True
                break
        results['avg_response_ms'] = round(sum(times)/len(times),2) if times else None
    except Exception:
        pass
    results['severity'] = 'medium' if not results['waf_detected'] else 'info'
    return results

@app.route('/api/firewall-detect', methods=['POST'])
def api_firewall_detect():
    url = (request.json or {}).get('url','').strip()
    if not url:
        return jsonify(error='URL required'), 400
    r = run_firewall_detect(url)
    save_scan('Firewall Detect', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 25 — EMAIL HEADER FORENSICS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_email_header_forensics(raw_headers):
    lines = raw_headers.strip().splitlines()
    result = {'hops': [], 'received': [], 'issues': [], 'spf': None, 'dkim': None,
              'dmarc': None, 'from': None, 'reply_to': None, 'x_mailer': None,
              'message_id': None, 'total_delay_sec': None}
    received_times = []
    for line in lines:
        ll = line.lower()
        if line.startswith('From:'):
            result['from'] = line[5:].strip()
        elif line.startswith('Reply-To:'):
            result['reply_to'] = line[9:].strip()
            if result['from'] and result['reply_to'] and                result['from'].split('@')[-1] != result['reply_to'].split('@')[-1]:
                result['issues'].append('From and Reply-To domains differ — possible phishing')
        elif line.startswith('X-Mailer:'):
            result['x_mailer'] = line[9:].strip()
        elif line.startswith('Message-ID:'):
            result['message_id'] = line[11:].strip()
        elif ll.startswith('received:'):
            result['received'].append(line)
            t = re.search(r'\d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2}', line)
            if t:
                try:
                    received_times.append(datetime.strptime(t.group(), '%d %b %Y %H:%M:%S'))
                except Exception:
                    pass
        elif 'spf' in ll:
            result['spf'] = 'pass' if 'pass' in ll else 'fail' if 'fail' in ll else 'softfail' if 'softfail' in ll else 'neutral'
            if result['spf'] in ('fail','softfail'):
                result['issues'].append(f"SPF {result['spf']} — sender may be spoofed")
        elif 'dkim' in ll:
            result['dkim'] = 'pass' if 'pass' in ll else 'fail'
            if result['dkim'] == 'fail':
                result['issues'].append('DKIM verification failed')
        elif 'dmarc' in ll:
            result['dmarc'] = 'pass' if 'pass' in ll else 'fail'
    if len(received_times) >= 2:
        received_times.sort()
        total_sec = int((received_times[-1]-received_times[0]).total_seconds())
        result['total_delay_sec'] = total_sec
        for i in range(len(received_times)-1):
            delay = int((received_times[i+1]-received_times[i]).total_seconds())
            result['hops'].append({'hop': i+1, 'delay_sec': delay})
    result['issue_count'] = len(result['issues'])
    result['severity'] = 'high' if result['issue_count'] > 1 else                          'medium' if result['issue_count'] == 1 else 'info'
    return result

@app.route('/api/email-forensics', methods=['POST'])
def api_email_forensics():
    headers = (request.json or {}).get('headers','').strip()
    if not headers:
        return jsonify(error='Raw email headers required'), 400
    r = run_email_header_forensics(headers)
    save_scan('Email Forensics', 'raw-headers', r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 26 — CIDR / IP RANGE SCANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def run_cidr_scan(cidr, ports=(80,443,22,21,25)):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {'error': str(e)}
    if network.num_addresses > 256:
        return {'error': 'CIDR range too large (max /24 = 256 hosts)'}
    live_hosts = []
    def check_host(ip):
        ip_str = str(ip)
        open_ports = []
        for p in ports:
            try:
                with socket.create_connection((ip_str, p), timeout=0.8):
                    open_ports.append(p)
            except Exception:
                pass
        if open_ports:
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                hostname = None
            return {'ip': ip_str, 'hostname': hostname, 'open_ports': open_ports}
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(check_host, ip) for ip in network.hosts()]
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                live_hosts.append(r)
    live_hosts.sort(key=lambda x: ipaddress.ip_address(x['ip']))
    return {'cidr': cidr, 'total_hosts': network.num_addresses - 2,
            'live_count': len(live_hosts), 'live_hosts': live_hosts,
            'ports_checked': list(ports), 'severity': 'info'}

@app.route('/api/cidr-scan', methods=['POST'])
def api_cidr_scan():
    data = request.json or {}
    cidr = data.get('cidr','').strip()
    ports = data.get('ports', [80,443,22,21,25])
    if not cidr:
        return jsonify(error='CIDR range required (e.g. 192.168.1.0/24)'), 400
    r = run_cidr_scan(cidr, tuple(ports))
    save_scan('CIDR Scan', cidr, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 27 — SHODAN-STYLE BANNER GRABBER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BANNER_PORTS = {
    21: ('FTP', b'\r\n'), 22: ('SSH', b'\r\n'), 25: ('SMTP', b'EHLO scan\r\n'),
    110: ('POP3', b'\r\n'), 143: ('IMAP', b'\r\n'), 3306: ('MySQL', b'\r\n'),
    6379: ('Redis', b'PING\r\n'), 9200: ('Elasticsearch', b'GET / HTTP/1.0\r\n\r\n'),
    5432: ('PostgreSQL', b'\r\n'), 27017: ('MongoDB', b'\r\n'),
}

def grab_banner(host, port, probe):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            if probe != b'\r\n':
                s.sendall(probe)
            else:
                time.sleep(0.3)
            banner = s.recv(512).decode('utf-8', errors='replace').strip()
            return banner[:200]
    except Exception:
        return None

def run_banner_grab(host):
    host = clean_host(host)
    results = {'host': host, 'ip': resolve_ip(host), 'services': [], 'issues': []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(grab_banner, host, port, probe): (port, svc)
                   for port, (svc, probe) in BANNER_PORTS.items()}
        for fut in concurrent.futures.as_completed(futures):
            port, svc = futures[fut]
            banner = fut.result()
            if banner:
                entry = {'port': port, 'service': svc, 'banner': banner}
                # Version disclosure check
                ver_patterns = [r'\b\d+\.\d+\.\d+\b', r'version[\s:]+([\d.]+)', r'v(\d+\.\d+)']
                for pat in ver_patterns:
                    m = re.search(pat, banner, re.I)
                    if m:
                        entry['version_disclosed'] = m.group(0)
                        results['issues'].append(f'Port {port} ({svc}): Version disclosed — {m.group(0)}')
                        break
                if port in RISKY_PORTS:
                    results['issues'].append(f'Port {port}: {RISKY_PORTS[port]}')
                results['services'].append(entry)
    results['service_count'] = len(results['services'])
    results['severity'] = 'high' if len(results['issues']) > 2 else                           'medium' if results['issues'] else 'info'
    return results

@app.route('/api/banner-grab', methods=['POST'])
def api_banner_grab():
    host = (request.json or {}).get('host','').strip()
    if not host:
        return jsonify(error='Host required'), 400
    r = run_banner_grab(host)
    save_scan('Banner Grab', host, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 28 — API SECURITY TESTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
API_CHECKS = [
    ('No Auth on endpoint',  'GET',  '',         lambda r: r.status_code == 200),
    ('BFLA — POST without auth', 'POST', '',     lambda r: r.status_code not in (401,403)),
    ('HTTP Methods — PUT',   'PUT',  '',         lambda r: r.status_code not in (405,501)),
    ('HTTP Methods — DELETE','DELETE','',        lambda r: r.status_code not in (405,501)),
    ('IDOR test — id=0',     'GET',  '?id=0',    lambda r: r.status_code == 200),
    ('IDOR test — id=-1',    'GET',  '?id=-1',   lambda r: r.status_code == 200),
    ('Mass assignment — extra fields', 'POST', '', lambda r: r.status_code not in (400,422,403)),
    ('Verbose error on bad JSON', 'POST', '',    lambda r: any(e in r.text[:500].lower()
        for e in ['traceback','exception','stack trace','syntax error'])),
]

def run_api_security(url):
    url = ensure_scheme(url).rstrip('/')
    issues = []
    tested = []
    headers = {'Content-Type':'application/json','User-Agent':'CyberScan/2.0'}
    for name, method, suffix, check_fn in API_CHECKS:
        test_url = url + suffix
        body = None
        if method in ('POST','PUT') and 'extra' in name.lower():
            body = json.dumps({'admin':True,'role':'admin','__proto__':{'admin':True}})
        elif method in ('POST',):
            body = '{invalid json' if 'bad JSON' in name else '{}'
        try:
            r = http.request(method, test_url, data=body, headers=headers,
                             timeout=6, allow_redirects=False)
            tested.append({'check': name, 'method': method, 'status': r.status_code})
            if check_fn(r):
                issues.append({'check': name, 'method': method, 'url': test_url,
                               'status': r.status_code, 'severity': 'high'})
        except Exception:
            pass
    result = {'url': url, 'issues': issues, 'tested': tested,
              'issue_count': len(issues),
              'severity': 'critical' if len(issues) > 4 else
                          'high' if issues else 'info'}
    return result

@app.route('/api/api-security', methods=['POST'])
def api_api_security():
    url = (request.json or {}).get('url','').strip()
    if not url:
        return jsonify(error='API endpoint URL required'), 400
    r = run_api_security(url)
    save_scan('API Security', url, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 29 — NETWORK SERVICE FINGERPRINTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OS_HINTS = {
    'ubuntu': 'Ubuntu Linux', 'debian': 'Debian Linux', 'centos': 'CentOS Linux',
    'windows': 'Windows Server', 'microsoft': 'Windows Server',
    'nginx': 'Nginx (Linux)', 'apache': 'Apache (Linux/Unix)',
    'iis': 'IIS (Windows)', 'openssl': 'OpenSSL-based',
    'freebsd': 'FreeBSD', 'cisco': 'Cisco IOS',
}

def run_fingerprint(host):
    host = clean_host(host)
    ip = resolve_ip(host)
    result = {'host': host, 'ip': ip, 'os_guess': [], 'services': {},
              'web': {}, 'issues': []}
    # HTTP fingerprint
    for scheme in ('https','http'):
        try:
            r = http_get(f'{scheme}://{host}', timeout=6)
            hdrs = dict(r.headers)
            server = hdrs.get('Server','')
            powered = hdrs.get('X-Powered-By','')
            result['web'] = {'server': server, 'powered_by': powered,
                             'status': r.status_code,
                             'headers': {k:v for k,v in hdrs.items()}}
            for hint, os_name in OS_HINTS.items():
                if hint in (server+powered).lower():
                    if os_name not in result['os_guess']:
                        result['os_guess'].append(os_name)
            if server:
                result['issues'].append(f'Server header reveals: {server}')
            if powered:
                result['issues'].append(f'X-Powered-By reveals: {powered}')
            break
        except Exception:
            pass
    # SSH fingerprint
    banner = grab_banner(host, 22, b'\r\n')
    if banner:
        result['services']['ssh'] = banner
        m = re.search(r'SSH-\S+', banner)
        if m:
            result['issues'].append(f'SSH version disclosed: {m.group(0)}')
    result['severity'] = 'medium' if result['issues'] else 'info'
    return result

@app.route('/api/fingerprint', methods=['POST'])
def api_fingerprint():
    host = (request.json or {}).get('host','').strip()
    if not host:
        return jsonify(error='Host required'), 400
    r = run_fingerprint(host)
    save_scan('Fingerprint', host, r, r.get('severity','info'))
    return jsonify(r)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MODULE 30 — CLOUD METADATA / SSRF PROBE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLOUD_META_ENDPOINTS = [
    ('AWS IMDSv1',     'http://169.254.169.254/latest/meta-data/'),
    ('AWS IMDSv2',     'http://169.254.169.254/latest/meta-data/'),
    ('GCP Metadata',   'http://metadata.google.internal/computeMetadata/v1/'),
    ('Azure IMDS',     'http://169.254.169.254/metadata/instance?api-version=2021-02-01'),
    ('DigitalOcean',   'http://169.254.169.254/metadata/v1/'),
    ('Oracle Cloud',   'http://169.254.169.254/opc/v1/instance/'),
]
SSRF_TEST_URLS = [
    'http://localhost/', 'http://127.0.0.1/', 'http://0.0.0.0/',
    'http://[::1]/', 'http://localhost:8080/', 'http://127.1/',
    'http://169.254.169.254/', 'http://metadata/',
]

def run_ssrf_cloud_probe(url):
    """Tests if a URL parameter accepts SSRF payloads or cloud metadata is accessible."""
    url = ensure_scheme(url)
    parsed = urlparse(url)
    params = dict(p.split('=',1) for p in parsed.query.split('&') if '=' in p)
    results = {'url': url, 'cloud_metadata_accessible': [],
               'ssrf_potential': [], 'params_tested': list(params.keys())}
    # Direct cloud metadata check (only works if running on cloud)
    for name, meta_url in CLOUD_META_ENDPOINTS:
        try:
            headers = {}
            if 'GCP' in name:
                headers = {'Metadata-Flavor': 'Google'}
            elif 'Azure' in name:
                headers = {'Metadata': 'true'}
            r = http.get(meta_url, timeout=2, headers=headers)
            if r.status_code == 200 and len(r.text) > 10:
                results['cloud_metadata_accessible'].append(
                    {'provider': name, 'url': meta_url, 'sample': r.text[:100]})
        except Exception:
            pass
    # SSRF via URL params
    if params:
        base = parsed._replace(query='').geturl()
        from urllib.parse import urlencode
        for param in list(params.keys())[:3]:
            for ssrf_url in SSRF_TEST_URLS[:4]:
                test_params = dict(params); test_params[param] = ssrf_url
                test_full = base + '?' + urlencode(test_params)
                try:
                    r = http_get(test_full, timeout=4)
                    if r.status_code == 200 and any(
                        indicator in r.text.lower() for indicator in
                        ['ami-','instance-id','metadata','local-ipv4','169.254']):
                        results['ssrf_potential'].append(
                            {'param': param, 'payload': ssrf_url, 'status': r.status_code})
                except Exception:
                    pass
    results['severity'] = 'critical' if results['cloud_metadata_accessible'] or results['ssrf_potential']                           else 'info'
    results['issue_count'] = len(results['cloud_metadata_accessible']) + len(results['ssrf_potential'])
    return results

@app.route('/api/ssrf-probe', methods=['POST'])
def api_ssrf_probe():
    url = (request.json or {}).get('url','').strip()
    if not url:
        return jsonify(error='URL required'), 400
    r = run_ssrf_cloud_probe(url)
    save_scan('SSRF Probe', url, r, r.get('severity','info'))
    return jsonify(r)



if __name__=='__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
