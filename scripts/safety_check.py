#!/usr/bin/env python3
"""SetAside Signal safety checker (stdlib only, $0).
Fast checks every run; --daily adds full outbound link crawl.
Writes findings to safety/report.md; exit 1 on any FAIL.
--write-baseline regenerates safety/baseline.json from the live site."""
import hashlib, json, re, socket, ssl, sys, datetime, urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser

SITE = "https://setasidesignal.net"
HOST = "setasidesignal.net"
PAGES = ["/", "/sponsor/", "/terms/", "/privacy/", "/agencies/", "/state/", "/offline", "/data.json", "/sw.js", "/manifest.webmanifest", "/sitemap.xml"]
STRIPE_IDS = {"6oU5kD9O3gXnaPa1Sn0ZW03", "aFacN5d0f9uV6yU68D0ZW0a", "eVq5kDd0fePf3mI1Sn0ZW06", "eVqbJ12lB8qR1eAeF90ZW09"}
KIT_FORM = "10050814"
ALLOW_DOMAINS = {"setasidesignal.net", "sam.gov", "buy.stripe.com", "app.kit.com", "kit.com", "adssettings.google.com",
                 "policies.google.com", "static.cloudflareinsights.com", "schema.org", "www.w3.org", "fonts.googleapis.com",
                 "fonts.gstatic.com", "certifications.sba.gov", "maps.certify.sba.gov", "www.acquisition.gov", "www.apexaccelerators.us", "www.gsa.gov", "pagead2.googlesyndication.com", "www.sba.gov", "sba.gov", "www.google.com"}
HEADERS = {"content-security-policy": None, "strict-transport-security": None, "x-content-type-options": "nosniff",
           "referrer-policy": None, "permissions-policy": None}
UA = {"User-Agent": "SetAsideSignal-SafetyCheck/1.0 (+https://setasidesignal.net)"}
fails, warns, oks = [], [], []

def get(url, method="GET", timeout=20):
    req = urllib.request.Request(url, headers=UA, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, (r.read() if method == "GET" else b""), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, b"", url
    except Exception as e:
        return 0, {}, str(e).encode(), url

class Links(HTMLParser):
    def __init__(s): super().__init__(); s.urls = []
    def handle_starttag(s, tag, attrs):
        for k, v in attrs:
            if k in ("href", "src", "action") and v: s.urls.append(v)

def links(html):
    p = Links(); p.feed(html); return p.urls

def check_pages():
    bodies = {}
    for p in PAGES:
        st, h, b, _ = get(SITE + p)
        if st != 200: fails.append(f"Page {p} returned {st or b.decode()[:120]}")
        else: bodies[p] = b.decode("utf-8", "replace")
    if not fails: oks.append(f"All {len(PAGES)} key pages return 200")
    return bodies

def check_ssl():
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((HOST, 443), timeout=15) as s, ctx.wrap_socket(s, server_hostname=HOST) as t:
            exp = datetime.datetime.strptime(t.getpeercert()["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (exp - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
        (fails if days < 14 else oks).append(f"SSL valid, expires {exp:%Y-%m-%d} ({days} days)")
    except Exception as e:
        fails.append(f"SSL check failed: {e}")

def check_headers():
    st, h, _, _ = get(SITE + "/")
    missing = [k for k, want in HEADERS.items() if k not in h or (want and want not in h[k].lower())]
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp: missing.append("x-frame-options/frame-ancestors")
    if "x-robots-tag" in h and "noindex" in h["x-robots-tag"].lower(): fails.append("Production is sending X-Robots-Tag noindex")
    (fails.append(f"Missing security headers: {', '.join(missing)}") if missing else oks.append("Security headers present"))

def check_safebrowsing():
    st, _, b, _ = get(f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={HOST}")
    try:
        row = json.loads(b.decode().split("\n", 1)[1])[0]
        status, flags = row[1], row[2:7]
        if status == 2 or any(flags): fails.append(f"Google Safe Browsing flags the site: {row}")
        elif status == 1: oks.append("Google Safe Browsing: no unsafe content")
        else: warns.append(f"Google Safe Browsing status {status} (no data/unknown)")
    except Exception as e:
        warns.append(f"Google Safe Browsing check unavailable (HTTP {st}): {e}")

def norm_terms(t):
    t = re.sub(r"<script.*?</script>|<style.*?</style>", "", t, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"(Last updated|Updated|Effective)[^.]{0,40}\d{4}", "", t, flags=re.I)
    return re.sub(r"\s+", " ", t).strip()

def fingerprints(b):
    sp = b.get("/sponsor/", ""); home = b.get("/", "")
    allhtml = "".join(v for k, v in b.items() if not k.endswith((".json", ".xml")))
    return {
        "sponsor_prices": sorted(set(re.findall(r"\$\s?\d[\d,]*(?:\.\d\d)?", re.sub(r"<[^>]+>", " ", sp)))),
        "stripe_links": sorted(set(re.findall(r"https://buy\.stripe\.com/[A-Za-z0-9_]+", allhtml))),
        "kit_forms": sorted(set(re.findall(r"app\.kit\.com/forms/(\d+)/", allhtml))),
        "terms_sha256": hashlib.sha256(norm_terms(b.get("/terms/", "")).encode()).hexdigest(),
        "privacy_sha256": hashlib.sha256(norm_terms(b.get("/privacy/", "")).encode()).hexdigest(),
        "sponsor_text_sha256": hashlib.sha256(norm_terms(sp).encode()).hexdigest(),
    }

def check_changes(b):
    fp = fingerprints(b)
    ids = {u.rsplit("/", 1)[1] for u in fp["stripe_links"]}
    if ids - STRIPE_IDS: fails.append(f"Unexpected Stripe payment link IDs: {sorted(ids - STRIPE_IDS)}")
    if not ids: fails.append("No Stripe payment links found on site")
    if fp["kit_forms"] != [KIT_FORM]: fails.append(f"Kit form ids changed: {fp['kit_forms']} (expected {KIT_FORM})")
    try: base = json.load(open("safety/baseline.json"))
    except Exception: warns.append("No baseline yet"); return fp
    diff = [k for k in base if base[k] != fp.get(k)]
    (fails.append("Key content changed vs baseline: " + ", ".join(f"{k} (was {base[k]}, now {fp.get(k)})" if not k.endswith("sha256") else k for k in diff)
                  + ". If intended, regenerate safety/baseline.json (python3 scripts/safety_check.py --write-baseline).")
     if diff else oks.append("Key content (prices, Stripe links, Kit form, terms, privacy, sponsor text) matches baseline"))
    return fp

def check_stripe_resolve(b):
    for u in sorted(set(re.findall(r"https://buy\.stripe\.com/[A-Za-z0-9_]+", b.get("/sponsor/", "")))):
        st, _, _, final = get(u)
        if urllib.parse.urlparse(final).hostname != "buy.stripe.com" or st != 200:
            fails.append(f"Stripe link {u} -> {final} (HTTP {st})")
    oks.append("Stripe payment links resolve on buy.stripe.com") if not any("Stripe link" in f for f in fails) else None

def check_outbound(b, full):
    pages = dict(b)
    if full:
        sm = b.get("/sitemap.xml", "")
        for loc in re.findall(r"<loc>([^<]+)</loc>", sm):
            p = urllib.parse.urlparse(loc).path
            if p not in pages:
                st, _, body, _ = get(SITE + p)
                if st != 200: fails.append(f"Sitemap page {p} returned {st}")
                else: pages[p] = body.decode("utf-8", "replace")
    ext, internal = set(), set()
    for p, html in pages.items():
        if p.endswith((".json", ".xml", ".js", ".webmanifest")): continue
        for u in links(html):
            pu = urllib.parse.urlparse(urllib.parse.urljoin(SITE + p, u))
            if pu.scheme not in ("http", "https"): continue
            if pu.hostname == HOST: internal.add(pu.path or "/")
            else: ext.add(pu._replace(fragment="").geturl())
    bad = sorted({urllib.parse.urlparse(u).hostname for u in ext} - ALLOW_DOMAINS)
    (fails.append(f"Outbound domains not on allowlist (possible hijack/injection): {bad}") if bad
     else oks.append(f"All outbound domains on allowlist ({len(ext)} URLs)"))
    if not full: return
    sam = sorted(u for u in ext if urllib.parse.urlparse(u).hostname == "sam.gov")
    targets = sorted(u for u in ext if urllib.parse.urlparse(u).hostname not in ("sam.gov", "app.kit.com", "static.cloudflareinsights.com", "schema.org", "www.w3.org")) + sam[:5]
    broken = []
    for u in targets:
        st, _, _, _ = get(u, "HEAD")
        if st in (0, 404, 405, 403, 410) or st >= 500:
            st2, _, _, _ = get(u)
            if st2 == 0 or st2 in (404, 410) or st2 >= 500: broken.append(f"{u} ({st2})")
    for p in sorted(internal):
        if p.startswith("/cdn-cgi/"): continue
        st, _, _, _ = get(SITE + p, "HEAD")
        if st in (404, 410) or st >= 500 or st == 0: broken.append(f"{SITE}{p} ({st})")
    (fails.append("Broken links: " + "; ".join(broken)) if broken
     else oks.append(f"Daily link crawl: {len(pages)} pages, {len(targets)} external + {len(internal)} internal links OK"))

def main():
    full = "--daily" in sys.argv
    b = check_pages()
    if "--write-baseline" in sys.argv:
        json.dump(fingerprints(b), open("safety/baseline.json", "w"), indent=2); print("baseline written"); return
    check_ssl(); check_headers(); check_safebrowsing(); check_changes(b); check_stripe_resolve(b); check_outbound(b, full)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M UTC")
    rep = [f"## Safety check {now} ({'daily full' if full else 'hourly'})", ""]
    rep += [f"- ❌ {x}" for x in fails] + [f"- ⚠️ {x}" for x in warns] + [f"- ✅ {x}" for x in oks]
    open("safety/report.md", "w").write("\n".join(rep) + "\n"); print("\n".join(rep))
    sys.exit(1 if fails else 0)

if __name__ == "__main__": main()
