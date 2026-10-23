"""Unit tests for the safety and SEO checkers (stdlib only, no network): python3 -m unittest discover -s tests"""
import importlib.util, json, sys, unittest, urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec); argv, sys.argv = sys.argv, ["x"]
    try: spec.loader.exec_module(m)
    finally: sys.argv = argv
    return m
sc, seo = load("safety_check"), load("seo_check")

# What Cloudflare Email Obfuscation (kept ON for setasidesignal.net) serves instead of a mailto link.
OBF = ('<p>Email <a href="/cdn-cgi/l/email-protection#026a676e6e6d4271677663716b6667716b656c636e2c6c6776">'
       '<span class="__cf_email__" data-cfemail="026a676e6e6d4271677663716b6667716b656c636e2c6c6776">[email&#160;protected]</span></a>.</p>'
       '<script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>')

class Rep:
    def __init__(s): s.items = []
    def fail(s, p, m): s.items.append(("FAIL", p, m))
    def warn(s, p, m): s.items.append(("WARN", p, m))
    def ok(s, p, m): s.items.append(("PASS", p, m))
    def fails(s): return [i for i in s.items if i[0] == "FAIL"]

class EmailObfuscation(unittest.TestCase):
    def test_safety_crawl_skips_cdn_cgi(self):
        paths = {urllib.parse.urlparse(urllib.parse.urljoin("https://setasidesignal.net/sponsor/", u)).path for u in sc.links(OBF)}
        self.assertIn("/cdn-cgi/l/email-protection", paths)
        self.assertTrue(all(sc.skip_internal(p) for p in paths if p.startswith("/cdn-cgi/")))
        self.assertFalse(sc.skip_internal("/sponsor/"))
    def test_safety_text_hash_decodes_address(self):
        self.assertIn("hello@setasidesignal.net", sc.norm_terms(OBF))
        self.assertEqual(sc.norm_terms(OBF), sc.norm_terms('<p>Email <a href="mailto:hello@setasidesignal.net">hello@setasidesignal.net</a>.</p>'))
    def test_seo_check_never_queues_email_protection_links(self):
        page = f'<!doctype html><html lang="en"><head><title>T</title><meta name="viewport" content="width=device-width"></head><body><h1>H</h1>{OBF}<a href="/state/">s</a></body></html>'
        orig = seo.fetch
        seo.fetch = lambda url, *a, **k: {"status": 200, "url": url, "headers": {}, "body": page, "bytes": len(page), "error": None, "redirects": []}
        try:
            targets = set(); seo.check_page("https://setasidesignal.net/sponsor/", "setasidesignal.net", Rep(), 5, {}, {}, targets)
        finally:
            seo.fetch = orig
        self.assertIn("https://setasidesignal.net/state/", targets)
        self.assertFalse([t for t in targets if "/cdn-cgi/" in t])

class AiAnswerChecks(unittest.TestCase):
    def test_robots_ai_crawlers(self):
        ok = "User-agent: GPTBot\nUser-agent: ClaudeBot\nAllow: /\nDisallow: /api/\n\nUser-agent: *\nAllow: /\nDisallow: /api/\n"
        r = Rep(); self.assertEqual(seo.check_ai_robots(ok, "x.net", r), []); self.assertFalse(r.fails())
        r = Rep(); self.assertEqual(seo.check_ai_robots("User-agent: CCBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n", "x.net", r), ["CCBot"])
    def test_llms_txt(self):
        good = "# Site\n\n> What it is.\n\n- [A](https://x.net/a)\n- [B](https://x.net/b)\n- [C](https://x.net/c)\n"
        r = Rep(); seo.check_llms({"status": 200, "body": good, "headers": {"Content-Type": "text/plain"}}, r); self.assertFalse(r.fails())
        for bad in ({"status": 404}, {"status": 200, "body": "<html>not llms</html>", "headers": {}}):
            r = Rep(); seo.check_llms(bad, r); self.assertTrue(r.fails())
    def test_structured_data_required_fields_and_honesty(self):
        ld = {"@context": "https://schema.org", "@graph": [
            {"@type": "Organization", "name": "S", "url": "https://x.net/"}, {"@type": "WebSite", "name": "S", "url": "https://x.net/"},
            {"@type": "FAQPage", "mainEntity": [{"@type": "Question", "name": "Is it free?", "acceptedAnswer": {"@type": "Answer", "text": "Yes."}}]},
            {"@type": "Article", "headline": "H", "datePublished": "2026-10-15", "author": {"@type": "Organization", "name": "S"}, "image": "https://x.net/og.png"},
            {"@type": "Product", "name": "Plan", "offers": {"@type": "Offer", "price": "1250", "priceCurrency": "USD"}},
            {"@type": "BreadcrumbList", "itemListElement": [{"@type": "ListItem", "position": 1, "name": "Home", "item": "https://x.net/"}]}]}
        page = "<dl><dt>Is it free?</dt><dd>Yes.</dd></dl><p>From $1,250/month</p>"
        r = Rep(); self.assertEqual(seo.check_structured("/", [json.dumps(ld)], page, r), 0, r.items)
        r = Rep(); self.assertGreaterEqual(seo.check_structured("/", [json.dumps(ld)], "<p>nothing visible</p>", r), 2)  # hidden FAQ + unshown price

class AdSenseLoader(unittest.TestCase):
    LOADER = '<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-7426783216892674" crossorigin="anonymous"></script>'
    def test_loader_and_ad_hosts_on_allowlist(self):
        hosts = {urllib.parse.urlparse(u).hostname for u in sc.links(self.LOADER)}
        self.assertEqual(hosts, {"pagead2.googlesyndication.com"})
        self.assertTrue(hosts <= sc.ALLOW_DOMAINS)
        for h in ("tpc.googlesyndication.com", "googleads.g.doubleclick.net", "adservice.google.com", "fundingchoicesmessages.google.com"):
            self.assertIn(h, sc.ALLOW_DOMAINS)
    def test_unknown_script_host_still_not_allowed(self):
        self.assertNotIn("evil.example.com", sc.ALLOW_DOMAINS)

if __name__ == "__main__":
    unittest.main()
