# SetAside Signal safety check

Automated, $0 external safety check for https://setasidesignal.net. Python standard library only, no secrets,
no site code. The site itself lives and deploys elsewhere.

**Schedule:** every hour at :37 UTC. The 11:37 UTC run (and manual runs by default) also crawls every page in the sitemap.
Manual run: Actions → SetAside safety check → Run workflow.

**Hourly checks:** key pages return 200; SSL valid and more than 14 days from expiry; security headers (CSP, HSTS,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options or frame-ancestors) and no stray noindex;
Google Safe Browsing (keyless transparency-report lookup); Stripe payment links are the expected ones and resolve on
buy.stripe.com; Kit signup form id unchanged; all outbound domains on an allowlist; sponsor prices, terms, privacy and
sponsor page text match `safety/baseline.json`.

**Daily full check:** every sitemap page returns 200 and outbound/internal links are not broken.

**On failure** the run fails and one open `safety-alert` issue is created or updated; it is closed automatically when checks pass again.

If a content change is intentional, regenerate the baseline: `python3 scripts/safety_check.py --write-baseline` and commit `safety/baseline.json`.
