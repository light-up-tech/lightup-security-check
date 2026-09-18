# Light Up Tech -- Free Security Health Check

A small web app: a visitor enters a domain, it runs three passive checks
(SSL/TLS certificate, HTTP security headers, SPF/DMARC email authentication),
and an AI (Claude) turns the results into a plain-English report. Meant as a
lead-magnet for lightuptech.net's mentoring/consulting services -- not a full
vulnerability scanner (see the note at the bottom about growing it into one).

## 1. Run it locally first

```bash
cd lightup-security-check
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # then edit .env and add your Anthropic API key
export $(cat .env | xargs)        # Windows: set each var manually, or use python-dotenv
python app.py
```

Open http://localhost:5000, enter a domain you own (or a public one you're
comfortable testing, like your own site), check the authorization box, and
run it. If you skip the API key, you'll still get results -- just as a raw
list instead of an AI-written report -- so you can confirm the checks work
before paying for any API usage.

Get an Anthropic API key at https://console.anthropic.com/ (this uses the
same account type as Claude.ai, but API keys are billed separately, pay-as-you-go
-- keep an eye on usage once this is public).

## 2. Deploy it somewhere it can run continuously

WordPress hosting (whether wordpress.com or a shared host) generally can't
run a Python app, so this needs to live on a separate small host. Two free-tier
options that work well for a low-traffic tool like this:

**Render** (render.com)
1. Push this folder to a GitHub repo.
2. In Render: New -> Web Service -> connect the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add `ANTHROPIC_API_KEY` (and optionally `ANTHROPIC_MODEL`) under Environment.
6. Deploy. Render gives you a URL like `lightup-security-check.onrender.com`.

**Railway** (railway.app) works almost identically -- connect the repo, set
the same environment variable, it auto-detects the start command from a
`Procfile` (add one containing `web: gunicorn app:app` if it doesn't).

Either free tier is fine to start; both will "sleep" the app after inactivity
on the free plan, so the first visitor after a quiet period waits a few
extra seconds -- acceptable for a low-traffic lead magnet, worth upgrading
once it gets real usage.

## 3. Put it on lightuptech.net

You don't need to rebuild this inside WordPress. Two options, easiest first:

**Option A -- link to it.** Add a page or menu item ("Free Security Check")
that simply links to your deployed URL (e.g. `check.lightuptech.net` if you
point a subdomain at it, or the raw Render URL). Simplest, and it's the
approach most consulting sites use for tools like this.

**Option B -- embed it in a WordPress page.** Add a Custom HTML block with:
```html
<iframe src="https://your-deployed-url.onrender.com"
        style="width:100%; height:900px; border:none;"></iframe>
```
Note: iframe embedding can feel slightly clunky (scrolling inside a box) --
Option A usually looks more professional for a standalone tool.

If you want it on a subdomain like `check.lightuptech.net`, add a CNAME
record for `check` pointing at the hostname Render/Railway gives you, in
whatever DNS panel you manage lightuptech.net's DNS from (this may be your
domain registrar, not WordPress -- worth checking which one actually holds
your DNS records while you're untangling what's charging you).

## 4. Before you make it public

- Change `app.secret_key` in `app.py` to a real random value.
- Keep the rate limit (`5 per hour` per visitor, in `app.py`) or lower it --
  it exists so the tool can't be turned into a free bulk-scanning service
  against domains people don't own.
- The `authorized` checkbox doesn't *prove* someone owns a domain -- nothing
  short of DNS/file verification does. For this passive, non-intrusive tool
  that's an acceptable, standard tradeoff (same as most "free header checker"
  tools online). It becomes a hard requirement, not just a checkbox, before
  you add anything more active -- see below.
- Anthropic API usage costs money per request; the rate limit also protects
  your API bill.

## 5. Growing this into more (later, not now)

This MVP intentionally only does passive checks -- nothing here touches a
company's actual systems beyond what a browser or DNS resolver already
would. If you later want the "full scanner" version (port checks, deeper
misconfiguration testing, etc.), that needs, before any code:

- Real domain-ownership verification (DNS TXT record or file upload proof --
  the same method Google Search Console or SSL cert issuers use).
- Terms of Service a visitor must accept, spelling out authorized use.
- Its own isolated scanning infrastructure, separate from this lead-magnet
  tool, so a misuse attempt can't be blamed on -- or break -- your main site.

That's a good "phase 2" project once this one is live and you've seen
whether people actually use it.
