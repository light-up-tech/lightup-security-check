import datetime
import logging

from flask import Flask, render_template, request, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from checks import run_all_checks, normalize_domain
from ai_report import generate_report

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-value-in-production"

# --- Abuse guardrails -------------------------------------------------
# In-memory limiter is fine for a single small instance. If you outgrow one
# server, switch storage_uri to a Redis URL (see Flask-Limiter docs).
limiter = Limiter(get_remote_address, app=app, default_limits=[])

logging.basicConfig(level=logging.INFO)
consent_log = logging.getLogger("consent")


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
@limiter.limit("5 per hour")  # keep this modest -- it's a lead-magnet tool, not a scanning service
def scan():
    domain_input = request.form.get("domain", "").strip()
    authorized = request.form.get("authorized")

    if not domain_input:
        flash("Please enter a domain to check.")
        return redirect(url_for("index"))

    if not authorized:
        flash("Please confirm you own this domain or are authorized to test it before running a check.")
        return redirect(url_for("index"))

    domain = normalize_domain(domain_input)

    # Log consent for accountability -- who asked to scan what, and when.
    consent_log.info(
        "Authorized scan requested: domain=%s ip=%s time=%s",
        domain, get_remote_address(), datetime.datetime.utcnow().isoformat(),
    )

    findings = run_all_checks(domain)
    report = generate_report(domain, findings)

    return render_template("results.html", domain=domain, findings=findings, report=report)


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("index.html", rate_limited=True), 429


if __name__ == "__main__":
    app.run(debug=True, port=5000)
