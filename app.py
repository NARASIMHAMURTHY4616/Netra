"""
app.py — Netra Security
Flask application factory, routes, and scan orchestration.
"""

import os
import csv
import json
from io import StringIO

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash,
    jsonify, Response
)
from werkzeug.utils import secure_filename

from extensions import db
from models import Scan, Finding

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR       = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER  = os.path.join(BASE_DIR, "uploads")
DATABASE_DIR   = os.path.join(BASE_DIR, "database")
ALLOWED_EXTS   = {"py"}

os.makedirs(UPLOAD_FOLDER, default_mode := 0o755, exist_ok=True) if False else None
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(DATABASE_DIR,   exist_ok=True)


# ---------------------------------------------------------------------------
# App Factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"]            = "netra-dev-secret-change-in-prod"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(DATABASE_DIR, 'netra.db')}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"]         = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"]    = 5 * 1024 * 1024  # 5 MB upload limit

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Register routes
    register_routes(app)

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def allowed_file(filename: str) -> bool:
    """Only allow .py files."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS


def run_scan(filepath: str) -> list[dict]:
    """
    Call the existing scan_engine and return findings as a list of dicts.
    Expects each dict to have:
        rule_id, title, severity, line_number,
        vulnerable_code, description, recommendation
    """
    try:
        from scan_engine import scan_file
        return scan_file(filepath) or []
    except ImportError:
        # scan_engine.py not found — return empty so app still runs
        return []
    except Exception as e:
        print(f"[Netra] Scanner error: {e}")
        return []


def count_severities(findings: list[dict]) -> dict:
    """Count findings by severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        level = f.get("severity", "").lower()
        if level in counts:
            counts[level] += 1
    return counts


def severity_order(severity: str) -> int:
    """Return sort weight for severity (lower = more severe)."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
        severity.upper(), 4
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_routes(app: Flask):

    # ------------------------------------------------------------------ #
    #  Dashboard                                                           #
    # ------------------------------------------------------------------ #
    @app.route("/")
    def dashboard():
        scans = Scan.query.order_by(Scan.scanned_at.desc()).all()

        # Aggregate totals across all scans for the stats cards
        totals = {
            "total":    sum(s.total    for s in scans),
            "critical": sum(s.critical for s in scans),
            "high":     sum(s.high     for s in scans),
            "medium":   sum(s.medium   for s in scans),
            "low":      sum(s.low      for s in scans),
        }

        return render_template("dashboard.html", scans=scans, totals=totals)


    # ------------------------------------------------------------------ #
    #  Upload & Scan                                                       #
    # ------------------------------------------------------------------ #
    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "GET":
            return render_template("upload.html")

        # ---- POST: handle file upload ----
        if "file" not in request.files:
            flash("No file part in the request.", "error")
            return redirect(url_for("upload"))

        file = request.files["file"]

        if file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("Only .py files are supported.", "error")
            return redirect(url_for("upload"))

        # Save file securely
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Run scanner
        raw_findings = run_scan(filepath)

        # Sort by severity before storing
        raw_findings.sort(key=lambda f: severity_order(f.get("severity", "LOW")))

        # Persist Scan record
        counts = count_severities(raw_findings)
        scan = Scan(
            filename  = filename,
            filepath  = filepath,
            status    = "completed",
            total     = len(raw_findings),
            critical  = counts["critical"],
            high      = counts["high"],
            medium    = counts["medium"],
            low       = counts["low"],
        )
        db.session.add(scan)
        db.session.flush()  # get scan.id before adding findings

        # Persist Finding records
        for raw in raw_findings:
            finding = Finding(
                scan_id         = scan.id,
                rule_id         = raw.get("rule_id",         "N/A"),
                title           = raw.get("title",           "Unknown"),
                severity        = raw.get("severity",        "LOW").upper(),
                line_number     = raw.get("line_number"),
                vulnerable_code = raw.get("vulnerable_code", ""),
                description     = raw.get("description",     ""),
                recommendation  = raw.get("recommendation",  ""),
            )
            db.session.add(finding)

        db.session.commit()

        flash(f"Scan complete — {len(raw_findings)} finding(s) detected.", "success")
        return redirect(url_for("findings", scan_id=scan.id))


    # ------------------------------------------------------------------ #
    #  Findings                                                            #
    # ------------------------------------------------------------------ #
    @app.route("/findings/<int:scan_id>")
    def findings(scan_id):
        scan = Scan.query.get_or_404(scan_id)

        # Already sorted by severity in upload route, but re-sort from DB
        all_findings = sorted(
            scan.findings,
            key=lambda f: severity_order(f.severity)
        )

        # Optional severity filter via query param  ?severity=HIGH
        filter_sev = request.args.get("severity", "").upper()
        if filter_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            all_findings = [f for f in all_findings if f.severity == filter_sev]

        return render_template(
            "findings.html",
            scan      = scan,
            findings  = all_findings,
            filter_sev= filter_sev,
        )


    # ------------------------------------------------------------------ #
    #  Delete Scan                                                         #
    # ------------------------------------------------------------------ #
    @app.route("/scan/<int:scan_id>/delete", methods=["POST"])
    def delete_scan(scan_id):
        scan = Scan.query.get_or_404(scan_id)

        # Remove uploaded file from disk
        if os.path.exists(scan.filepath):
            os.remove(scan.filepath)

        db.session.delete(scan)
        db.session.commit()

        flash(f"Scan '{scan.filename}' deleted.", "info")
        return redirect(url_for("dashboard"))


    # ------------------------------------------------------------------ #
    #  Export — JSON                                                       #
    # ------------------------------------------------------------------ #
    @app.route("/findings/<int:scan_id>/export/json")
    def export_json(scan_id):
        scan = Scan.query.get_or_404(scan_id)

        payload = {
            "scan":     scan.to_dict(),
            "findings": [f.to_dict() for f in scan.findings],
        }

        return Response(
            json.dumps(payload, indent=2),
            mimetype    = "application/json",
            headers     = {"Content-Disposition": f"attachment; filename=netra_scan_{scan_id}.json"},
        )


    # ------------------------------------------------------------------ #
    #  Export — CSV                                                        #
    # ------------------------------------------------------------------ #
    @app.route("/findings/<int:scan_id>/export/csv")
    def export_csv(scan_id):
        scan = Scan.query.get_or_404(scan_id)

        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "id", "rule_id", "title", "severity",
            "line_number", "vulnerable_code", "description", "recommendation"
        ])
        writer.writeheader()
        for f in scan.findings:
            writer.writerow({
                "id":               f.id,
                "rule_id":          f.rule_id,
                "title":            f.title,
                "severity":         f.severity,
                "line_number":      f.line_number,
                "vulnerable_code":  f.vulnerable_code,
                "description":      f.description,
                "recommendation":   f.recommendation,
            })

        return Response(
            output.getvalue(),
            mimetype    = "text/csv",
            headers     = {"Content-Disposition": f"attachment; filename=netra_scan_{scan_id}.csv"},
        )


    # ------------------------------------------------------------------ #
    #  Error Handlers                                                      #
    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    @app.errorhandler(413)
    def file_too_large(e):
        flash("File too large. Maximum size is 5 MB.", "error")
        return redirect(url_for("upload"))


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
