"""
models.py — Netra Security
Database schema for Scan and Finding records.
Uses Flask-SQLAlchemy with SQLite.
"""

from datetime import datetime
from extensions import db


# ---------------------------------------------------------------------------
# Scan Model
# Represents one uploaded file scan session.
# ---------------------------------------------------------------------------

class Scan(db.Model):
    __tablename__ = "scans"

    id            = db.Column(db.Integer, primary_key=True)
    filename      = db.Column(db.String(255), nullable=False)       # Original uploaded filename
    filepath      = db.Column(db.String(512), nullable=False)       # Path on disk
    scanned_at    = db.Column(db.DateTime, default=datetime.utcnow) # Timestamp
    status        = db.Column(db.String(50), default="completed")   # completed | failed

    # Severity counts — pre-computed for fast dashboard queries
    total         = db.Column(db.Integer, default=0)
    critical      = db.Column(db.Integer, default=0)
    high          = db.Column(db.Integer, default=0)
    medium        = db.Column(db.Integer, default=0)
    low           = db.Column(db.Integer, default=0)

    # One scan → many findings
    findings      = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan id={self.id} file={self.filename} total={self.total}>"

    def to_dict(self):
        """Serialize scan metadata to a plain dict (used for JSON export)."""
        return {
            "id":         self.id,
            "filename":   self.filename,
            "scanned_at": self.scanned_at.strftime("%Y-%m-%d %H:%M:%S"),
            "status":     self.status,
            "total":      self.total,
            "critical":   self.critical,
            "high":       self.high,
            "medium":     self.medium,
            "low":        self.low,
        }


# ---------------------------------------------------------------------------
# Finding Model
# Represents a single vulnerability detected during a scan.
# ---------------------------------------------------------------------------

class Finding(db.Model):
    __tablename__ = "findings"

    id               = db.Column(db.Integer, primary_key=True)
    scan_id          = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    rule_id          = db.Column(db.String(50),  nullable=False)   # e.g. S001
    title            = db.Column(db.String(255), nullable=False)   # e.g. SQL Injection
    severity         = db.Column(db.String(20),  nullable=False)   # CRITICAL | HIGH | MEDIUM | LOW
    line_number      = db.Column(db.Integer,     nullable=True)    # Line in source file
    vulnerable_code  = db.Column(db.Text,        nullable=True)    # Snippet of bad code
    description      = db.Column(db.Text,        nullable=True)    # What the issue is
    recommendation   = db.Column(db.Text,        nullable=True)    # How to fix it

    def __repr__(self):
        return f"<Finding rule={self.rule_id} severity={self.severity} line={self.line_number}>"

    def to_dict(self):
        """Serialize finding to a plain dict (used for JSON/CSV export)."""
        return {
            "id":               self.id,
            "scan_id":          self.scan_id,
            "rule_id":          self.rule_id,
            "title":            self.title,
            "severity":         self.severity,
            "line_number":      self.line_number,
            "vulnerable_code":  self.vulnerable_code,
            "description":      self.description,
            "recommendation":   self.recommendation,
        }
