"""
extensions.py — Netra Security
Holds shared Flask extensions to avoid circular imports.
Import `db` from here in both models.py and app.py.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
