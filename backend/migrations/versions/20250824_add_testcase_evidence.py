# backend/migrations/versions/20250824_add_testcase_evidence.py
"""add testcase and evidence tables

Revision ID: 20250824_add_testcase_evidence
Revises: 
Create Date: 2025-08-24 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic identifiers
# ---------------------------------------------------------------------------
revision = "20250824_add_testcase_evidence"
down_revision = None  # set to your previous revision id if you have one
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utc_now():
    # Use database-side current timestamp where possible
    return sa.text("CURRENT_TIMESTAMP")


# ---------------------------------------------------------------------------
# Upgrade / Downgrade
# ---------------------------------------------------------------------------
def upgrade() -> None:
    # --- test_cases ---------------------------------------------------------
    op.create_table(
        "test_cases",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer, sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("param", sa.String(length=128), nullable=False),
        sa.Column("family", sa.String(length=32), nullable=False, server_default=sa.text("'plan'")),
        sa.Column("payload_id", sa.String(length=64), nullable=False, server_default=sa.text("'n/a'")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'planned'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=_utc_now()),
        sa.UniqueConstraint("job_id", "endpoint_id", "param", "family", "payload_id", name="uq_test_case_job_ep_param_family_payload"),
    )

    # Add simple indexes that are commonly queried
    op.create_index("ix_test_cases_job", "test_cases", ["job_id"])
    op.create_index("ix_test_cases_endpoint", "test_cases", ["endpoint_id"])
    op.create_index("ix_test_cases_param", "test_cases", ["param"])

    # --- evidence -----------------------------------------------------------
    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("endpoint_id", sa.Integer, sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("test_case_id", sa.Integer, sa.ForeignKey("test_cases.id", ondelete="SET NULL"), nullable=True),

        sa.Column("method", sa.String(length=8), nullable=False, server_default=sa.text("'GET'")),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("param", sa.String(length=128), nullable=True),

        sa.Column("family", sa.String(length=32), nullable=False, server_default=sa.text("'unknown'")),
        sa.Column("label", sa.String(length=64), nullable=True),

        sa.Column("payload_id", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.Text, nullable=True),

        sa.Column("confidence", sa.Float, nullable=False, server_default=sa.text("0")),

        sa.Column("response_hash", sa.String(length=64), nullable=True),
        sa.Column("response_snippet", sa.Text, nullable=True),

        sa.Column("param_locs", sa.JSON, nullable=True),
        sa.Column("request_meta", sa.JSON, nullable=True),
        sa.Column("response_meta", sa.JSON, nullable=True),
        sa.Column("signals", sa.JSON, nullable=True),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=_utc_now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=_utc_now()),
    )

    # Useful indexes for report queries
    op.create_index("ix_evidence_job", "evidence", ["job_id"])
    op.create_index("ix_evidence_job_confidence", "evidence", ["job_id", "confidence"])
    op.create_index("ix_evidence_endpoint", "evidence", ["endpoint_id"])
    op.create_index("ix_evidence_test_case", "evidence", ["test_case_id"])
    op.create_index("ix_evidence_family", "evidence", ["family"])
    op.create_index("ix_evidence_label", "evidence", ["label"])


def downgrade() -> None:
    # Drop evidence first due to FK dependency
    try:
        op.drop_index("ix_evidence_label", table_name="evidence")
        op.drop_index("ix_evidence_family", table_name="evidence")
        op.drop_index("ix_evidence_test_case", table_name="evidence")
        op.drop_index("ix_evidence_endpoint", table_name="evidence")
        op.drop_index("ix_evidence_job_confidence", table_name="evidence")
        op.drop_index("ix_evidence_job", table_name="evidence")
    except Exception:
        pass
    op.drop_table("evidence")

    try:
        op.drop_index("ix_test_cases_param", table_name="test_cases")
        op.drop_index("ix_test_cases_endpoint", table_name="test_cases")
        op.drop_index("ix_test_cases_job", table_name="test_cases")
    except Exception:
        pass
    op.drop_table("test_cases")
