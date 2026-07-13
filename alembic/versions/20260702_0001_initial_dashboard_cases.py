"""Initial dashboard and case management tables."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260702_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create dashboard and case management tables."""
    op.create_table(
        "dashboard_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_dashboard_snapshots_singleton"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_dashboard_snapshots_generated_at", "dashboard_snapshots", ["generated_at"])
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=180), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("lead_investigator", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_number", name="uq_cases_case_number"),
    )
    op.create_index("idx_cases_created_at", "cases", ["created_at"])
    op.create_index("idx_cases_status_priority", "cases", ["status", "priority"])


def downgrade() -> None:
    """Drop case management and dashboard tables."""
    op.drop_index("idx_cases_status_priority", table_name="cases")
    op.drop_index("idx_cases_created_at", table_name="cases")
    op.drop_table("cases")
    op.drop_index("idx_dashboard_snapshots_generated_at", table_name="dashboard_snapshots")
    op.drop_table("dashboard_snapshots")
