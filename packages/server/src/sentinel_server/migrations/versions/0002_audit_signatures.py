"""audit signatures

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22 13:30:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
import sentinel_server.models


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_signatures',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('entry_hash', sa.String(length=64), nullable=False),
    sa.Column('key_id', sa.String(length=32), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=False),
    sa.Column('signed_at', sentinel_server.models.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('seq')
    )


def downgrade() -> None:
    op.drop_table('audit_signatures')
