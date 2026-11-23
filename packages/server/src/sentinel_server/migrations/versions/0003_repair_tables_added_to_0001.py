"""repair tables missing from databases created before they were added to 0001

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-22 19:50:00.000000

Revision 0001 was edited in place after its first release: the advisories and field-data tables were added on
2026-10-27 and behavior_detections on 2026-10-28. A database created before those edits is already stamped
0001, so Alembic never created them, and the Advisories, Field Data and Behavior pages fail with "no such
table". This revision creates whichever of those tables is missing and does nothing on a database that has
them. The definitions are copies of the ones in 0001.

The lesson is recorded in docs/dev-conventions.md: a released migration is never edited; add a new revision.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
import sentinel_server.models


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if 'advisories' not in existing:
        op.create_table('advisories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('external_id', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('url', sa.String(length=1024), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('author', sa.String(length=128), nullable=True),
        sa.Column('score', sa.Integer(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('cve_ids', sa.JSON(), nullable=False),
        sa.Column('matched', sa.Boolean(), nullable=False),
        sa.Column('match_detail', sa.JSON(), nullable=False),
        sa.Column('severity_hint', sa.String(length=16), nullable=False),
        sa.Column('suggested_coverage', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('published_at', sentinel_server.models.UTCDateTime(), nullable=True),
        sa.Column('fetched_at', sentinel_server.models.UTCDateTime(), nullable=False),
        sa.Column('read_at', sentinel_server.models.UTCDateTime(), nullable=True),
        sa.Column('notified', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source', 'external_id')
        )
        with op.batch_alter_table('advisories', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_advisories_matched'), ['matched'], unique=False)
            batch_op.create_index(batch_op.f('ix_advisories_published_at'), ['published_at'], unique=False)
            batch_op.create_index(batch_op.f('ix_advisories_source'), ['source'], unique=False)
            batch_op.create_index(batch_op.f('ix_advisories_status'), ['status'], unique=False)

    if 'field_captures' not in existing:
        op.create_table('field_captures',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('source_label', sa.String(length=128), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), nullable=True),
        sa.Column('uploaded_at', sentinel_server.models.UTCDateTime(), nullable=False),
        sa.Column('original_format', sa.String(length=32), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('field_captures', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_field_captures_kind'), ['kind'], unique=False)
            batch_op.create_index(batch_op.f('ix_field_captures_uploaded_at'), ['uploaded_at'], unique=False)

    if 'field_observations' not in existing:
        op.create_table('field_observations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('capture_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('key', sa.String(length=256), nullable=False),
        sa.Column('label', sa.String(length=256), nullable=False),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('classification', sa.String(length=24), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['capture_id'], ['field_captures.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('field_observations', schema=None) as batch_op:
            batch_op.create_index('ix_field_obs_capture', ['capture_id', 'kind'], unique=False)
            batch_op.create_index(batch_op.f('ix_field_observations_capture_id'), ['capture_id'], unique=False)

    if 'behavior_detections' not in existing:
        op.create_table('behavior_detections',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=True),
        sa.Column('rule_id', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('summary', sa.String(length=1000), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('confidence', sa.String(length=16), nullable=False),
        sa.Column('technique_ids', sa.JSON(), nullable=False),
        sa.Column('technique_names', sa.JSON(), nullable=False),
        sa.Column('host', sa.String(length=256), nullable=False),
        sa.Column('dedup_key', sa.String(length=512), nullable=False),
        sa.Column('process_guids', sa.JSON(), nullable=False),
        sa.Column('events', sa.JSON(), nullable=False),
        sa.Column('process_tree', sa.JSON(), nullable=False),
        sa.Column('first_ts', sentinel_server.models.UTCDateTime(), nullable=False),
        sa.Column('last_ts', sentinel_server.models.UTCDateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('created_at', sentinel_server.models.UTCDateTime(), nullable=False),
        sa.Column('notified', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id', 'dedup_key')
        )
        with op.batch_alter_table('behavior_detections', schema=None) as batch_op:
            batch_op.create_index('ix_behavior_det_device_status', ['device_id', 'status'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_created_at'), ['created_at'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_dedup_key'), ['dedup_key'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_device_id'), ['device_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_host'), ['host'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_last_ts'), ['last_ts'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_rule_id'), ['rule_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_severity'), ['severity'], unique=False)
            batch_op.create_index(batch_op.f('ix_behavior_detections_status'), ['status'], unique=False)

def downgrade() -> None:
    pass  # these tables belong to 0001; removing them here would break a database that had them all along
