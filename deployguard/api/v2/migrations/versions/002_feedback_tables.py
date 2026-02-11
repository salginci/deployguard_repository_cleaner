"""Add feedback tables for ML training

Revision ID: 002_feedback_tables
Revises: 001_initial
Create Date: 2026-02-10

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_feedback_tables'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create feedback_submissions table
    op.create_table(
        'feedback_submissions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('client_id', sa.String(64), index=True),
        sa.Column('client_ip_hash', sa.String(16)),
        sa.Column('version', sa.String(20)),
        
        # Summary stats
        sa.Column('total_detected', sa.Integer, default=0),
        sa.Column('confirmed_secrets', sa.Integer, default=0),
        sa.Column('false_positives', sa.Integer, default=0),
        sa.Column('false_positive_rate', sa.Float, default=0),
        
        # Timestamps
        sa.Column('submitted_at', sa.DateTime),
        sa.Column('received_at', sa.DateTime, default=sa.func.now()),
    )
    
    # Create feedback_items table (individual secret classifications)
    op.create_table(
        'feedback_items',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('submission_id', sa.String(36), sa.ForeignKey('feedback_submissions.id'), index=True),
        
        # Secret metadata (anonymized)
        sa.Column('value_hash', sa.String(64), index=True),
        sa.Column('secret_type', sa.String(50)),
        sa.Column('severity', sa.String(20)),
        sa.Column('value_length', sa.Integer),
        sa.Column('value_pattern', sa.String(255), index=True),
        sa.Column('file_extension', sa.String(20)),
        sa.Column('file_type', sa.String(50)),
        
        # Classification
        sa.Column('is_true_positive', sa.Boolean, nullable=False),  # True = real secret, False = false positive
    )
    
    # Create known_false_positive_patterns table
    op.create_table(
        'known_false_positive_patterns',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('pattern', sa.String(255), unique=True, index=True),
        sa.Column('confidence', sa.Float, default=0),
        sa.Column('sample_count', sa.Integer, default=0),
        sa.Column('true_positive_count', sa.Integer, default=0),
        sa.Column('false_positive_count', sa.Integer, default=0),
        sa.Column('reason', sa.String(500)),
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Create aggregated_stats table
    op.create_table(
        'aggregated_stats',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('stat_key', sa.String(100), unique=True, index=True),
        sa.Column('stat_value', sa.JSON),
        sa.Column('updated_at', sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Insert initial aggregated stats
    op.execute("""
        INSERT INTO aggregated_stats (stat_key, stat_value) VALUES 
        ('overall_stats', '{"total_submissions": 0, "total_confirmed": 0, "total_false_positives": 0}'),
        ('pattern_stats', '{"true_positives": {}, "false_positives": {}}'),
        ('file_type_stats', '{"true_positives": {}, "false_positives": {}}')
    """)
    
    # Create indexes
    op.create_index('ix_feedback_items_pattern_tp', 'feedback_items', ['value_pattern', 'is_true_positive'])


def downgrade() -> None:
    op.drop_index('ix_feedback_items_pattern_tp')
    
    op.drop_table('aggregated_stats')
    op.drop_table('known_false_positive_patterns')
    op.drop_table('feedback_items')
    op.drop_table('feedback_submissions')
