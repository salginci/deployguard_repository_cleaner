"""Initial database schema

Revision ID: 001_initial
Revises: 
Create Date: 2026-02-10

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create jobs table
    op.create_table(
        'jobs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(255), nullable=False, index=True),
        
        # Source repository info
        sa.Column('source_platform', sa.String(50), nullable=False),
        sa.Column('source_url', sa.String(500), nullable=False),
        sa.Column('source_branch', sa.String(255), default='main'),
        sa.Column('source_credentials_id', sa.String(255)),
        
        # Target repository info
        sa.Column('target_platform', sa.String(50)),
        sa.Column('target_url', sa.String(500)),
        sa.Column('target_branch', sa.String(255)),
        sa.Column('target_credentials_id', sa.String(255)),
        
        # Job status
        sa.Column('status', sa.String(50), default='pending', index=True),
        sa.Column('status_message', sa.Text),
        sa.Column('progress_percent', sa.Integer, default=0),
        
        # Storage references
        sa.Column('storage_repo_path', sa.String(500)),
        sa.Column('storage_report_path', sa.String(500)),
        sa.Column('storage_cleaned_path', sa.String(500)),
        
        # Statistics
        sa.Column('total_commits', sa.Integer),
        sa.Column('total_branches', sa.Integer),
        sa.Column('total_secrets_found', sa.Integer, default=0),
        sa.Column('secrets_selected_for_cleaning', sa.Integer, default=0),
        
        # Timestamps
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
        sa.Column('started_at', sa.DateTime),
        sa.Column('scan_completed_at', sa.DateTime),
        sa.Column('clean_completed_at', sa.DateTime),
        sa.Column('completed_at', sa.DateTime),
        sa.Column('expires_at', sa.DateTime),
    )
    
    # Create secrets_found table
    op.create_table(
        'secrets_found',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('job_id', sa.String(36), sa.ForeignKey('jobs.id'), nullable=False, index=True),
        
        # Secret details
        sa.Column('secret_type', sa.String(50), default='other'),
        sa.Column('secret_name', sa.String(255)),
        sa.Column('secret_value_preview', sa.String(50)),
        sa.Column('secret_value_hash', sa.String(64)),
        
        # Location info
        sa.Column('file_path', sa.String(500)),
        sa.Column('line_number', sa.Integer),
        sa.Column('commit_hash', sa.String(40)),
        sa.Column('commit_date', sa.DateTime),
        sa.Column('author', sa.String(255)),
        
        # Detection info
        sa.Column('pattern_matched', sa.String(255)),
        sa.Column('confidence', sa.Integer, default=100),
        sa.Column('is_false_positive', sa.Boolean, default=False),
        sa.Column('false_positive_reason', sa.String(255)),
        
        # User selection
        sa.Column('selected_for_cleaning', sa.Boolean, default=True),
        
        # Occurrence count
        sa.Column('occurrence_count', sa.Integer, default=1),
        
        # Context
        sa.Column('context_before', sa.Text),
        sa.Column('context_after', sa.Text),
    )
    
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('job_id', sa.String(36), sa.ForeignKey('jobs.id'), index=True),
        sa.Column('user_id', sa.String(255), index=True),
        
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('details', sa.JSON),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.String(500)),
        sa.Column('created_at', sa.DateTime, default=sa.func.now()),
    )
    
    # Create indexes for performance
    op.create_index('ix_jobs_status_created', 'jobs', ['status', 'created_at'])
    op.create_index('ix_secrets_job_type', 'secrets_found', ['job_id', 'secret_type'])
    op.create_index('ix_audit_action_time', 'audit_logs', ['action', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_audit_action_time')
    op.drop_index('ix_secrets_job_type')
    op.drop_index('ix_jobs_status_created')
    
    op.drop_table('audit_logs')
    op.drop_table('secrets_found')
    op.drop_table('jobs')
