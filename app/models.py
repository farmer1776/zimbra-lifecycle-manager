from sqlalchemy import Column, BigInteger, Integer, String, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from app.database import Base


class Account(Base):
    __tablename__ = "accounts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    zimbra_id = Column(String(36), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    display_name = Column(String(255))
    domain = Column(String(255), nullable=False, index=True)
    account_status = Column(String(50), nullable=False, default="active")
    last_login = Column(DateTime, nullable=True)
    forwarding_addresses = Column(Text, nullable=True)
    cos_name = Column(String(255))
    mailbox_size = Column(BigInteger, default=0)
    quota = Column(BigInteger, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    inactive_since = Column(DateTime, nullable=True)
    purge_eligible = Column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    admin_user = Column(String(255), default="system")
    action = Column(String(100), nullable=False)
    target_account = Column(String(255))
    old_value = Column(String(255))
    new_value = Column(String(255))
    details = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())


class SyncLog(Base):
    __tablename__ = "sync_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sync_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    records_processed = Column(Integer, default=0)
    records_added = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    errors = Column(Integer, default=0)
    error_details = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_name = Column(String(255), unique=True, nullable=False)
    account_count = Column(Integer, default=0)
    last_synced = Column(DateTime)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    display_name = Column(String(255))
    role = Column(String(20), nullable=False, default="operator")
    is_active = Column(Boolean, default=True)
    token_version = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
