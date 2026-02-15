-- Zimbra Mailbox Lifecycle Manager - MySQL Schema
-- Database: zimbra_mgmt

CREATE TABLE IF NOT EXISTS accounts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    zimbra_id VARCHAR(36) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    domain VARCHAR(255) NOT NULL,
    account_status VARCHAR(50) NOT NULL DEFAULT 'active',
    last_login DATETIME NULL,
    forwarding_addresses TEXT,
    cos_name VARCHAR(255),
    mailbox_size BIGINT DEFAULT 0,
    quota BIGINT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    inactive_since DATETIME NULL,
    purge_eligible TINYINT(1) DEFAULT 0,
    INDEX idx_domain (domain),
    INDEX idx_status (account_status),
    INDEX idx_last_login (last_login),
    INDEX idx_inactive (inactive_since),
    INDEX idx_purge (purge_eligible)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    admin_user VARCHAR(255) DEFAULT 'system',
    action VARCHAR(100) NOT NULL,
    target_account VARCHAR(255),
    old_value VARCHAR(255),
    new_value VARCHAR(255),
    details JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_action (action),
    INDEX idx_target (target_account),
    INDEX idx_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sync_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    records_processed INT DEFAULT 0,
    records_added INT DEFAULT 0,
    records_updated INT DEFAULT 0,
    errors INT DEFAULT 0,
    error_details TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    INDEX idx_sync_status (status),
    INDEX idx_sync_started (started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    account_count INT DEFAULT 0,
    last_synced DATETIME,
    INDEX idx_domain_name (domain_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'operator',
    is_active TINYINT(1) DEFAULT 1,
    token_version INT NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB;
