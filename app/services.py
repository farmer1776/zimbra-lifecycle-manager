"""Core lifecycle management services: sync, status transitions, purge."""

import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from app.models import Account, AuditLog, SyncLog, Domain
from app.zimbra_client import zimbra_client
from app.config import settings
from app import cache

logger = logging.getLogger(__name__)


async def sync_accounts(db: Session, domain: str = None) -> dict:
    """Sync accounts from Zimbra SOAP API into MySQL."""
    sync_log = SyncLog(
        sync_type="full" if not domain else f"domain:{domain}",
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(sync_log)
    db.commit()
    cache.set_sync_status({"status": "running", "started": str(datetime.utcnow())})

    added = 0
    updated = 0
    errors = 0
    processed = 0
    error_details = []

    try:
        offset = 0
        batch_size = 500
        seen_emails = set()

        while True:
            try:
                accounts, has_more = await zimbra_client.get_all_accounts(
                    domain=domain, offset=offset, limit=batch_size
                )
            except Exception as e:
                logger.error("Zimbra fetch error at offset %d: %s", offset, e)
                error_details.append(f"Fetch error at offset {offset}: {e}")
                errors += 1
                break

            if not accounts:
                break

            for acct_data in accounts:
                processed += 1
                email = acct_data["email"]
                seen_emails.add(email)

                try:
                    existing = (
                        db.query(Account).filter(Account.email == email).first()
                    )

                    last_login = None
                    if acct_data.get("last_login"):
                        try:
                            last_login = datetime.fromisoformat(
                                acct_data["last_login"]
                            )
                        except (ValueError, TypeError):
                            pass

                    if existing:
                        existing.zimbra_id = acct_data["zimbra_id"]
                        existing.display_name = acct_data.get("display_name", "")
                        existing.account_status = acct_data["account_status"]
                        existing.last_login = last_login
                        existing.forwarding_addresses = acct_data.get(
                            "forwarding_addresses", ""
                        )
                        existing.cos_name = acct_data.get("cos_name", "")
                        existing.quota = acct_data.get("quota", 0)
                        existing.domain = acct_data["domain"]
                        _update_inactivity(existing)
                        updated += 1
                    else:
                        new_acct = Account(
                            zimbra_id=acct_data["zimbra_id"],
                            email=email,
                            display_name=acct_data.get("display_name", ""),
                            domain=acct_data["domain"],
                            account_status=acct_data["account_status"],
                            last_login=last_login,
                            forwarding_addresses=acct_data.get(
                                "forwarding_addresses", ""
                            ),
                            cos_name=acct_data.get("cos_name", ""),
                            quota=acct_data.get("quota", 0),
                        )
                        _update_inactivity(new_acct)
                        db.add(new_acct)
                        added += 1

                    cache.cache_account(email, acct_data)

                except Exception as e:
                    logger.error("Error processing account %s: %s", email, e)
                    error_details.append(f"{email}: {e}")
                    errors += 1

            db.commit()

            if not has_more:
                break
            offset += batch_size

        # Update domain table
        _update_domain_counts(db)

        sync_log.status = "completed"
        sync_log.records_processed = processed
        sync_log.records_added = added
        sync_log.records_updated = updated
        sync_log.errors = errors
        sync_log.error_details = "\n".join(error_details) if error_details else None
        sync_log.completed_at = datetime.utcnow()
        db.commit()

        cache.invalidate_all()
        result = {
            "status": "completed",
            "processed": processed,
            "added": added,
            "updated": updated,
            "errors": errors,
        }
        cache.set_sync_status(result)
        return result

    except Exception as e:
        logger.error("Sync failed: %s", e)
        sync_log.status = "failed"
        sync_log.error_details = str(e)
        sync_log.completed_at = datetime.utcnow()
        db.commit()
        cache.set_sync_status({"status": "failed", "error": str(e)})
        raise


def _update_inactivity(account: Account):
    """Calculate inactivity and purge eligibility."""
    now = datetime.utcnow()
    threshold = now - timedelta(days=settings.PURGE_INACTIVITY_DAYS)

    if account.account_status == "closed":
        if account.inactive_since is None:
            account.inactive_since = now
        has_forwarding = bool(
            account.forwarding_addresses
            and account.forwarding_addresses.strip()
        )
        if has_forwarding:
            account.purge_eligible = False
        elif account.inactive_since and account.inactive_since <= threshold:
            account.purge_eligible = True
        else:
            account.purge_eligible = False
    else:
        if account.last_login and account.last_login > threshold:
            account.inactive_since = None
            account.purge_eligible = False
        elif account.account_status == "locked":
            if account.inactive_since is None:
                account.inactive_since = now


def _update_domain_counts(db: Session):
    """Refresh domain account counts."""
    results = (
        db.query(Account.domain, func.count(Account.id))
        .group_by(Account.domain)
        .all()
    )
    for domain_name, count in results:
        domain = (
            db.query(Domain).filter(Domain.domain_name == domain_name).first()
        )
        if domain:
            domain.account_count = count
            domain.last_synced = datetime.utcnow()
        else:
            db.add(
                Domain(
                    domain_name=domain_name,
                    account_count=count,
                    last_synced=datetime.utcnow(),
                )
            )
    db.commit()


async def change_account_status(
    db: Session, account_id: int, new_status: str, admin_user: str = "admin"
) -> Account:
    """Change account status with Zimbra sync and audit logging."""
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise ValueError("Account not found")

    old_status = account.account_status

    # Validate transition
    valid_transitions = {
        "active": ["locked", "closed", "maintenance"],
        "locked": ["active", "closed"],
        "closed": ["active", "locked"],
        "maintenance": ["active"],
    }
    allowed = valid_transitions.get(old_status, [])
    if new_status not in allowed:
        raise ValueError(
            f"Invalid status transition: {old_status} -> {new_status}. "
            f"Allowed: {allowed}"
        )

    # Push to Zimbra
    try:
        await zimbra_client.modify_account_status(account.zimbra_id, new_status)
    except Exception as e:
        logger.error("Zimbra status change failed for %s: %s", account.email, e)
        raise ValueError("Failed to update status in Zimbra — check server logs")

    # Update local DB
    account.account_status = new_status
    if new_status == "closed" and account.inactive_since is None:
        account.inactive_since = datetime.utcnow()
    elif new_status == "active":
        account.inactive_since = None
        account.purge_eligible = False

    _update_inactivity(account)

    # Audit log
    db.add(
        AuditLog(
            admin_user=admin_user,
            action="status_change",
            target_account=account.email,
            old_value=old_status,
            new_value=new_status,
        )
    )
    db.commit()
    cache.invalidate_all()
    return account


async def purge_account(
    db: Session, account_id: int, admin_user: str = "admin"
) -> dict:
    """Purge an account - with safety checks for forwarding addresses."""
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise ValueError("Account not found")

    # Safety: never purge accounts with forwarding addresses
    if account.forwarding_addresses and account.forwarding_addresses.strip():
        raise ValueError(
            f"Cannot purge {account.email}: account has forwarding address(es) "
            f"({account.forwarding_addresses}). Remove forwarding first."
        )

    # Must be in closed status
    if account.account_status != "closed":
        raise ValueError(
            f"Cannot purge {account.email}: account status is "
            f"'{account.account_status}', must be 'closed'."
        )

    # Check inactivity period
    if account.inactive_since:
        days_inactive = (datetime.utcnow() - account.inactive_since).days
        if days_inactive < settings.PURGE_INACTIVITY_DAYS:
            raise ValueError(
                f"Cannot purge {account.email}: only {days_inactive} days inactive, "
                f"requires {settings.PURGE_INACTIVITY_DAYS} days."
            )

    # Purge from Zimbra
    try:
        await zimbra_client.delete_account(account.zimbra_id)
    except Exception as e:
        logger.error("Zimbra purge failed for %s: %s", account.email, e)
        raise ValueError("Failed to purge account in Zimbra — check server logs")

    # Audit log
    db.add(
        AuditLog(
            admin_user=admin_user,
            action="purge",
            target_account=account.email,
            old_value=account.account_status,
            new_value="purged",
            details={
                "zimbra_id": account.zimbra_id,
                "inactive_since": str(account.inactive_since),
                "forwarding": account.forwarding_addresses or "",
            },
        )
    )

    email = account.email
    db.delete(account)
    db.commit()
    cache.invalidate_all()
    return {"email": email, "status": "purged"}


def get_dashboard_stats(db: Session) -> dict:
    """Get aggregated stats for the dashboard."""
    cached = cache.get_domain_stats()
    if cached:
        return cached

    total = db.query(func.count(Account.id)).scalar() or 0

    status_counts = dict(
        db.query(Account.account_status, func.count(Account.id))
        .group_by(Account.account_status)
        .all()
    )

    purge_eligible = (
        db.query(func.count(Account.id))
        .filter(Account.purge_eligible == True)
        .scalar()
        or 0
    )

    with_forwarding = (
        db.query(func.count(Account.id))
        .filter(
            Account.forwarding_addresses.isnot(None),
            Account.forwarding_addresses != "",
        )
        .scalar()
        or 0
    )

    domains = (
        db.query(Account.domain, func.count(Account.id))
        .group_by(Account.domain)
        .order_by(func.count(Account.id).desc())
        .all()
    )

    stats = {
        "total_accounts": total,
        "active": status_counts.get("active", 0),
        "locked": status_counts.get("locked", 0),
        "closed": status_counts.get("closed", 0),
        "maintenance": status_counts.get("maintenance", 0),
        "purge_eligible": purge_eligible,
        "with_forwarding": with_forwarding,
        "domains": [{"name": d, "count": c} for d, c in domains],
    }

    cache.cache_domain_stats(stats)
    return stats


def get_accounts(
    db: Session,
    domain: str = None,
    status: str = None,
    search: str = None,
    purge_eligible: bool = None,
    page: int = 1,
    per_page: int = 50,
    sort_by: str = "email",
    sort_dir: str = "asc",
) -> dict:
    """Query accounts with filtering, pagination, and sorting."""
    query = db.query(Account)

    if domain:
        query = query.filter(Account.domain == domain)
    if status:
        query = query.filter(Account.account_status == status)
    if search:
        query = query.filter(Account.email.ilike(f"%{search}%"))
    if purge_eligible is not None:
        query = query.filter(Account.purge_eligible == purge_eligible)

    total = query.count()

    allowed_sort = {"email", "domain", "account_status", "last_login", "inactive_since", "display_name"}
    if sort_by not in allowed_sort:
        sort_by = "email"
    sort_col = getattr(Account, sort_by)
    if sort_dir == "desc":
        sort_col = sort_col.desc()
    query = query.order_by(sort_col)

    offset = (page - 1) * per_page
    accounts = query.offset(offset).limit(per_page).all()

    return {
        "accounts": [_account_to_dict(a) for a in accounts],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


def get_audit_log(
    db: Session,
    target: str = None,
    action: str = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if target:
        query = query.filter(AuditLog.target_account.ilike(f"%{target}%"))
    if action:
        query = query.filter(AuditLog.action == action)

    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "logs": [
            {
                "id": l.id,
                "admin_user": l.admin_user,
                "action": l.action,
                "target_account": l.target_account,
                "old_value": l.old_value,
                "new_value": l.new_value,
                "details": l.details,
                "created_at": str(l.created_at) if l.created_at else None,
            }
            for l in logs
        ],
        "total": total,
        "page": page,
        "pages": (total + per_page - 1) // per_page,
    }


def _account_to_dict(a: Account) -> dict:
    return {
        "id": a.id,
        "zimbra_id": a.zimbra_id,
        "email": a.email,
        "display_name": a.display_name,
        "domain": a.domain,
        "account_status": a.account_status,
        "last_login": str(a.last_login) if a.last_login else None,
        "forwarding_addresses": a.forwarding_addresses or "",
        "cos_name": a.cos_name,
        "mailbox_size": a.mailbox_size,
        "quota": a.quota,
        "inactive_since": str(a.inactive_since) if a.inactive_since else None,
        "purge_eligible": a.purge_eligible,
        "created_at": str(a.created_at) if a.created_at else None,
        "updated_at": str(a.updated_at) if a.updated_at else None,
    }
