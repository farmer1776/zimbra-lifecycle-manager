"""Zimbra Admin SOAP API client for mailbox lifecycle management."""

from __future__ import annotations

import ssl
import logging
import aiohttp
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from app.config import settings

logger = logging.getLogger(__name__)

ZIMBRA_NS = "urn:zimbra"
ADMIN_NS = "urn:zimbraAdmin"


class ZimbraClient:
    """Async client for Zimbra Admin SOAP API."""

    def __init__(self):
        self.base_url = f"{settings.ZIMBRA_HOST}:{settings.ZIMBRA_ADMIN_PORT}"
        self.soap_url = f"{self.base_url}/service/admin/soap"
        self.auth_token = None
        self._session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    def _build_envelope(self, body_xml: str, auth: bool = True) -> str:
        auth_header = ""
        if auth and self.auth_token:
            auth_header = (
                f'<context xmlns="{ZIMBRA_NS}">'
                f"<authToken>{self.auth_token}</authToken>"
                f"</context>"
            )
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
            f"<soap:Header>{auth_header}</soap:Header>"
            f"<soap:Body>{body_xml}</soap:Body>"
            f"</soap:Envelope>"
        )

    async def _soap_request(self, body_xml: str, auth: bool = True) -> ET.Element:
        envelope = self._build_envelope(body_xml, auth)
        session = await self._get_session()
        async with session.post(
            self.soap_url,
            data=envelope,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout=aiohttp.ClientTimeout(total=120),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                logger.error("SOAP error %d: %s", resp.status, text[:500])
                raise Exception(f"Zimbra SOAP error: HTTP {resp.status}")
            root = ET.fromstring(text)
            fault = root.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
            if fault is not None:
                reason = fault.findtext(
                    ".//{http://www.w3.org/2003/05/soap-envelope}Text", "Unknown"
                )
                raise Exception(f"Zimbra SOAP fault: {reason}")
            return root

    async def authenticate(self) -> str:
        body = (
            f'<AuthRequest xmlns="{ADMIN_NS}">'
            f'<account by="name">{xml_escape(settings.ZIMBRA_ADMIN_USER)}</account>'
            f"<password>{xml_escape(settings.ZIMBRA_ADMIN_PASSWORD)}</password>"
            f"</AuthRequest>"
        )
        root = await self._soap_request(body, auth=False)
        token_el = root.find(f".//{{{ADMIN_NS}}}authToken")
        if token_el is None:
            raise Exception("Failed to get auth token from Zimbra")
        self.auth_token = token_el.text
        logger.info("Authenticated with Zimbra admin API")
        return self.auth_token

    async def _ensure_auth(self):
        if not self.auth_token:
            await self.authenticate()

    async def get_all_accounts(
        self, domain: str = None, offset: int = 0, limit: int = 1000
    ) -> tuple[list[dict], bool]:
        """Fetch accounts from Zimbra. Returns (accounts, has_more)."""
        await self._ensure_auth()

        query = ""
        if domain:
            query = f'<query>zimbraMailDeliveryAddress=*@{xml_escape(domain)}</query>'

        body = (
            f'<SearchDirectoryRequest xmlns="{ADMIN_NS}" '
            f'offset="{offset}" limit="{limit}" sortBy="name" '
            f'types="accounts" attrs="zimbraAccountStatus,zimbraLastLogonTimestamp,'
            f'zimbraMailForwardingAddress,zimbraPrefMailForwardingAddress,zimbraCOSId,zimbraMailQuota,'
            f'zimbraId,displayName,zimbraMailDeliveryAddress">'
            f"{query}"
            f"</SearchDirectoryRequest>"
        )
        root = await self._soap_request(body)
        resp = root.find(f".//{{{ADMIN_NS}}}SearchDirectoryResponse")
        if resp is None:
            return [], False

        more = resp.get("more", "0") == "1"
        accounts = []
        for acct in resp.findall(f"{{{ADMIN_NS}}}account"):
            account_data = self._parse_account(acct)
            if account_data:
                accounts.append(account_data)
        return accounts, more

    async def get_all_domains(self) -> list[dict]:
        """Fetch all domains from Zimbra."""
        await self._ensure_auth()
        body = (
            f'<GetAllDomainsRequest xmlns="{ADMIN_NS}" />'
        )
        root = await self._soap_request(body)
        domains = []
        for dom in root.findall(f".//{{{ADMIN_NS}}}domain"):
            name = dom.get("name")
            if name:
                domains.append({"name": name, "id": dom.get("id", "")})
        return domains

    def _parse_account(self, acct_element: ET.Element) -> dict | None:
        """Parse a Zimbra account XML element into a dict."""
        email = acct_element.get("name")
        if not email:
            return None

        attrs = {}
        for attr in acct_element.findall(f"{{{ADMIN_NS}}}a"):
            name = attr.get("n")
            if name:
                if name in attrs:
                    existing = attrs[name]
                    if isinstance(existing, list):
                        existing.append(attr.text or "")
                    else:
                        attrs[name] = [existing, attr.text or ""]
                else:
                    attrs[name] = attr.text or ""

        fwd_parts = []
        for fwd_attr in ("zimbraPrefMailForwardingAddress", "zimbraMailForwardingAddress"):
            val = attrs.get(fwd_attr, "")
            if val:
                if isinstance(val, list):
                    fwd_parts.extend(val)
                else:
                    fwd_parts.append(val)
        forwarding = ", ".join(dict.fromkeys(fwd_parts))  # deduplicate, preserve order

        last_login_raw = attrs.get("zimbraLastLogonTimestamp", "")
        last_login = None
        if last_login_raw and last_login_raw != "0":
            try:
                last_login = last_login_raw[:4] + "-" + last_login_raw[4:6] + "-" + \
                    last_login_raw[6:8] + "T" + last_login_raw[8:10] + ":" + \
                    last_login_raw[10:12] + ":" + last_login_raw[12:14]
            except (IndexError, ValueError):
                last_login = None

        return {
            "zimbra_id": attrs.get("zimbraId", acct_element.get("id", "")),
            "email": email,
            "display_name": attrs.get("displayName", ""),
            "domain": email.split("@")[1] if "@" in email else "",
            "account_status": attrs.get("zimbraAccountStatus", "active"),
            "last_login": last_login,
            "forwarding_addresses": forwarding,
            "cos_name": attrs.get("zimbraCOSId", ""),
            "quota": int(attrs.get("zimbraMailQuota", "0") or "0"),
        }

    async def modify_account_status(
        self, zimbra_id: str, new_status: str
    ) -> bool:
        """Change account status in Zimbra (active, locked, closed, maintenance)."""
        await self._ensure_auth()
        body = (
            f'<ModifyAccountRequest xmlns="{ADMIN_NS}">'
            f'<id>{xml_escape(zimbra_id)}</id>'
            f'<a n="zimbraAccountStatus">{xml_escape(new_status)}</a>'
            f"</ModifyAccountRequest>"
        )
        await self._soap_request(body)
        logger.info("Changed account %s status to %s", zimbra_id, new_status)
        return True

    async def delete_account(self, zimbra_id: str) -> bool:
        """Permanently delete/purge an account from Zimbra."""
        await self._ensure_auth()
        body = (
            f'<DeleteAccountRequest xmlns="{ADMIN_NS}">'
            f"<id>{xml_escape(zimbra_id)}</id>"
            f"</DeleteAccountRequest>"
        )
        await self._soap_request(body)
        logger.info("Purged account %s", zimbra_id)
        return True

    async def get_account_info(self, email: str) -> dict | None:
        """Get detailed info for a single account."""
        await self._ensure_auth()
        body = (
            f'<GetAccountRequest xmlns="{ADMIN_NS}">'
            f'<account by="name">{xml_escape(email)}</account>'
            f"</GetAccountRequest>"
        )
        root = await self._soap_request(body)
        acct = root.find(f".//{{{ADMIN_NS}}}account")
        if acct is None:
            return None
        return self._parse_account(acct)

    async def get_mailbox_size(self, zimbra_id: str) -> int:
        """Get mailbox size in bytes."""
        await self._ensure_auth()
        body = (
            f'<GetMailboxRequest xmlns="{ADMIN_NS}">'
            f'<mbox id="{xml_escape(zimbra_id)}" />'
            f"</GetMailboxRequest>"
        )
        try:
            root = await self._soap_request(body)
            mbox = root.find(f".//{{{ADMIN_NS}}}mbox")
            if mbox is not None:
                return int(mbox.get("s", "0"))
        except Exception:
            pass
        return 0

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


zimbra_client = ZimbraClient()
