# Zimbra Mailbox Lifecycle Management Engine

Web-based application for managing Zimbra mailbox accounts at scale using the Zimbra Admin SOAP API. Built for environments with ~25,000+ mailboxes.

## Features

- **Account Sync** — Pull accounts from Zimbra via SOAP API in batches, with domain filtering
- **Status Management** — Transition accounts between active, locked, closed, and maintenance states with two-way Zimbra sync
- **Purge Queue** — Automatically identifies accounts eligible for purge (closed >60 days, no forwarding). Accounts with forwarding addresses are protected and cannot be purged
- **CSV Bulk Import** — Upload a CSV to perform batch status changes across hundreds of accounts
- **CSV Export** — Export filtered account lists for review (e.g., all locked accounts for marketing)
- **Audit Log** — Every status change and purge is logged with timestamp, admin user, and before/after values
- **Authentication** — JWT-based auth with role-based access control (admin and operator roles)
- **User Management** — Admins can create, disable, and manage application users
- **Redis Caching** — Dashboard stats and account lookups cached for fast response times
- **Dark Theme UI** — Lightweight, production-ready interface using Alpine.js (no build step)

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.9 / FastAPI |
| Database | MariaDB 10.5 (MySQL-compatible) |
| Cache | Redis |
| Web Server | nginx (reverse proxy + static files + TLS) |
| Frontend | Vanilla HTML/CSS/JS + Alpine.js |
| OS | Rocky Linux 9 |

## Project Structure

```
/opt/zimbra_mgmt/
├── .env                    # Configuration (not in repo)
├── run.py                  # Application entry point
├── schema.sql              # MySQL schema reference
├── app/
│   ├── auth.py             # JWT authentication & user seeding
│   ├── cache.py            # Redis caching layer
│   ├── config.py           # Settings from environment
│   ├── database.py         # SQLAlchemy engine & session
│   ├── main.py             # FastAPI routes & API endpoints
│   ├── models.py           # ORM models
│   ├── services.py         # Core lifecycle logic (sync, status, purge)
│   └── zimbra_client.py    # Zimbra Admin SOAP API client
└── static/
    ├── index.html           # Main application SPA
    ├── login.html           # Login page
    ├── css/style.css        # Dark theme stylesheet
    └── js/app.js            # Frontend application logic
```

## Installation

### Prerequisites

- Rocky Linux 9 (or RHEL 9 compatible)
- MariaDB / MySQL
- Redis
- nginx
- Python 3.9+

### 1. Install system packages

```bash
dnf install -y mariadb-server nginx
systemctl enable --now mariadb redis
```

### 2. Create the database

```bash
mysql -u root < /opt/zimbra_mgmt/schema.sql
mysql -u root -e "
  CREATE DATABASE IF NOT EXISTS zimbra_mgmt CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE USER IF NOT EXISTS 'zimbra_mgmt'@'localhost' IDENTIFIED BY 'YOUR_DB_PASSWORD';
  GRANT ALL PRIVILEGES ON zimbra_mgmt.* TO 'zimbra_mgmt'@'localhost';
  FLUSH PRIVILEGES;
  USE zimbra_mgmt;
  SOURCE /opt/zimbra_mgmt/schema.sql;
"
```

### 3. Install Python dependencies

```bash
pip3 install fastapi uvicorn[standard] sqlalchemy pymysql redis aiohttp python-dotenv pyjwt bcrypt python-multipart
```

### 4. Configure the application

Copy and edit the environment file:

```bash
cp .env.example .env   # or create from scratch
```

Required `.env` values:

```ini
# Zimbra SOAP API
ZIMBRA_HOST=https://your-zimbra-server.com
ZIMBRA_ADMIN_USER=admin@yourdomain.com
ZIMBRA_ADMIN_PASSWORD=your-admin-password
ZIMBRA_ADMIN_PORT=7071

# MySQL
DB_HOST=localhost
DB_PORT=3306
DB_NAME=zimbra_mgmt
DB_USER=zimbra_mgmt
DB_PASSWORD=your-db-password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Security (required — app will not start without these)
JWT_SECRET=your-random-secret-key
SEED_ADMIN_PASSWORD=your-admin-password
SEED_OPERATOR_PASSWORD=your-operator-password

# Application
APP_HOST=127.0.0.1
APP_PORT=8000
PURGE_INACTIVITY_DAYS=60
```

### 5. Set up the systemd service

```bash
cp zimbra-mgmt.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zimbra-mgmt
```

### 6. Configure nginx

Place the nginx config in `/etc/nginx/conf.d/zimbra-mgmt.conf` with reverse proxy to `127.0.0.1:8000` and static file serving from `/opt/zimbra_mgmt/static/`.

For TLS, generate a self-signed certificate or use Let's Encrypt:

```bash
# Self-signed
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/zimbra-mgmt.key \
  -out /etc/nginx/ssl/zimbra-mgmt.crt \
  -subj "/CN=zimbra-mgmt"

systemctl enable --now nginx
```

## Default Accounts

On first startup, the application seeds two users:

| Username | Role | Description |
|----------|------|-------------|
| `admin` | admin | Full access including user management |
| `derek` | operator | All features except user management |

Passwords are configured via `SEED_ADMIN_PASSWORD` and `SEED_OPERATOR_PASSWORD` in `.env`. Seed users are only created if they don't already exist.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate and receive JWT |
| GET | `/api/auth/me` | Current user info |
| GET | `/api/dashboard` | Aggregated account statistics |
| GET | `/api/accounts` | List/filter/search accounts (paginated) |
| GET | `/api/accounts/export` | Export filtered accounts as CSV |
| POST | `/api/accounts/{id}/status` | Change account status |
| POST | `/api/accounts/{id}/purge` | Purge a closed account |
| POST | `/api/accounts/bulk-csv` | Bulk status change via CSV upload |
| POST | `/api/sync` | Trigger account sync from Zimbra |
| GET | `/api/domains` | List synced domains |
| GET | `/api/audit` | Audit log (paginated) |
| GET/POST/PUT/DELETE | `/api/users` | User management (admin only) |
| GET | `/api/health` | Health check |

## Purge Safety Rules

An account can only be purged when **all** of the following are true:

1. Account status is **closed**
2. Account has been inactive for **60+ days** (configurable via `PURGE_INACTIVITY_DAYS`)
3. Account has **no forwarding addresses** set

Accounts with forwarding addresses are marked as protected and the purge button is disabled in the UI.

## CSV Bulk Import Format

```csv
email,new_status
user1@example.com,closed
user2@example.com,locked
user3@example.com,active
```

Valid statuses: `active`, `locked`, `closed`, `maintenance`
