import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))


def _require_env(name: str) -> str:
    """Return an env var or raise if missing."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


class Settings:
    # Zimbra
    ZIMBRA_HOST: str = os.getenv("ZIMBRA_HOST", "https://mail.example.com")
    ZIMBRA_ADMIN_USER: str = os.getenv("ZIMBRA_ADMIN_USER", "admin@example.com")
    ZIMBRA_ADMIN_PASSWORD: str = os.getenv("ZIMBRA_ADMIN_PASSWORD", "changeme")
    ZIMBRA_ADMIN_PORT: int = int(os.getenv("ZIMBRA_ADMIN_PORT", "7071"))
    ZIMBRA_SSL_VERIFY: bool = os.getenv("ZIMBRA_SSL_VERIFY", "true").lower() in ("true", "1", "yes")
    ZIMBRA_CA_CERT: str = os.getenv("ZIMBRA_CA_CERT", "")

    # Database
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_NAME: str = os.getenv("DB_NAME", "zimbra_mgmt")
    DB_USER: str = os.getenv("DB_USER", "zimbra_mgmt")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DATABASE_URL: str = (
        f"mysql+pymysql://{os.getenv('DB_USER', 'zimbra_mgmt')}:"
        f"{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', 'localhost')}:"
        f"{os.getenv('DB_PORT', '3306')}/{os.getenv('DB_NAME', 'zimbra_mgmt')}"
    )

    # Redis
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # Security
    JWT_SECRET: str = _require_env("JWT_SECRET")
    SEED_ADMIN_PASSWORD: str = _require_env("SEED_ADMIN_PASSWORD")
    SEED_OPERATOR_PASSWORD: str = _require_env("SEED_OPERATOR_PASSWORD")

    # App
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    PURGE_INACTIVITY_DAYS: int = int(os.getenv("PURGE_INACTIVITY_DAYS", "60"))
    SYNC_INTERVAL_MINUTES: int = int(os.getenv("SYNC_INTERVAL_MINUTES", "30"))
    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))  # 5 MB


settings = Settings()
