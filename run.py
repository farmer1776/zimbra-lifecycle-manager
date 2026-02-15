#!/usr/bin/env python3
"""Entry point for the Zimbra Lifecycle Manager."""

import uvicorn
from app.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        workers=4,
        log_level="info",
        access_log=True,
    )
