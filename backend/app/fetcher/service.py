"""The isolated website fetcher: a tiny HTTP service with no database or Redis access.

Run it on its own network segment that can reach the internet but not the platform's internal
services (see docker-compose.yml and docs/threat-model.md). Callers authenticate with the
shared FETCHER_TOKEN.
"""

import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.fetcher.net import fetch

app = FastAPI(title="Website fetcher", docs_url=None, redoc_url=None, openapi_url=None)


class FetchRequest(BaseModel):
    url: str = Field(max_length=4096)
    timeout: float = Field(default=10.0, ge=1, le=30)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/fetch")
def do_fetch(body: FetchRequest, x_fetcher_token: str = Header(default="")) -> dict:
    expected = os.environ.get("FETCHER_TOKEN", "")
    if not expected or not hmac.compare_digest(x_fetcher_token, expected):
        raise HTTPException(status_code=401, detail="unauthorised")
    return fetch(
        body.url, timeout=body.timeout, max_redirects=body.max_redirects, max_bytes=body.max_bytes
    ).to_dict()
