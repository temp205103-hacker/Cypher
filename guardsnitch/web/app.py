"""Local-only dashboard server."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


app = FastAPI(title="GuardSnitch.ai")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return "<!doctype html><title>GuardSnitch.ai</title><h1>GuardSnitch.ai dashboard</h1>"
