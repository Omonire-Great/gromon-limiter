"""Runnable example: rate limiting a login endpoint.

Run it directly::

    export GROMON_LIMITER_SECRET="$(python -c \
'import secrets; print(secrets.token_urlsafe(32))')"
    python examples/flask_app.py

Then hammer the endpoint::

    for i in $(seq 1 8); do
      curl -s -o /dev/null -w '%{http_code} ' -X POST localhost:5000/login \
        -d 'email=victim@example.com&password=guess'
    done; echo

Expect ``401 401 401 401 401 429 429 429`` for the default 5/minute limit, and
inspect the response body of a rejection with ``curl -i``.

The same app with real shared state instead of process-local memory::

    AuthLimiter(app, limit="5/minute", storage="redis")   # needs REDIS_URL
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

from gromon_limiter import AuthLimiter, RateLimitExceeded
from gromon_limiter.flask import current_limiter

# Change this: it decides how identifiers are fingerprinted, so counters written
# with one salt cannot be read with another.
os.environ.setdefault(
    "GROMON_LIMITER_SECRET",
    "example-only-secret-change-me-in-production"
)

app = Flask(__name__)

limiter = AuthLimiter(
    app,
    limit="5/minute",          # default for every protected route
    storage="memory",          # "redis" for several workers/instances
    # Without this, every request appears to come from the proxy and IP limits
    # do nothing. Only list proxies you actually operate.
    trusted_proxies=os.environ.get("TRUSTED_PROXIES", "").split(",")
    if os.environ.get("TRUSTED_PROXIES")
    else (),
    cooldown=60,               # seconds of quiet after a breach, never forever
    account_limit_multiplier=3,  # account budget = 15/minute here
)


@app.post("/login")
@limiter.limit("5/minute")
def login() -> tuple[dict[str, object], int]:
    """Pretend to authenticate. The limiter runs before the body of this view."""
    # Real code would verify the password here and then, on success:
    # current_limiter().reset(...) so honest typos do not accumulate.
    return jsonify(ok=False, detail="invalid credentials"), 401


@app.post("/login-raise")
@limiter.limit("5/minute", raise_on_limit=True)
def login_raise() -> tuple[dict[str, object], int]:
    """Same protection, but the error is rendered by the project's own handler."""
    return jsonify(ok=False, detail="invalid credentials"), 401


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(error: RateLimitExceeded) -> tuple[dict[str, object], int]:
    return (
        jsonify(error="rate_limit_exceeded", try_again_in=int(error.decision.retry_after or 1)),
        429,
    )


@app.post("/sms-code")
@limiter.limit("3/hour", algorithm="fixed_window")
def sms_code() -> tuple[dict[str, object], int]:
    """A stricter, cheaper limit for an expensive action."""
    return jsonify(sent=True), 202


@app.get("/me")
def me() -> dict[str, object]:
    """The current decision is available for logging, never for raw identifiers."""
    from gromon_limiter.flask import current_decision

    decision = current_decision()
    return jsonify(
        path=request.path,
        checked=decision is not None,
        remaining=None if decision is None else decision.remaining,
        limiter=type(current_limiter()).__name__,
    )


if __name__ == "__main__":
    app.run(port=5000, debug=False)
