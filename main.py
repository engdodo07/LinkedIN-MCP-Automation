#!/usr/bin/env python3
"""
LinkedIn Automation MCP Server (GitHub-Safe Production Version)
Compatible with Google Antigravity, Gemini MCP Connectors, and Cloud Hosting (Cloud Run, Railway, Render).

Security Note:
- Do NOT hardcode secrets in this file before pushing to GitHub.
- Set LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET via environment variables or a local `.env` file
  (make sure `.env` and `linkedin_tokens.json` are listed in `.gitignore`).
"""

import json
import logging
import os
import secrets
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("linkedin-mcp-server")


# ---------------------------------------------------------------------------
# Minimal Built-in .env Loader (Zero Extra Dependencies)
# ---------------------------------------------------------------------------
def load_dotenv_if_present(dotenv_path: Path = Path(".env")) -> None:
    """Load key=value pairs from a local .env file if it exists."""
    if not dotenv_path.exists():
        return
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception as exc:
        logger.warning("Could not read .env file: %s", exc)


load_dotenv_if_present()

# ---------------------------------------------------------------------------
# Configuration & Credentials (Loaded Strictly from Environment / .env)
# ---------------------------------------------------------------------------
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "").strip()
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "").strip()

PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

DATA_DIR = Path(os.getenv("DATA_DIR", ".")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
TOKEN_FILE = DATA_DIR / "linkedin_tokens.json"
DRAFTS_FILE = DATA_DIR / "linkedin_drafts.json"

# Standard LinkedIn OAuth 2.0 & OpenID Connect Scopes
LINKEDIN_SCOPES = os.getenv(
    "LINKEDIN_SCOPES", "openid profile email w_member_social"
)

LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_USERINFO_URL = "https://api.linkedin.com/v2/userinfo"
LINKEDIN_ME_URL = "https://api.linkedin.com/v2/me"
LINKEDIN_UGC_POSTS_URL = "https://api.linkedin.com/v2/ugcPosts"
LINKEDIN_REST_POSTS_URL = "https://api.linkedin.com/rest/posts"

OAUTH_STATE_STORE: Dict[str, float] = {}


# ---------------------------------------------------------------------------
# Storage Helpers (Tokens & Drafts)
# ---------------------------------------------------------------------------
def load_auth_data() -> Dict[str, Any]:
    """Load saved OAuth token and user profile from disk or environment variables."""
    data: Dict[str, Any] = {}
    if TOKEN_FILE.exists():
        try:
            data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read token file %s: %s", TOKEN_FILE, exc)

    env_token = os.getenv("LINKEDIN_ACCESS_TOKEN", "").strip()
    env_urn = os.getenv("LINKEDIN_PERSON_URN", "").strip()
    if env_token and not data.get("access_token"):
        data["access_token"] = env_token
    if env_urn and not data.get("person_urn"):
        if not env_urn.startswith("urn:li:"):
            env_urn = f"urn:li:person:{env_urn}"
        data["person_urn"] = env_urn

    return data


def save_auth_data(data: Dict[str, Any]) -> None:
    """Persist OAuth token and user profile to disk."""
    try:
        TOKEN_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        logger.error("Failed to save token file %s: %s", TOKEN_FILE, exc)


def load_drafts() -> List[Dict[str, Any]]:
    """Load saved LinkedIn post drafts from disk."""
    if DRAFTS_FILE.exists():
        try:
            content = json.loads(DRAFTS_FILE.read_text(encoding="utf-8"))
            if isinstance(content, list):
                return content
        except Exception as exc:
            logger.warning("Failed to read drafts file %s: %s", DRAFTS_FILE, exc)
    return []


def save_drafts(drafts: List[Dict[str, Any]]) -> None:
    """Save LinkedIn post drafts to disk."""
    try:
        DRAFTS_FILE.write_text(
            json.dumps(drafts, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        logger.error("Failed to write drafts file %s: %s", DRAFTS_FILE, exc)


def resolve_base_url(request: Request) -> str:
    """Determine external base URL (supports Cloudflare Tunnel & Cloud Reverse Proxies)."""
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    forwarded_host = request.headers.get(
        "x-forwarded-host", request.headers.get("host", f"localhost:{PORT}")
    )
    return f"{forwarded_proto}://{forwarded_host}"


# ---------------------------------------------------------------------------
# LinkedIn API Helpers
# ---------------------------------------------------------------------------
async def fetch_linkedin_identity(access_token: str) -> Dict[str, Any]:
    """Fetch authenticated user profile via OpenID Connect /v2/userinfo with fallback to /v2/me."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        # 1. Try OpenID Connect /v2/userinfo
        resp = await client.get(LINKEDIN_USERINFO_URL, headers=headers)
        if resp.status_code == 200:
            info = resp.json()
            sub = info.get("sub", "")
            person_urn = f"urn:li:person:{sub}" if sub else ""
            return {
                "id": sub,
                "person_urn": person_urn,
                "name": info.get("name")
                or f"{info.get('given_name', '')} {info.get('family_name', '')}".strip(),
                "given_name": info.get("given_name", ""),
                "family_name": info.get("family_name", ""),
                "email": info.get("email", ""),
                "picture": info.get("picture", ""),
                "locale": info.get("locale", {}),
            }

        # 2. Fallback to Legacy /v2/me
        resp_me = await client.get(
            LINKEDIN_ME_URL,
            headers={**headers, "X-Restli-Protocol-Version": "2.0.0"},
        )
        if resp_me.status_code == 200:
            me = resp_me.json()
            user_id = me.get("id", "")
            first_name = me.get("localizedFirstName", "")
            last_name = me.get("localizedLastName", "")
            return {
                "id": user_id,
                "person_urn": f"urn:li:person:{user_id}" if user_id else "",
                "name": f"{first_name} {last_name}".strip(),
                "given_name": first_name,
                "family_name": last_name,
                "email": "",
            }

        raise RuntimeError(
            f"LinkedIn profile lookup failed (userinfo HTTP {resp.status_code}: {resp.text})"
        )


# ---------------------------------------------------------------------------
# MCP Server & Tool Definitions
# ---------------------------------------------------------------------------
mcp = FastMCP("LinkedIn Automation Server")


@mcp.tool()
async def check_connection_status() -> str:
    """
    Verify if LinkedIn API credentials are setup and if an active OAuth session exists.
    Returns:
        Status summary and instructions if authentication is missing.
    """
    auth = load_auth_data()
    access_token = auth.get("access_token")
    person_urn = auth.get("person_urn")
    expires_at = auth.get("expires_at", 0)

    has_client_creds = bool(LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET)
    now = int(time.time())
    is_expired = bool(expires_at and now >= expires_at)

    if not has_client_creds and not access_token:
        return json.dumps(
            {
                "status": "MISSING_CREDENTIALS",
                "client_credentials_configured": False,
                "message": (
                    "LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET are not set. "
                    "Configure them in your .env file or cloud environment variables."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )

    if not access_token:
        return json.dumps(
            {
                "status": "NOT_AUTHENTICATED",
                "client_credentials_configured": has_client_creds,
                "message": (
                    "LinkedIn Client ID and Secret are configured, but no active OAuth Access Token was found. "
                    "Open your server's '/auth' URL in a browser to complete LinkedIn OAuth login, "
                    "or set LINKEDIN_ACCESS_TOKEN in your environment."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )

    if is_expired:
        return json.dumps(
            {
                "status": "TOKEN_EXPIRED",
                "person_urn": person_urn,
                "expired_at": datetime.fromtimestamp(
                    expires_at, tz=timezone.utc
                ).isoformat(),
                "message": "OAuth token has expired. Please re-authenticate via '/auth'.",
            },
            ensure_ascii=False,
            indent=2,
        )

    try:
        profile = await fetch_linkedin_identity(access_token)
        if profile.get("person_urn") and not person_urn:
            auth["person_urn"] = profile["person_urn"]
            auth["profile"] = profile
            save_auth_data(auth)

        return json.dumps(
            {
                "status": "CONNECTED",
                "authenticated_user": profile.get("name"),
                "email": profile.get("email"),
                "person_urn": profile.get("person_urn") or person_urn,
                "message": "LinkedIn API connection is active and ready to publish posts.",
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            {
                "status": "ERROR",
                "person_urn": person_urn,
                "error": str(exc),
                "message": "Token verification failed. Please re-authenticate via '/auth'.",
            },
            ensure_ascii=False,
            indent=2,
        )


@mcp.tool()
async def get_linkedin_profile() -> str:
    """
    Fetch the profile information of the currently authenticated LinkedIn user.
    Returns:
        JSON string containing user name, email, person URN, and auth status.
    """
    auth = load_auth_data()
    access_token = auth.get("access_token")
    if not access_token:
        return json.dumps(
            {
                "authenticated": False,
                "error": "No active LinkedIn access token found. Please authenticate at /auth first.",
            },
            ensure_ascii=False,
            indent=2,
        )

    try:
        profile = await fetch_linkedin_identity(access_token)
        auth["person_urn"] = profile.get("person_urn", auth.get("person_urn", ""))
        auth["profile"] = profile
        save_auth_data(auth)
        return json.dumps(
            {
                "authenticated": True,
                "name": profile.get("name"),
                "email": profile.get("email"),
                "person_urn": profile.get("person_urn"),
                "profile": profile,
            },
            ensure_ascii=False,
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            {
                "authenticated": False,
                "error": str(exc),
            },
            ensure_ascii=False,
            indent=2,
        )


@mcp.tool()
async def post_to_linkedin(content: str, visibility: str = "PUBLIC") -> str:
    """
    Publish a new post to LinkedIn feed on behalf of the authenticated user.
    Args:
        content: The text content of the LinkedIn post. Should be well formatted with line breaks and relevant hashtags.
        visibility: Post visibility ('PUBLIC' or 'CONNECTIONS'). Default is 'PUBLIC'.
    Returns:
        A message with post status, URN, and direct link to the published post.
    """
    if not content or not content.strip():
        return json.dumps(
            {"status": "ERROR", "message": "Post content cannot be empty."},
            ensure_ascii=False,
        )

    visibility_clean = visibility.upper().strip()
    if visibility_clean not in ("PUBLIC", "CONNECTIONS"):
        visibility_clean = "PUBLIC"

    auth = load_auth_data()
    access_token = auth.get("access_token")
    if not access_token:
        return json.dumps(
            {
                "status": "NOT_AUTHENTICATED",
                "message": "Cannot publish post: No LinkedIn access token found. Please visit /auth to log in.",
            },
            ensure_ascii=False,
            indent=2,
        )

    person_urn = auth.get("person_urn")
    if not person_urn:
        try:
            profile = await fetch_linkedin_identity(access_token)
            person_urn = profile.get("person_urn")
            auth["person_urn"] = person_urn
            auth["profile"] = profile
            save_auth_data(auth)
        except Exception as exc:
            return json.dumps(
                {
                    "status": "ERROR",
                    "message": f"Failed to resolve LinkedIn Person URN: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )

    ugc_payload = {
        "author": person_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": content},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": visibility_clean
        },
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Restli-Protocol-Version": "2.0.0",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            LINKEDIN_UGC_POSTS_URL, headers=headers, json=ugc_payload
        )

        if resp.status_code in (200, 201):
            body = resp.json() if resp.content else {}
            post_urn = (
                resp.headers.get("x-restli-id")
                or body.get("id")
                or "urn:li:share:unknown"
            )
            post_url = f"https://www.linkedin.com/feed/update/{post_urn}/"
            return json.dumps(
                {
                    "status": "PUBLISHED",
                    "post_urn": post_urn,
                    "post_url": post_url,
                    "visibility": visibility_clean,
                    "published_at": datetime.now(timezone.utc).isoformat(),
                    "message": f"Post successfully published to LinkedIn! View at: {post_url}",
                },
                ensure_ascii=False,
                indent=2,
            )

        # Fallback to versioned REST Posts API (/rest/posts) if ugcPosts fails
        rest_payload = {
            "author": person_urn,
            "commentary": content,
            "visibility": visibility_clean,
            "distribution": {
                "feedDistribution": "MAIN_FEED",
                "targetEntities": [],
                "thirdPartyDistributionChannels": [],
            },
            "lifecycleState": "PUBLISHED",
            "isReshareDisabledByAuthor": False,
        }
        rest_headers = {
            **headers,
            "LinkedIn-Version": "202502",
        }
        resp_rest = await client.post(
            LINKEDIN_REST_POSTS_URL, headers=rest_headers, json=rest_payload
        )
        if resp_rest.status_code in (200, 201):
            post_urn = resp_rest.headers.get("x-restli-id", "urn:li:share:created")
            post_url = f"https://www.linkedin.com/feed/update/{post_urn}/"
            return json.dumps(
                {
                    "status": "PUBLISHED",
                    "post_urn": post_urn,
                    "post_url": post_url,
                    "visibility": visibility_clean,
                    "published_at": datetime.now(timezone.utc).isoformat(),
                    "message": f"Post successfully published to LinkedIn! View at: {post_url}",
                },
                ensure_ascii=False,
                indent=2,
            )

        return json.dumps(
            {
                "status": "FAILED",
                "ugc_status_code": resp.status_code,
                "ugc_error": resp.text,
                "rest_status_code": resp_rest.status_code,
                "rest_error": resp_rest.text,
            },
            ensure_ascii=False,
            indent=2,
        )


@mcp.tool()
async def save_draft_post(topic: str, content: str) -> str:
    """
    Save a generated post draft for review before publishing.
    Args:
        topic: Brief topic or headline for the draft.
        content: The full body of the post.
    """
    drafts = load_drafts()
    draft_item = {
        "id": f"draft_{int(time.time())}_{len(drafts) + 1}",
        "topic": topic.strip(),
        "content": content,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    drafts.append(draft_item)
    save_drafts(drafts)
    return json.dumps(
        {
            "status": "SAVED",
            "draft": draft_item,
            "total_drafts": len(drafts),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def list_drafts() -> str:
    """List all saved LinkedIn post drafts."""
    drafts = load_drafts()
    return json.dumps(
        {
            "total_drafts": len(drafts),
            "drafts": drafts,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def get_posting_best_practices() -> str:
    """
    Get recommended best practices and guidelines for writing high-engagement LinkedIn posts.
    """
    guidelines = {
        "structure": [
            "Strong Hook (first 1-2 lines): Start with a bold question, surprising shop-floor reality, or painful truth.",
            "Short Intro: 2 lines maximum setting up the real-world scenario.",
            "Structured Body: Use clear contrasts (Routine vs True Planner) with bullet points and visual markers (❌, ✅, 🔹, 👉).",
            "Key Takeaway: Bold 2-line summary delivering the practical lesson.",
            "Engagement Question: End with a direct question prompting comments.",
            "Hashtags: 5 to 7 targeted hashtags mixing English (#ProductionPlanning #Manufacturing #SupplyChain) and Arabic (#التخطيط #الصناعة_المصرية).",
        ],
        "formatting_tips": [
            "Keep sentences short and conversational with generous line breaks.",
            "Ground posts in real Shop Floor, ERP, WIP, Bottleneck, and Lead Time scenarios.",
            "Publish around peak local engagement windows (e.g., 10:00 AM Cairo time, Sunday–Thursday).",
        ],
    }
    return json.dumps(guidelines, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Web Routes for OAuth 2.0 & Server Status Dashboard
# ---------------------------------------------------------------------------
async def homepage(request: Request) -> HTMLResponse:
    """Render an interactive status & OAuth setup page."""
    base_url = resolve_base_url(request)
    redirect_uri = f"{base_url}/callback"
    sse_url = f"{base_url}/sse"

    auth = load_auth_data()
    has_token = bool(auth.get("access_token"))
    has_creds = bool(LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET)
    profile_name = auth.get("profile", {}).get("name", "Not loaded")
    person_urn = auth.get("person_urn", "Not resolved")

    if has_token:
        status_badge = '<span style="color:#0a7d33;font-weight:bold;">✅ Connected & Ready</span>'
    elif has_creds:
        status_badge = '<span style="color:#d97706;font-weight:bold;">⚠️ OAuth Login Required</span>'
    else:
        status_badge = '<span style="color:#c93b2b;font-weight:bold;">❌ Missing LINKEDIN_CLIENT_ID / SECRET in Environment</span>'

    masked_client_id = (
        f"{LINKEDIN_CLIENT_ID[:4]}...{LINKEDIN_CLIENT_ID[-4:]}"
        if len(LINKEDIN_CLIENT_ID) > 8
        else ("Configured" if LINKEDIN_CLIENT_ID else "Not Configured")
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LinkedIn Automation MCP Server</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 780px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #1f2937; }}
        .card {{ border: 1px solid #e5e7eb; border-radius: 10px; padding: 24px; margin-bottom: 20px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        code {{ background: #f3f4f6; padding: 3px 6px; border-radius: 4px; font-size: 0.92em; }}
        .btn {{ display: inline-block; background: #0a66c2; color: #fff; padding: 10px 18px; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 10px; }}
        .btn:hover {{ background: #004182; }}
    </style>
</head>
<body>
    <h1>LinkedIn Automation MCP Server</h1>
    <div class="card">
        <h3>Connection Status: {status_badge}</h3>
        <p><strong>LinkedIn Client ID:</strong> <code>{masked_client_id}</code></p>
        <p><strong>Authenticated User:</strong> {profile_name}</p>
        <p><strong>Person URN:</strong> <code>{person_urn}</code></p>
        <p><strong>MCP Connector SSE Endpoint:</strong> <code>{sse_url}</code></p>
        <a class="btn" href="/auth">🔗 Authorize with LinkedIn OAuth 2.0</a>
    </div>
    <div class="card">
        <h3>Important Setup Step in LinkedIn Developer Portal</h3>
        <p>In your <a href="https://www.linkedin.com/developers/apps" target="_blank">LinkedIn Developer App</a> under the <strong>Auth</strong> tab, add this exact Redirect URL to <em>Authorized redirect URLs for your app</em>:</p>
        <p><code>{redirect_uri}</code></p>
        <p>Also ensure both products are enabled under the <strong>Products</strong> tab: <em>Share on LinkedIn</em> and <em>Sign In with LinkedIn using OpenID Connect</em>.</p>
    </div>
</body>
</html>"""
    return HTMLResponse(html)


async def start_oauth(request: Request) -> HTMLResponse | RedirectResponse:
    """Redirect user to LinkedIn's OAuth 2.0 authorization page."""
    if not LINKEDIN_CLIENT_ID or not LINKEDIN_CLIENT_SECRET:
        return HTMLResponse(
            "<h2>Missing Credentials</h2>"
            "<p>Please set <code>LINKEDIN_CLIENT_ID</code> and <code>LINKEDIN_CLIENT_SECRET</code> "
            "in your environment variables or <code>.env</code> file before starting OAuth.</p>",
            status_code=400,
        )

    base_url = resolve_base_url(request)
    redirect_uri = f"{base_url}/callback"
    state = secrets.token_urlsafe(16)
    OAUTH_STATE_STORE[state] = time.time()

    params = {
        "response_type": "code",
        "client_id": LINKEDIN_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": LINKEDIN_SCOPES,
    }
    url = f"{LINKEDIN_AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)


async def oauth_callback(request: Request) -> HTMLResponse:
    """Exchange LinkedIn authorization code for an access token and store it."""
    error = request.query_params.get("error")
    error_desc = request.query_params.get("error_description", "")
    if error:
        return HTMLResponse(
            f"<h2>LinkedIn OAuth Error</h2><p><strong>{error}</strong>: {error_desc}</p>",
            status_code=400,
        )

    code = request.query_params.get("code")
    if not code:
        return HTMLResponse("<h2>Missing authorization code</h2>", status_code=400)

    base_url = resolve_base_url(request)
    redirect_uri = f"{base_url}/callback"

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
    }

    async with httpx.AsyncClient(timeout=25.0) as client:
        resp = await client.post(
            LINKEDIN_TOKEN_URL,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            return HTMLResponse(
                f"<h2>Token Exchange Failed ({resp.status_code})</h2><pre>{resp.text}</pre>",
                status_code=400,
            )

        token_json = resp.json()
        access_token = token_json.get("access_token", "")
        expires_in = int(token_json.get("expires_in", 5184000))
        refresh_token = token_json.get("refresh_token", "")

    profile: Dict[str, Any] = {}
    person_urn = ""
    try:
        profile = await fetch_linkedin_identity(access_token)
        person_urn = profile.get("person_urn", "")
    except Exception as exc:
        logger.warning("Could not fetch profile immediately after OAuth: %s", exc)

    auth_record = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "expires_at": int(time.time()) + expires_in,
        "obtained_at": datetime.now(timezone.utc).isoformat(),
        "person_urn": person_urn,
        "profile": profile,
    }
    save_auth_data(auth_record)

    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>LinkedIn Connected</title></head>
<body style="font-family:system-ui,sans-serif;max-width:650px;margin:40px auto;padding:20px;">
    <h2 style="color:#0a7d33;">✅ LinkedIn Connected Successfully!</h2>
    <p><strong>Name:</strong> {profile.get('name', 'Authenticated User')}</p>
    <p><strong>Person URN:</strong> <code>{person_urn}</code></p>
    <p>Your token has been saved to <code>{TOKEN_FILE.name}</code>. Your MCP Server is now ready to publish posts!</p>
    <p><a href="/">← Back to Dashboard</a></p>
</body>
</html>"""
    )


async def health_check(request: Request) -> JSONResponse:
    """Health check route for cloud hosting & tunnel monitors."""
    auth = load_auth_data()
    return JSONResponse(
        {
            "status": "ok",
            "service": "LinkedIn Automation MCP Server",
            "authenticated": bool(auth.get("access_token")),
            "person_urn": auth.get("person_urn", ""),
        }
    )


# ---------------------------------------------------------------------------
# Combined ASGI Application (OAuth Web Routes + FastMCP SSE App)
# ---------------------------------------------------------------------------
mcp_sse_app = mcp.sse_app()

app = Starlette(
    routes=[
        Route("/", endpoint=homepage, methods=["GET"]),
        Route("/auth", endpoint=start_oauth, methods=["GET"]),
        Route("/login", endpoint=start_oauth, methods=["GET"]),
        Route("/callback", endpoint=oauth_callback, methods=["GET"]),
        Route("/oauth/callback", endpoint=oauth_callback, methods=["GET"]),
        Route("/health", endpoint=health_check, methods=["GET"]),
        Mount("/", app=mcp_sse_app),
    ]
)

if __name__ == "__main__":
    logger.info("Starting LinkedIn Automation MCP Server on %s:%s", HOST, PORT)
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )