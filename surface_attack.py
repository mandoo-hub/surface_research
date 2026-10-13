import os
import socket
import ssl
import json
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

import dns.resolver
import requests

result_dir = "result"

os.makedirs(
    result_dir,
    exist_ok=True
)

TARGET_DOMAIN = "jusohot6.com"

HTTP_TIMEOUT = 5
DNS_TIMEOUT = 3
JS_TIMEOUT = 5

USER_AGENT = "AttackSurfaceResearch/1.0"

# ---------------------------------------------------------
# 공통
# ---------------------------------------------------------

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/154.0.0.0 Safari/537.36"
    )
}


def normalize_url(base_url, value):
    if not value:
        return None

    value = value.strip()

    # javascript:, data:, blob: 등 제외
    if value.startswith((
        "javascript:",
        "data:",
        "mailto:",
        "tel:",
        "ftp:",
        "irc:",
        "nntp:",
        "news:",
        "telnet:",
        "mms:",
        "rtsp:",
        "callto:",
        "blob:",
        "file:"
    )):
        return None
    
    try:
        return urljoin(base_url, value)
    except Exception:
        return None

# =========================================================
# DNS
# =========================================================

def resolve_dns(domain):
    result = {
        "domain": domain,
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "ns": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    record_types = [
        ("A", "a"),
        ("AAAA", "aaaa"),
        ("CNAME", "cname"),
        ("MX", "mx"),
        ("NS", "ns")
    ]

    for rtype, key in record_types:

        try:
            answers = resolver.resolve(domain, rtype)

            for answer in answers:

                value = str(answer).rstrip(".")

                if rtype == "MX":
                    # ex:
                    # 10 mail.example.com.
                    parts = value.split()

                    if len(parts) >= 2:
                        value = parts[-1].rstrip(".")

                result[key].append(value)

        except Exception:
            pass

    return result


# =========================================================
# CDN Detection
# =========================================================

CDN_SIGNATURES = {
    "cloudflare": [
        "cloudflare",
        "cloudflare.net"
    ],

    "cloudfront": [
        "cloudfront.net"
    ],

    "akamai": [
        "akamaiedge.net",
        "akamai.net",
        "akamaitechnologies.com"
    ],

    "fastly": [
        "fastly.net",
        "fastlylb.net"
    ],

    "azure": [
        "azureedge.net",
        "trafficmanager.net",
        "azurefd.net"
    ],

    "google": [
        "googleusercontent.com",
        "googlehosted.com"
    ]
}


def detect_cdn_from_cname(cnames):
    detected = []

    for cname in cnames:

        cname_lower = cname.lower()

        for provider, signatures in CDN_SIGNATURES.items():

            for signature in signatures:

                if signature in cname_lower:

                    detected.append({
                        "provider": provider,
                        "evidence": f"CNAME={cname}"
                    })

    return detected

# =========================================================
# HTTP
# =========================================================


def get_http_info(domain):

    results = []

    analyzed_final_urls = {}

    for scheme in ["https", "http"]:

        url = f"{scheme}://{domain}/"

        try:
            response = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            response.encoding = "utf-8"

            interesting_headers = {}

            header_names = [
                "server",
                "via",
                "x-powered-by",
                "x-cache",
                "cf-ray",
                "cf-cache-status",
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "x-azure-ref",
                "x-served-by",
                "x-fastly-request-id",
                "strict-transport-security",
                "content-security-policy",
                "location"
            ]

            for header in header_names:

                value = response.headers.get(header)

                if value:
                    interesting_headers[header] = value

            title = extract_title(response.text)

            http_result = {
                "scheme": scheme,
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "title": title,
                "headers": interesting_headers,
                "content_length": len(response.content)
            }
            
            # Content-Type 확인
            content_type = response.headers.get(
                "Content-Type",
                ""
            )
            
            # HTML 페이지인 경우만 링크 / JS 분석
            if (
                response.status_code == 200
                and
                "text/html" in content_type.lower()
            ):
                
                http_result["links"] = (
                    extract_links_from_html(
                        response.url,
                        response.text
                    )
                )

                final_url = (
                    response.url
                )

                if (
                    final_url
                    in analyzed_final_urls
                ):
                    
                    http_result[
                        "browser_analysis"
                    ] = analyzed_final_urls[
                        final_url
                    ]
                
                else:

                    browser_analysis = (
                        analyze_web_surface(
                            final_url,
                            html=response.text,
                            run_dynamic=True
                        )
                    )

                    analyzed_final_urls[
                        final_url
                    ] = browser_analysis

                    http_result[
                        "browser_analysis"
                    ] = browser_analysis
                
            results.append(
                http_result
            )

        except Exception as e:

            results.append({
                "scheme": scheme,
                "url": url,
                "error": str(e)
            })

    return results


def extract_title(html):

    if not html:
        return None

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL
    )

    if not match:
        return None

    return re.sub(
        r"\s+",
        " ",
        match.group(1)
    ).strip()


# =========================================================
# HTTP Header → CDN/WAF detection
# =========================================================

def detect_edge_from_headers(http_results):

    findings = []

    for result in http_results:

        headers = result.get("headers", {})

        server = headers.get(
            "server",
            ""
        ).lower()

        if "cloudflare" in server or "cf-ray" in headers:

            findings.append({
                "provider": "cloudflare",
                "evidence": "HTTP header"
            })

        if (
            "cloudfront" in server
            or "x-amz-cf-id" in headers
            or "x-amz-cf-pop" in headers
        ):

            findings.append({
                "provider": "aws_cloudfront",
                "evidence": "HTTP header"
            })

        if (
            "x-fastly-request-id" in headers
            or "x-served-by" in headers
        ):

            findings.append({
                "provider": "fastly",
                "evidence": "HTTP header"
            })

        if "x-azure-ref" in headers:

            findings.append({
                "provider": "azure_front_door",
                "evidence": "HTTP header"
            })

        via = headers.get(
            "via",
            ""
        ).lower()

        if "akamai" in via:

            findings.append({
                "provider": "akamai",
                "evidence": "Via header"
            })

    return findings


# =========================================================
# TLS
# =========================================================

def get_tls_info(domain, port=443):

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, port),
            timeout=HTTP_TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as tls_sock:

                cert = tls_sock.getpeercert()

                cipher = tls_sock.cipher()

                tls_version = tls_sock.version()

                san_list = []

                for item in cert.get(
                    "subjectAltName",
                    []
                ):

                    if item[0] == "DNS":

                        san_list.append(
                            item[1]
                        )

                return {
                    "tls_version": tls_version,
                    "cipher": cipher,
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": sorted(set(san_list))
                }

    except Exception as e:

        return {
            "error": str(e)
        }


# =========================================================
# Asset Candidate extraction
# =========================================================

def extract_asset_candidates(
    original_domain,
    dns_info,
    tls_info
):

    assets = set()

    assets.add(
        original_domain.lower()
    )

    #
    # CNAME
    #
    for cname in dns_info.get(
        "cname",
        []
    ):

        assets.add(
            cname.lower()
        )

    #
    # TLS SAN
    #
    for san in tls_info.get(
        "san",
        []
    ):

        san = san.lower()

        #
        # wildcard는 실제 호스트가 아니므로
        # 정보만 참고하고 직접 scan 하지 않음
        #
        if san.startswith("*."):
            continue

        assets.add(san)

    return sorted(
        assets
    )


# =========================================================
# Basic technology fingerprint
# =========================================================

def fingerprint_technology(http_results):

    technologies = set()

    for result in http_results:

        headers = result.get(
            "headers",
            {}
        )

        server = headers.get(
            "server"
        )

        powered = headers.get(
            "x-powered-by"
        )

        if server:

            technologies.add(
                ("server", server)
            )

        if powered:

            technologies.add(
                ("framework", powered)
            )

    return [
        {
            "type": tech_type,
            "value": value
        }
        for tech_type, value in technologies
    ]

# =========================================================
# HTML에서 JavaScript 자산 추출
# =========================================================


def extract_script_urls(base_url, html):
    """
    기존 <script src> 뿐 아니라
    modulepreload / preload as=script까지 수집
    """

    scripts = set()

    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    # <Scrip src="...">
    for tag in soup.find_all("script"):
        src = tag.get("src")

        if src:
            url = normalize_url(base_url, src)

            if url:
                scripts.add(url)
    
    # <link rel="modulepreload" href="...">
    # <link rel="preload" as="script" href="...">
    for tag in soup.find_all("link"):

        href = tag.get("href")

        if not href:
            continue

        rel = tag.get("rel", [])
        rel = [str(x).lower() for x in rel]

        as_type = str(tag.get("as", "")).lower()

        is_js_link = (
            "modulepreload" in rel
            or (
                "preload" in rel
                and as_type == "script"
            )
        )

        if not is_js_link:
            continue

        url = normalize_url(base_url, href)

        if url:
            scripts.add(url)

    return sorted(scripts)

# ---------------------------------------------------------
# 2. HTML inline script 추출
# ---------------------------------------------------------

def extract_inline_scripts(html):
    results = []

    if not html:
        return results

    soup = BeautifulSoup(html, "html.parser")

    for idx, tag in enumerate(soup.find_all("script")):

        # src가 있는 것은 별도 다운로드 대상
        if tag.get("src"):
            continue

        text = tag.string or tag.get_text()

        if not text:
            continue

        text = text.strip()

        if len(text) < 10:
            continue

        results.append({
            "index": idx,
            "content_length": len(text),
            "content": text,            
        })

    return results

# ---------------------------------------------------------
# 3. JS 내부 endpoint 후보 추출
# ---------------------------------------------------------

def extract_api_candidates_from_js(js_text, base_url):
    """
    JS 코드 안에 들어있는 endpoint 후보 추출.

    fetch("/api/...")
    axios.get("/api/...")
    "/grahql"
    "/v1/users"
    import("/assets/chunk.js")
    WebSocket(...)
    등의 문자열 후보를 찾음.
    """

    if not js_text:
        return []

    candidates = set()

    patterns = [
        # fetch("...")
        r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]''',

        # axios.get("..."), axios.post("...")
        r'''axios\.(?:get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`]+)["'`]''',

        # axios({... url: "..."})
        r'''url\s*:\s*["'`]([^"'`]+)["'`]''',

        # XMLHttpRequest.open("GET", "/api/...")
        r'''\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`]+)["'`]''',

        # dynamic import("...")
        r'''import\s*\(\s*["'`]([^"'`]+)["'`]\s*\)''',

        # WebSocket("wss://...")
        r'''(?:WebSocket|EventSource)\s*\(\s*["'`]([^"'`]+)["'`]''',

        # API-like quoted strings
        r'''["'`](
            \ (?:api|graphql|ajax|rest|v\d+)
            \?[^"'`\s<>]*
        )["'`]''',

        # 절대 URL
        r'''["'`](https?://[^"'`\s<>]+)["'`]''',

        # /api/...
        r"""["'](/api/[A-Za-z0-9_\-./{}?=&%]+)["']""",

        # /v1/... /v2/... 등
        r"""["'](/?v[0-9]+/[A-Za-z0-9_\-./{}?=&%]+)["']""",

        # 일반적인 상대 endpoint
        r"""["'](/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-./{}?=&%]+)["']"""
    ]

    for pattern in patterns:

        try:
            matches = re.findall(
                pattern,
                js_text,
                flags=re.IGNORECASE | re.VERBOSE
            )

        except re.error as e:
            print(f"[!] Regex error")
            print(f"    pattern: {pattern}")
            print(f"    error: {e}")
            continue

        for value in matches:

            if isinstance(value, tuple):
                value = next(
                    (x for x in value if x),
                    None
                )

            if not value:
                continue

            value = value.strip()

            # template vaiable 비중이 너무 높은 값 제외
            if value in ("/", "./", "../"):
                continue
            
            url = normalize_url(base_url, value)

            if url:
                candidates.add(url)

    return sorted(candidates)


def extract_links_from_html(base_url, html):
    """
    HTML의 href/src에서 공개 자산 및 endpoint 후보 수집
    """
    links = set()

    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']'
    ]

    for pattern in patterns:
        for value in re.findall(
            pattern,
            html,
            re.IGNORECASE
        ):
            full_url = urljoin(base_url, value)
            links.add(full_url)

    return sorted(links)

def analyze_javascript_assets(base_url, html, timeout=10):
    """
    페이지의 JS 자산을 다운로드하고 endpoint 후보 추출
    """

    result = {
        "scripts": [],
        "endpoint_candidates": []
    }

    all_endpoints = set()

    script_urls = extract_script_urls(
        base_url,
        html
    )

    for script_url in script_urls:

        print(f"[*] JS analysis: {script_url}")

        script_result = {
            "url": script_url
        }

        try:
            r = requests.get(
                    script_url,
                    headers=DEFAULT_HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
            )

            script_result["status_code"] = r.status_code
            script_result["content_length"] = len(r.content)
            script_result["content_type"] = (
                r.headers.get("Content-Type")
            )

            if r.status_code == 200:

                endpoints = extract_api_candidates_from_js(
                    r.text,
                    r.url
                )

                script_result[
                    "endpoint_candidates"
                ] = endpoints

                all_endpoints.update(endpoints)
        
        except Exception as e:
            script_result["error"] = str(e)

        result["scripts"].append(
            script_result
        )

    # inline script도 분석
    inline_scripts = extract_inline_scripts(html)

    for item in inline_scripts:

        endpoints = extract_api_candidates_from_js(
            item["content"],
            base_url
        )

        if endpoints:
            result["scripts"].append({
                "type": "inline",
                "index": item["index"],
                "content_length": item["content_length"],
                "endpoint_candidates": endpoints,
            })

            all_endpoints.update(endpoints)

    result["endpoint_candidates"] = sorted(
        all_endpoints
    )

    return result

# ---------------------------------------------------------
# 5. Playwright 동적 네트워크 수집
# ---------------------------------------------------------

def collect_dynamic_network(
    url,
    timeout=30000,
    headless=True
):
    """
    브라우저가 실제로 발생시키는 네트워크 요청 수집.

    - document
    - script
    - fetch
    - xhr
    - websocket
    - 기타 요청

    특히 fetch/xhr는 API 후보로 별도 분류
    """

    result = {
        "final_url": None,
        "requests": [],
        "responses": [],
        "javascript": [],
        "api_candidates": [],
        "interactions": [],
        "websockets": [],
        "errors": [],
    }

    seen_requests = set()
    seen_responses = set()
    seen_js = set()
    seen_api = set()
    seen_ws = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless
        )

        context = browser.new_context(
            user_agent=DEFAULT_HEADERS[
                "User-Agent"
            ],
            ignore_https_errors=True,
        )

        page = context.new_page()

        def on_request(request):

            request_url = request.url
            resource_type = request.resource_type
            method = request.method

            key = (
                method,
                request_url,
                resource_type
            )

            if key not in seen_requests:

                seen_requests.add(key)

                result["requests"].append({
                    "method": method,
                    "url": request_url,
                    "resource_type": resource_type,
                })

            # 실제 브라우저에서 로딩된 JavaScript
            if resource_type == "script":

                if request_url not in seen_js:
                    seen_js.add(request_url)

                    result["javascript"].append(
                        request_url
                    )

            # fetch / xhr
            if resource_type in (
                "fetch",
                "xhr",
            ):
                print(
                    f"[API] "
                    f"{method} "
                    f"{request_url} "
                )
                try:
                    post_data = request.post_data
                except Exception:
                    post_data = None

                api_key = (
                    method,
                    request_url,
                    post_data
                )
                if api_key not in seen_api:
                    
                    seen_api.add(api_key)

                    api_item = {
                        "method": method,
                        "url": request_url,
                        "resource_type": resource_type,
                        "headers": {},
                        "post_data": post_data
                    }

                    # Request headers 수집
                    try:
                        api_item["headers"] = request.headers
                    except Exception as e:
                        api_item["headers_error"] = str(e)

                    api_item["score"] = (
                        score_api_candidate(
                            api_item
                        )
                    )

                    result[
                        "api_candidates"
                    ].append(api_item)
            
        def on_response(response):
            
            request = response.request
            try:
                request_body = request.post_data
            except Exception:
                request_body =None

            if request.resource_type in ("fetch", "xhr"):
                key = (
                    request.method,
                    response.url,
                    response.status,
                    request_body
                )

                if key not in seen_responses:
                    seen_responses.add(key)
                    
                    item = {
                        "method": request.method,
                        "url": response.url,
                        "status": response.status,
                        "content_type": response.headers.get(
                            "content-type"
                        ),
                    }

                    content_type = (
                        item["content_type"]
                        or ""
                    ).lower()

                    if "application/json" in content_type:
                        try:
                            body = response.text()

                            if len(body) <= 100000:
                                item["body"] = body
                        except Exception as e:
                            item["body_error"] = str(e)
                    
                    result[
                        "responses"
                    ].append(item)

        def on_websocket(ws):

            if ws.url not in seen_ws:

                seen_ws.add(ws.url)

                result["websockets"].append(
                    ws.url
                )
        
        def on_request_failed(request):

            failure = request.failure

            result["errors"].append({
                "url": request.url,
                "method": request.method,
                "failure": failure,
            })
        
        page.on(
            "request",
            on_request
        )

        page.on(
            "response",
            on_response
        )

        page.on(
            "websocket",
            on_websocket
        )

        page.on(
            "requestfailed",
            on_request_failed
        )

        try:

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=timeout
            )

            # SPA / Lazy Load / runtime fetch 기다림
            page.wait_for_timeout(2000)

            interaction_base_url = page.url
            
            result[
                "interactions"
            ] = interact_page(
                page,
                interaction_base_url,
                result
            )

            page.wait_for_timeout(3000)

            result["final_url"] = page.url

        except Exception as e:
            result["errors"].append({
                "type": "navigation",
                "error": str(e),
            })
        
        finally:
            context.close()
            browser.close()
    
    result[
        "api_candidates"
    ] = sorted(
        result["api_candidates"],
        key=lambda x: x.get(
            "score",
            0
        ),
        reverse=True
    )

    return result

# ---------------------------------------------------------
# 6. 동적으로 발견한 JavaScript도 다시 정적 분석
# ---------------------------------------------------------

def analyze_dynamic_javascript(
    javascript_urls,
    timeout=10
):
    result = {
        "scripts": [],
        "endpoint_candidates": []
    }

    endpoints = set()

    for js_url in javascript_urls:

        item = {
            "url": js_url
        }

        try:

            r = requests.get(
                js_url,
                headers=DEFAULT_HEADERS,
                timeout=timeout,
                allow_redirects=True,
            )

            item["status_code"] = r.status_code
            item["content_length"] = len(r.content)
            item["content_type"] = (
                r.headers.get("Content-Type")
            )

            if r.status_code == 200:

                found = extract_api_candidates_from_js(
                    r.text,
                    r.url
                )

                item[
                    "endpoint_candidates"
                ] = found

                endpoints.update(found)
        
        except Exception as e:
            item["error"] = str(e)

        result["scripts"].append(item)
    
    result[
        "endpoint_candidates"
    ] = sorted(endpoints)

    return result

# ---------------------------------------------------------
# 7. helper 추가
# ---------------------------------------------------------

def interact_page(page, base_url, result):
    """
    안전한 UI 상호작용만 수행
    """

    safe_keywords = [
        r"\bcontact\b",
        r"\bsales?\b",
        r"\bpricing\b",
        r"\blearn\s+more\b",
        r"\blanguage\b",
        r"\bcountr(y|ies)\b",
        r"\bcookie\b",
        r"\bpreferences\b",
        r"\bstart\b",
        r"\bsign\s+up\b",
        r"\btry\b",
        r"\bdemo\b",
    ]

    dangerous_keywords = [
        r"\bdelete\b",
        r"\bremove\b",
        r"\blog\s*out\b",
        r"\bpurchase\b",
        r"\bbuy\b",
        r"\bcheckout\b",
        r"\bpay(?:ment)?\b",
        r"\bconfirm\b",
        r"\bsubmit\s+order\b",
    ]

    candidates = []

    interactions = []

    elements = page.locator(
        "button, a, [role='button']"
    )

    count = min(elements.count(), 300)

    for i in range(count):

        try:
            element = elements.nth(i)

            if not element.is_visible():
                continue
            
            original_text = (
                element.inner_text(timeout=500)
                or ""
            ).strip()

            text_lower = original_text.lower()

            if not original_text:
                continue
            
            if any(
                re.search(
                    pattern,
                    text_lower
                )
                for pattern in dangerous_keywords
            ):
                continue
            
            if any(
                re.search(
                    pattern,
                    text_lower
                )
                for pattern in safe_keywords
            ):
                candidates.append(original_text)
        
        except Exception:
            continue
    
    # 중복 제거
    candidates = list(dict.fromkeys(candidates))

    print(
        "\n[*] Interaction candidates"
    )

    for i, text in enumerate(
        candidates,
        start=1
    ):
        print(
            f"     [{i}] {text}"
        )
    
    print(
        f"[*] Total candidates: "
        f"{len(candidates)}"
    )

    for text in candidates[:15]:

        interaction = {
            "text": text,
            "clicked": False,
            "after_url": None,
            "api_before": len(
                result[
                    "api_candidates"
                ]
            ),
            "api_after": None,
            "new_api_count": 0,
            "error": None,
        }

        try:

            print(f"[*] click: {text}")

            locator = page.get_by_text(
                text,
                exact=True
            ).first

            locator.click(
                timeout=3000
            )

            interaction[
                "clicked"
            ] = True

            page.wait_for_timeout(1500)

            interaction[
                "after_url"
            ] = page.url

            interaction[
                "api_after"
            ] = len(
                result[
                    "api_candidates"
                ]
            )

            interaction[
                "new_api_count"
            ] = (
                interaction[
                    "api_after"
                ]
                -
                interaction[
                    "api_before"
                ]
            )

            print(
                "[+] click result: "
                f"new{text} | "
                f"new APIs: "
                f"{interaction['new_api_count']}"
            )

            # modal/dialog가 열렸으면 ESC로 닫기
            try:
                page.keyboard.press(
                    "Escape"
                )
            except Exception:
                pass

            page.wait_for_timeout(
                500
            )

            # 다른 페이지로 이동했다면 원래 페이지 복귀
            if page.url != base_url:
                page.goto(
                    base_url,
                    wait_until="domcontentloaded",
                    timeout=10000
                )

                page.wait_for_timeout(1000)
        
        except Exception as e:

            interaction[
                "error"
            ] = str(e)

            interaction[
                "after_url"
            ] = page.url

            interaction[
                "api_after"
            ] = len(
                result[
                    "api_candidates"
                ]
            )

            print(
                f"[!] interaction failed: "
                f"{text}: {e}"
            )
        
        interactions.append(
            interaction
        )
    
    return interactions

# ---------------------------------------------------------
# 8. Score 추가
# ---------------------------------------------------------

def score_api_candidate(item):
    score = 0

    method = (
        item.get("method")
        or ""
    ).upper()

    url = (
        item.get("url")
        or ""
    ).lower()

    resource_type = (
        item.get("resource_type")
        or ""
    ).lower()

    headers = item.get(
        "headers",
        {}
    ) or {}

    post_data = (
        item.get("post_data")
        or ""
    )

    # 실제 브라우저 fetch/xhr
    if resource_type in (
        "fetch",
        "xhr",
    ):
        score += 5
    
    # 상태 변경 가능성이 있는 메서드
    if method in (
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ):
        score += 3
    
    # API / GrapQL 경로
    if "/api/" in url:
        score += 4
    
    if "/graphql" in url:
        score += 4
    
    # 인증/세션/계정 관련
    if any(
        keyword in url
        for keyword in (
            "auth",
            "oauth",
            "session",
            "login",
            "account",
            "user",
            "profile",
            "admin",
            "token",
            "password",
        )
    ):
        score += 3
    
    # JSON 요청
    content_type = (
        headers.get("content-type")
        or headers.get("Content-Type")
        or ""
    ).lower()

    if "application/json" in content_type:
        score += 2
    
    # Request body 존재
    if post_data:
        score += 1
    
    # 외부 분석/광고 계열은 감점
    if any(
        keyword in url
        for keyword in (
            "google",
            "googletagmanager",
            "doubleclick",
            "facebook",
            "linkedin",
            "analytics",
            "adservice",
            "pagead",
        )
    ):
        score -= 5
    
    # telemetry / logging 계열 감점
    if any(
        keyword in url
        for keyword in (
            "logging",
            "metrics",
            "telemetry",
            "collect",
            "monorail",
        )
    ):
        score -= 3
    
    return score
# ---------------------------------------------------------
# 9. 전체 통합
# ---------------------------------------------------------

def analyze_web_surface(
    url,
    html=None,
    run_dynamic=True
):
    """
    최종 통합 함수
    """

    result = {
        "static": {
            "javascript": {
                "scripts": [],
                "endpoint_candidates": []
            }
        },

        "dynamic": {
            "network": {},
            "javascript": {
                "scripts": [],
                "endpoint_candidates": []
            }
        },
        
        "endpoint_candidates": []
    }

    all_endpoints = set()

    # -------------------------
    # Static
    # -------------------------

    if html is None:

        try:
            r = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=15,
                allow_redirects=True
            )

            html = r.text
            
            # redirect 후 URL 기준
            base_url = r.url

        except Exception as e:

            result["static"]["error"] = str(e)

            return result
        
    else:
        base_url = url
        
    static_js = analyze_javascript_assets(
        base_url,
        html
    )

    result["static"]["javascript"] = static_js

    all_endpoints.update(
        static_js.get(
            "endpoint_candidates",
            []
        )
    )

    # -------------------------
    # Dynamic
    # -------------------------

    if run_dynamic:

        dynamic_network = collect_dynamic_network(
            base_url
        )

        result["dynamic"][
            "network"
        ] = dynamic_network

        #fetch / xhr 자체가 endpoint 후보
        for api in dynamic_network.get(
            "api_candidates",
            []
        ):
            endpoint = api.get("url")

            if endpoint:
                all_endpoints.add(endpoint)
        
        # 실제 브라우저가 로딩한 JS 재분석
        dynamic_js = analyze_dynamic_javascript(
            dynamic_network.get(
                "javascript",
                []
            )
        )

        result["dynamic"][
            "javascript"
        ] = dynamic_js

        all_endpoints.update(
            dynamic_js.get(
                "endpoint_candidates",
                []
            )
        )
    
    result[
        "endpoint_candidates"
    ] = sorted(all_endpoints)

    return result

# =========================================================
# Main Scanner
# =========================================================

def analyze_domain(domain):

    print(
        f"\n[*] Target: {domain}"
    )

    #
    # DNS
    #
    print(
        "[*] DNS analysis..."
    )

    dns_info = resolve_dns(
        domain
    )

    #
    # CDN by CNAME
    #
    print(
        "[*] CDN analysis..."
    )
    cdn_dns = detect_cdn_from_cname(
        dns_info["cname"]
    )

    #
    # HTTP
    #
    print(
        "[*] HTTP fingerprinting..."
    )

    http_info = get_http_info(
        domain
    )

    #
    # CDN/WAF by HTTP
    #
    cdn_http = detect_edge_from_headers(
        http_info
    )

    #
    # TLS
    #
    print(
        "[*] TLS certificate analysis..."
    )

    tls_info = get_tls_info(
        domain
    )

    #
    # Technology
    #
    technologies = fingerprint_technology(
        http_info
    )

    #
    # Asset candidates
    #
    assets = extract_asset_candidates(
        domain,
        dns_info,
        tls_info
    )

    result = {

        "target": domain,

        "scan_time": datetime.now().isoformat(),

        "dns": dns_info,

        "edge": {
            "detected": bool(
                cdn_dns or cdn_http
            ),

            "evidence":
                cdn_dns + cdn_http
        },

        "http": http_info,

        "tls": tls_info,

        "technologies":
            technologies,

        "asset_candidates":
            assets
    }

    return result


# =========================================================
# Run
# =========================================================

if __name__ == "__main__":

    requests.packages.urllib3.disable_warnings()

    result = analyze_domain(
        TARGET_DOMAIN
    )

    print(
        "\n=============================="
    )

    print(
        "        SCAN RESULT"
    )

    print(
        "==============================\n"
    )

    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False
        )
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    safe_domain = TARGET_DOMAIN.replace(".", "_").replace("/", "_")

    filename = f"surface_{safe_domain}_{timestamp}.json"

    output = os.path.join(
        result_dir,
        filename
    )

    with open(
        output,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"\n[+] Saved: {output}"
    )
