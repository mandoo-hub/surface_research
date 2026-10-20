import os
import socket
import ssl
import json
import csv
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

import dns.resolver
import time
import requests

result_dir = "result"

os.makedirs(
    result_dir,
    exist_ok=True
)

TARGET_DOMAIN = "jusohot7.com"

HTTP_TIMEOUT = 5
DNS_TIMEOUT = 3
JS_TIMEOUT = 5

USER_AGENT = "SurfaceResearch/1.0"

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
                
                http_result["javascript"] = (
                    analyze_javascript_assets(
                        response.url,
                        response.text
                    )
                )
                
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
# JS Collect
# =========================================================


def extract_script_urls(base_url, html):
    """
    HTML에서 <script src="..."> 형태의 JS 자산 URL 수집
    """

    scripts = set()

    pattern = re.compile(
        # [^>]+ : >(태그 닫기)를 제외한 모든 문자 1개 이상을 허용
        # [^"\']+ : 큰따옴표나 작은따옴표가 아닌 문자 1개 이상 이어지는 구간을 그룹으로 지정하여 결과값으로 가져온다.
        # ["\'] : 시작으로 열었던 큰따옴표 또는 작은따옴표로 끝나는지 확인한다.
        # re.IGNORECASE : 대소문자 구별하지 않고 매칭함
        r'<script[^>]+src=["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    # 정규식 매칭결과(src 속성값)를 하나씩 순회한다.
    for match in pattern.findall(html):
        # 상대 경로(예: /js/app.js))를 기준 경로(https://example.com)과 결합하여 완전한 절대 URL(https://example.com/js/app.js)로 결합
        full_url = urljoin(base_url, match)
        # 중복을 자동으로 제거하기 위해 set(집합) 자료형에 추가
        scripts.add(full_url)

    # 중복이 제거된 URL들을 알파벳순으로 정렬하여 리스트(list)로 반환
    return sorted(scripts)


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


def extract_api_candidates_from_js(js_text, base_url):

    candidates = set()

    patterns = [
        # 절대 URL
        r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",

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
                re.IGNORECASE
            )

        except re.error as e:
            print(f"[!] Regex error")
            print(f"    pattern: {pattern}")
            print(f"    error: {e}")
            continue

        for match in matches:

            if isinstance(match, tuple):
                match = match[0]

            if not match:
                continue

            if (
                match.startswith("http://")
                or match.startswith("https://")
            ):
                candidates.add(match)

            else:
                candidates.add(
                    urljoin(base_url, match)
                )

    return sorted(candidates)


def analyze_javascript_assets(base_url, html):
    """
    페이지의 JS 자산을 다운로드하고 endpoint 후보 추출
    """

    script_urls = extract_script_urls(base_url, html)

    result = {
        "scripts": [],
        "endpoint_candidates": []
    }

    endpoint_set = set()

    for js_url in script_urls:

        print(f"[*] JS analysis: {js_url}")

        try:
            response = requests.get(
                js_url,
                timeout=JS_TIMEOUT,
                verify=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            if response.status_code != 200:
                result["scripts"].append({
                    "url": js_url,
                    "status_code": response.status_code
                })
                continue

            response.encoding = "utf-8"

            js_text = response.text

            endpoints = extract_api_candidates_from_js(
                js_text,
                js_url
            )

            endpoint_set.update(
                endpoints
            )

            result["scripts"].append({
                "url": js_url,
                "status_code": response.status_code,
                "content_length": len(
              response.content
                ),
                "endpoint_candidates": endpoints
            })

        except Exception as e:

            result["scripts"].append({
                "url": js_url,
                "error": str(e)
            })
    
    result["endpoint_candidates"] = sorted(
        endpoint_set
    )
    
    return result
    
# =========================================================
# Playwright를 이용한 동적 분석(length, jitter 검사/기록)
# =========================================================    

def collect_browser_observations(page_url):
    observations = []
    ws_connections = []
    ws_frames = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        attach_websocket_recorder(
            page,
            ws_connections,
            ws_frames,
        )
        
        started_at = {}
        
        def on_request(request):
            if request.resource_type not in {"fetch", "xhr", "eventsource"}:
                return
            
            started_at[id(request)] = time.perf_counter()
        
        def on_response(response):
            request = response.request
            
            if request.resource_type not in {"fetch", "xhr", "eventsource"}:
                return
            
            try:
                response_bytes = len(response.body())
            except Exception:
                response_bytes = None
            
            start = started_at.get(id(request))
            duration_ms = (
                round((time.perf_counter() - start) * 1000, 2)
                if start is not None
                else None
            )
            
            request_body = request.post_data_buffer
            
            observations.append({
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "request_body_bytes": (
                    len(request_body) if request_body else 0
                ),
                "response_body_bytes": response_bytes,
                "duration_ms": duration_ms,
            })
            
        page.on("request", on_request)
        page.on("response", on_response)
        
        page.goto(page_url, wait_until="domcontentloaded",
                  timeout=30000)
        page.wait_for_timeout(30000)
        browser.close()
        
    return {
    "browser_observations": observations,
    "ws_connections": ws_connections,
    "ws_frames": ws_frames,
    }

# =========================================================
# csv 파일 생성
# =========================================================    

def export_review_csv(result, json_path):
    """정적 URL과 브라우저 관찰 정보를 하나의 CSV로 저장한다."""

    rows = {}

    def add_url(
        url,
        found_as,
        source_url="",
        status_code=None,
        title="",
    ):
        if not isinstance(url, str) or not url.strip():
            return None

        url = url.strip()

        if url not in rows:
            rows[url] = {
                "found_as": set(),
                "source_urls": set(),
                "status_codes": set(),
                "titles": set(),
                "methods": set(),
                "resource_types": set(),
                "content_types": set(),
                "browser_observations": [],
                "ws_connections": [],
                "ws_frames": [],
            }

        row = rows[url]
        row["found_as"].add(found_as)

        if source_url:
            row["source_urls"].add(source_url)

        if status_code is not None:
            row["status_codes"].add(str(status_code))

        if title:
            row["titles"].add(title)

        return row

    # --------------------------------------------------
    # 1. 기존 정적 분석 결과
    # --------------------------------------------------
    for http_result in result.get("http", []):
        requested_url = http_result.get("url", "")
        final_url = http_result.get("final_url") or requested_url

        add_url(requested_url, found_as="시작 URL")

        if http_result.get("status_code") is not None:
            add_url(
                final_url,
                found_as="HTTP 응답 URL",
                source_url=requested_url,
                status_code=http_result.get("status_code"),
                title=http_result.get("title"),
            )

        for url in http_result.get("links", []):
            add_url(
                url,
                found_as="HTML 링크 또는 자산",
                source_url=final_url,
            )

        javascript = http_result.get("javascript", {})
        script_candidates = set()

        for script in javascript.get("scripts", []):
            script_url = script.get("url", "")

            add_url(
                script_url,
                found_as="JS 파일",
                source_url=final_url,
            )

            # 반드시 scripts 반복문 안에서 처리
            for url in script.get("endpoint_candidates", []):
                add_url(
                    url,
                    found_as="JS 내부 endpoint 후보",
                    source_url=script_url,
                )
                script_candidates.add(url)

        for url in javascript.get("endpoint_candidates", []):
            if url not in script_candidates:
                add_url(
                    url,
                    found_as="JS endpoint 집계 목록",
                    source_url=final_url,
                )

    # --------------------------------------------------
    # 2. Playwright HTTP 요청·응답 관찰 결과
    # --------------------------------------------------
    for observation in result.get("browser_observations", []):
        resource_type = observation.get("resource_type", "")

        row = add_url(
            observation.get("url", ""),
            found_as=f"브라우저 {resource_type or 'HTTP'} 응답",
            source_url=observation.get("source_url", ""),
            status_code=observation.get("status"),
        )

        if row is None:
            continue

        row["browser_observations"].append(observation)

        for source_key, target_key in [
            ("method", "methods"),
            ("resource_type", "resource_types"),
            ("content_type", "content_types"),
        ]:
            value = observation.get(source_key)
            if value:
                row[target_key].add(str(value))

    # --------------------------------------------------
    # 3. WebSocket 연결
    # --------------------------------------------------
    ws_url_by_id = {}

    for connection in result.get("ws_connections", []):
        url = connection.get("url", "")
        connection_id = connection.get("connection_id")

        if connection_id:
            ws_url_by_id[connection_id] = url

        row = add_url(
            url,
            found_as="브라우저 WebSocket 연결",
            source_url=connection.get("source_url", ""),
        )

        if row is not None:
            row["resource_types"].add("websocket")
            row["ws_connections"].append(connection)

    # --------------------------------------------------
    # 4. WebSocket 송수신 프레임
    # --------------------------------------------------
    for frame in result.get("ws_frames", []):
        url = frame.get("url") or ws_url_by_id.get(
            frame.get("connection_id"), ""
        )

        row = add_url(
            url,
            found_as="브라우저 WebSocket 송수신",
        )

        if row is not None:
            row["resource_types"].add("websocket")
            row["ws_frames"].append(frame)

    # 숫자 관측값이 없으면 빈 칸으로 출력
    def metric(observations, key, operation):
        values = [
            observation.get(key)
            for observation in observations
            if isinstance(observation.get(key), (int, float))
        ]
        return operation(values) if values else ""

    def join_values(values):
        return " | ".join(sorted(values))

    def safe_cell(value):
        value = str(value)
        if value.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    fields = [
        "id",
        "url",
        "found_as",
        "source_urls",
        "status_codes",
        "titles",
        "request_methods",
        "resource_types",
        "content_types",
        "browser_response_count",
        "request_body_bytes_min",
        "request_body_bytes_max",
        "response_body_bytes_min",
        "response_body_bytes_max",
        "duration_ms_min",
        "duration_ms_max",
        "ws_connection_count",
        "ws_sent_frames",
        "ws_received_frames",
        "ws_sent_bytes",
        "ws_received_bytes",
        "ws_json_keys",
        "ws_errors",
        "manual_type",
        "manual_function",
        "memo",
    ]

    csv_path = f"{os.path.splitext(json_path)[0]}_review.csv"

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for number, url in enumerate(sorted(rows), start=1):
            item = rows[url]
            observations = item["browser_observations"]

            sent = [
                frame for frame in item["ws_frames"]
                if frame.get("direction") == "sent"
            ]
            received = [
                frame for frame in item["ws_frames"]
                if frame.get("direction") == "received"
            ]

            json_keys = {
                str(key)
                for frame in item["ws_frames"]
                for key in (frame.get("json_keys") or [])
            }

            ws_errors = {
                str(connection["error"])
                for connection in item["ws_connections"]
                if connection.get("error")
            }

            row = {
                "id": number,
                "url": url,
                "found_as": join_values(item["found_as"]),
                "source_urls": "\n".join(sorted(item["source_urls"])),
                "status_codes": join_values(item["status_codes"]),
                "titles": join_values(item["titles"]),
                "request_methods": join_values(item["methods"]),
                "resource_types": join_values(item["resource_types"]),
                "content_types": join_values(item["content_types"]),
                "browser_response_count": len(observations),
                "request_body_bytes_min": metric(
                    observations, "request_body_bytes", min
                ),
                "request_body_bytes_max": metric(
                    observations, "request_body_bytes", max
                ),
                "response_body_bytes_min": metric(
                    observations, "response_body_bytes", min
                ),
                "response_body_bytes_max": metric(
                    observations, "response_body_bytes", max
                ),
                "duration_ms_min": metric(
                    observations, "duration_ms", min
                ),
                "duration_ms_max": metric(
                    observations, "duration_ms", max
                ),
                "ws_connection_count": len(item["ws_connections"]),
                "ws_sent_frames": len(sent),
                "ws_received_frames": len(received),
                "ws_sent_bytes": metric(sent, "payload_bytes", sum),
                "ws_received_bytes": metric(received, "payload_bytes", sum),
                "ws_json_keys": join_values(json_keys),
                "ws_errors": join_values(ws_errors),
                "manual_type": "",
                "manual_function": "",
                "memo": "",
            }

            writer.writerow({
                key: safe_cell(value)
                for key, value in row.items()
            })

    print(f"[+] Saved: {csv_path} ({len(rows)} URLs)")
    return csv_path

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
    
    # Playwright로 페이지 로드 중 발생한 fetch/XHR 요청 및 응답 수집
    browser_result = collect_browser_observations(
        f"https://{TARGET_DOMAIN}/"
    )

    result.update(browser_result)

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
    
    export_review_csv(result, output)
