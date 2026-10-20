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

TARGET_DOMAIN = "shopify.plus"

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
