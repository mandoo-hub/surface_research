"""
1. argparse(모듈) : CLI를 구축할 때 사용하는 모듈. 즉, 사용자가 스크립트 실행 시 입력한 파라미터(--input, -v 등)를 쉽게 처리하고, --help 도움말 메시지를 자동을 생성해준다.
2. html(모듈) : HTML 문서 안에서 사용되는 특수 문자와 엔티티를 변환·처리하는 모듈이다. 즉, <, >, &와 같은 문자를 HTML 엔티티(&lt;, &gt;, &amp;)로 이스케이프하거나, 반대로 복원할 때 사용한다.
3. json(모듈) : JSON 형식의 데이터를 파이썬 객체와 상호 변환(직렬화/역직렬화)하는 모듈이다.
4. re(모듈) : 파이썬에서 정규 표현식을 지원하는 모듈이다.
5. collections.Counter(클래스) : 리스트나 문자열 등에서 각 원소가 몇 번 등장했는지 자동으로 세어주며, 가장 많이 등장한 원소를 순서대로 반환해주는 most_common() 메서드 등을 제공한다.
6. pathlib.Path(클래스) : 기존의 문자열 기반 경로 조작 방식(os.path)을 대신하여, 슬래시(/) 연산자로 경로를 손쉽게 조합하고 파일 존재 여부 확인, 확장자 추출, 파일 읽기/쓰기를 직관적으로 수행한다.
7. urllib.parse.urlparse(클래스) : 하나의 URL을 입력받아 프로토콜(Scheme), 도메인(Netloc), 경로(Path), 쿼리(Query) 등으로 쪼개어 분석할 때 사용한다.
"""
import argparse
import html
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlsplit, parse_qsl, urlencode, urlunsplit


THIRD_PARTY = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "googletagmanage.com",
    "google-analytics.com",
    "doubleclick.net",
    "googleadservices.com",
    "gstatic.com",
    "googlesydication.com",
    "hotjar.com",
    "segment.io",
    "newrelic.com",
}

NOISE_HOSTS = {
    "schema.org",
    "www.w3.org",
    "w3.org",
    "localhost",
    "127.0.0.1",
    "0.0.0.0"
}

STATIC_EXT = {
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".avif",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".webm",
    ".pdf",
    ".mp3",
    ".otf"
}

TRACKING_PARAMETERS = {
    "fbclid",
    "gclid",
    "dclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content"
}

# 조건 1 : (api|graphql|graphiql|rest|rpc|v[0-9]+)로 시작하거나 앞에 "/"가 있어야할것. 또한, 뒤에 "/"가 나오거나 문자열의 끝일 것.
# 조건 2 : (auth|oauth|session|token|login|logout|users|account|orders|checkout|payments|admin) 앞에 "/"가 나오고 해당 문자열 뒤에 "/"가 나오거나 끝일 것.
# 대소문자 상관없음(re.I 옵션)
API_PATTERN = re.compile(
    r"(^|/)(api|graphql|graphiql|rest|rpc|v[0-9]+)(/|$)"
    r"|/(auth|oauth|session|token|login|logout|users|account|orders|checkout|payments|admin)(/|$)",
    re.I,
)

# 같은 도메인이거나 해당 도메인의 하위 도메인인지 판단한다.
def match(host, domain):
    
    if host == domain:
        return True

    if host.endswith("." + domain):
        return True
    
    return False

# 주어진 도메인 목록에 host가 속하는지 확인
def matches_any_domain(host, domains):

    for domain in domains:
        if match(host, domain):
            return True
    return False

# URL 정리 : HTML 이스케이프, 기본 포트, 중복 슬래시, 추적 파라미터 제거
def normalize_url(raw_url):

    # raw_url이 문자열이 아니면 함수를 끝냄
    if not isinstance(raw_url, str):
        return ""
    
    url = html.unescape(raw_url)
    url = url.strip()
    url = url.strip("\\\"'")
    url = url.strip("\"'")

    if not url:
        return None
    
    ignored_prefixes = ("#", "javascript:", "data", "mailto", "tel:")
    if url.startswith(ignored_prefixes):
        return None
    
    # 템플릿 변수(ex. ${...} or {{...}})가 들어간 URL은 호스트를 임의로 추측하지 않고 그대로 저장한다.
    if "${" in url or "{{" in url:
        return url

    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        
        if scheme not in ("http", "https"):
            return None

        if not parts.hostname:
            return None
        
        # scheme = https, http / hostname = "www" / domain : example.com / host : www.example.com
        host = parts.hostname.lower().rstrip(".")

        # 기본 포트(HTTP: 80, HTTPS: 443)는 URL에서 생략
        port_text = ""
        if parts.port:
            if scheme == "https":
                defualt_portt = 443
            else:
                defualt_portt = 80
        
            if parts.port != defualt_portt:
                port_text = f":{parts.port}"
    
        netloc = host + port_text
        path = parts.path
    
        # path가 없으면 "/" 추가
        if not path:
            path = "/"
    
        # "/"가 여러개 있으면 "/" 하나로 수정
        # 끝에 있는 path는 원본 path를 말함 
        path = re.sub(r"/+", "/", path)

        # 추적용 파라미터를 제외하고 나머지는 정렬하여 유지
        # 형태는 딕셔너리가 아니라 (key, value) 튜플 리스트이다.
        # 예: filtered_parameters = [(key, value), (key, value), ...]
        filtered_parameters = []
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    
        for key, value in query_pairs:
            if key.lower() in TRACKING_PARAMETERS:
                continue
        
            filtered_parameters.append((key, value))
    
            # 정렬
            filtered_parameters.sort()
        # filtered_parameters의 정렬값을 다시 합친다. 예) ('q','shoes'), ('page','2')이면 q=shoes&page=2
        query = urlencode(filtered_parameters, doseq=True)
        # 조각낸 것을 다시 하나로 합친다.
        # 마지막 ""는 # 뒤 fragment인데, fragment를 비우라는 의미이다. 예를들어 https://example.com/path?q=1#reviews 이면 # 뒤를 제거하라는 의미이다.
        # fragment란 서버로 전송되지 않는 영역이며, 페이지 내부 HTML 문서 내에서 고유 ID(id="...")를 가진 요소나 위치를 가리키는 페이지 내부의 이정표 역할을 한다.
        normalized = urlunsplit((scheme, netloc, path, query, ""))

        # 기존 코드와 동일하게 쿼리가 없는 도메인 루트의 마지막 /만 생략한다.
        # filtered_parameters는 URL에서 쿼리부분을 의미한다.
        if path == "/" and not filtered_parameters:
            normalized = normalized.rstrip("/")

        return normalized
    
    # ValueError : 값이 왔는데 형식이 틀림
    # TypeError : 타입이 안맞음
    # try 안에서 URL을 파싱 및 조립하다가 타입/값 오류가 나면 예외를 삼키고 None을 반환한다. 전체 필터가 멈추지 않게 하는 가드 역할
    except (TypeError, ValueError):
        return None

# URL 분류
def classify_url(url, source_types, scopes, related_domains):
    #(분류명, 분류 사유)를 반환한다. 실제 취약점을 판정하지는 않는다.
    if "${" in url or "{{" in url:
        return "UNRESOLVED_DYNAMIC", "runtime_variable"
    
    parts = urlsplit(url)
    host = parts.hostname or ""
    host = host.lower()
    path = parts.path.lower()

    if matches_any_domain(host, NOISE_HOSTS):
        return "NOISE", "specification_or_localhost"

    if matches_any_domain(host, THIRD_PARTY):
        return "THIRD_PARTY", "external_service"
    
    # suffix 는 확장자(.js, .PNG, .gz 등)를 말한다.
    extension = Path(path).suffix.lower()
    if extension in STATIC_EXT:
        return "STATIC_RESOURCE", "static_asset"
    
    # 검증 허용 범위와 단순 관련 도메인을 구분한다.
    if matches_any_domain(host, scopes):
        scope_status = "IN_SCOPE"
    elif matches_any_domain(host, related_domains):
        scope_status = "RELATED_UNVERIFIED"
    else:
        scope_status = "OUT_OF_SCOPE"
    
    # API 후보 확인
    api_path_found = API_PATTERN.search(path) is not None
    
    api_observed = False

    if "observed_api" in source_types:
        api_observed = True

    if api_path_found or api_observed:

        if scope_status == "IN_SCOPE":
            return "API_CANDIDATE", "api_pattern_or_observed"

        return scope_status, "api_like_outside_approved_scope"

    # 일반 외부 도메인
    if scope_status == "OUT_OF_SCOPE":
        return "THIRD_PARTY", "other_external_domain"
    
    # 관련 도메인
    if scope_status == "RELATED_UNVERIFIED":
        return "RELATED_UNVERIFIED", "related_domain_unverified"
    
    # 일반 페이지
    return "OTHER_PAGE", "non_api_page_or_unknown"

# 중복 URL을 합치면서 발견 출처 기록
def collect_urls(document):
    # JSON의 HTTP/브라우저/JS/네트워크 결과에서 URL을 추출
    found = {}

    def add_url(raw_url, source, source_type="generic", method=None):
        url = normalize_url(raw_url)
        if not url:
            return

        if url not in found:
            found[url] = {
                "url": url,
                "sources": set(),
                "source_types": set(),
                "methods": set(),
                "observations": 0,
            }
        
        record = found[url]
        record["sources"].add(source)
        record["source_types"].add(source_type)
        record["observations"] += 1

        if method:
            record["methods"].add(str(method).upper())
    
    http_results = document.get("http", [])
    # enumerate(http_results) : 목록을(순서, 항목)으로 돈다. ex) http_index -> 0, 1, 2 ... / http_result -> 그 칸의 HTTP 결과 객체
    for http_index, http_result in enumerate(http_results):
        if not isinstance(http_result, dict):
            continue
        
        # 몇번째 항목에서 나왔는지 찾기위한 표시. 예) http[0], http[1] ... 등
        prefix = f"http[{http_index}]"

        for url in http_result.get("links", []):
            add_url(url, prefix + ".links")
        
        browser = http_result.get("browser_analysis") or {}
        for url in browser.get("endpoint_candidates", []):
            add_url(url, prefix + ".browser_analysis.endpoint_candidates")
        
        # 정적 JS 후보
        static_analysis = browser.get("static") or {}
        static_js = static_analysis.get("javascript") or {}
        collect_js_urls(static_js, prefix + ".static.javascript", add_url)

        # 실제 브라우저 네트워크 요청
        dynamic_analysis = http_result.get("dynamic") or {}
        network = dynamic_analysis.get("network") or {}
        requests = network.get("requests", [])
        for request_index, request in enumerate(requests):
            if not isinstance(request, dict):
                continue
            
            resource_type = str(request.get("resource_type", "")).lower()
            api_resource_types = ("fetch", "xhr", "websocket", "eventsource")

            if resource_type in api_resource_types:
                source_type = "network_request"
            else:
                source_type = "network_resource"
            
            source = f"{prefix}.dynamic.network.requests[{request_index}]"
            add_url(request.get("url"), source, source_type, request.get("method"))
        
        # 분석 코드가 이미 API라고 분류한 네트워크 후보
        api_candidates = network.get("api_candidates", [])
        for candidates_index, candidate in enumerate(api_candidates):
            source = f"{prefix}.dynamic.network.api_candidates[{candidates_index}]"

            if isinstance(candidate, str):
                add_url(candidate, source, "observed_api")
            elif isinstance(candidate, dict):
                add_url(candidate.get("url"), source, "observed_api", candidate.get("method"))
    
    return found

# 정적·동적 JS 결과에 공통으로 적용되는 URL 수집 부분
def collect_js_urls(js_analysis, prefix, add_url):
    
    # inferred : 추론
    for url in js_analysis.get("endpoint_candidates", []):
        add_url(url, prefix + ".endpoint_candidates", "js_inferred")
    
    scripts = js_analysis.get("scripts", [])
    
    for script_index, script in enumerate(scripts):
        if not isinstance(script, dict):
            continue

        source = f"{prefix}.scripts[{script_index}]"
        add_url(script.get("url"), source + ".url", "script")

        for url in script.get("endpoint_candidates", []):
            add_url(url, source + ".endpoint_candidates", "js_inferred")

# JSON 파일 저장
def save_json(path, data):

    text = json.dumps(
        data,
        indent = 2,
        ensure_ascii=False
    )

    path.write_text(text, encoding = "utf-8")

def main():
    
    parser = argparse.ArgumentParser(description="수집된 웹 URL/API 후보를 오프라인으로 분류")
    parser.add_argument("input", help="분석 결과 JSON 파일")
    parser.add_argument("--out", default=None, help="결과 폴더")
    parser.add_argument("--scope", action="append", default=[], help="승인된 대상 도메인 (반복 가능)")
    parser.add_argument("--related", action="append", default=[], help="관련 도메인 (범위 승인과 별개)")
    args = parser.parse_args()

    input_file = Path(args.input)
    document = json.loads(input_file.read_text(encoding="utf-8-sig"))
    target = str(document.get("target", "")).lower().strip()

    scopes = []

    for domain in args.scope:
        domain = domain.lower().strip()

        if domain:
            scopes.append(domain)

    if not scopes and target:
        scopes.append(target)
    

    related_domains = []
    
    for domain in args.related:
        domain = domain.lower().strip()

        if domain:
            related_domains.append(domain)

    if args.out:
        output_dir = Path(args.out)
    else:
        output_dir = input_file.with_name(input_file.stem + "_filtered")
    output_dir.mkdir(parents=True, exist_ok=True)

    collected = collect_urls(document)
    rows = []
    for url, record in collected.items():
        category, reason = classify_url(url, record["source_types"], scopes, related_domains)
        row = {
            "url": url,
            "category": category,
            "reason": reason,
            "sources": sorted(record["sources"]),
            "source_types": sorted(record["source_types"]),
            "methods": sorted(record["methods"]),
            "observations": record["observations"],
            "approved_for_testing": category == "API_CANDIDATE",
        }
        rows.append(row)

    rows.sort(key=lambda item: (item["category"], item["url"]))
    groups = {}
    
    for row in rows:
        category = row["category"]
        if category not in groups:
            groups[category] = []
        
        groups[category].append(row)
    
    save_json(output_dir / "classified_all.json", rows)

    for category, group_rows in sorted(groups.items()):
        filename = category.lower() + ".json"
        save_json(output_dir / filename, group_rows)
    
    category_counts = Counter()
    for row in rows:
        category_counts[row["category"]] += 1
    
    summary = {
        "input": str(input_file),
        "target": target,
        "authorized_scope": scopes,
        "related_unverified": related_domains,
        "total_unique": len(rows),
        "categories": dict(category_counts),
        "note": "Heuristic classification only; no HTTP requests, access testing, or ownership verification.",
    }

    save_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent = 2))
    print("Output:", output_dir)


if __name__ == "__main__":
    main()
