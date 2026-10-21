# Surface Research

> **Public Web Attack Surface Discovery & Analysis**  
> 공개 웹 자산의 정적·동적 관측 정보를 수집하고, API·JavaScript·WebSocket 등 외부 공격표면을 분석하기 위한 Python 기반 연구 프로젝트입니다.

## 1. Project Overview

현대 웹 애플리케이션은 HTML과 JavaScript뿐 아니라 여러 API, CDN 및 실시간 통신 채널을 통해 동작합니다. 이 프로젝트는 공개적으로 관측 가능한 웹 자산과 연결 관계를 수집하여 **무엇이 노출되어 있는지, 어떤 근거로 발견되었는지, 실제 브라우저에서 어떤 통신이 관측되었는지**를 체계적으로 기록하는 것을 목표로 합니다.

현재 단계는 **공격표면 발견 및 관측 데이터 정리**에 초점을 맞춥니다. 인증 우회, CORS 오설정, 권한 취약점 등을 자동으로 확정하는 취약점 검증 도구는 아닙니다.

### 주요 목표

- DNS, TLS, HTTP 기반의 기초 외부 노출 정보 수집
- HTML 및 JavaScript에서 URL·endpoint 후보 추출
- Playwright 기반의 실제 `fetch`·`XHR`·`EventSource` 통신 관측
- WebSocket 연결 및 프레임의 메타데이터 수집
- 분석 결과를 JSON과 검토용 CSV로 저장
- 별도의 분류 스크립트에서 불필요한 URL과 API 후보 구분

## 2. Architecture

```text
                    [ Target Domain ]
                            |
             +--------------+--------------+
             |              |              |
        DNS / TLS       HTTP / HTML    Headless Browser
             |              |              |
        DNS Records      Links / JS     Fetch / XHR / SSE
        Certificate      JS URLs        WebSocket Events
             |              |              |
             +--------------+--------------+
                            |
                  [ Raw JSON Result ]
                            |
                  [ Review CSV Export ]
                            |
                  [ URL Classification ]
                  (별도 filtering.py)
                            |
                 [ Classified JSON Files ]
```

> **현재 구현 상태:** 수집기의 출력과 `filtering.py`의 입력 스키마는 일부 다릅니다. 위 흐름은 목표 파이프라인이며, 두 스크립트의 완전한 자동 연동은 추가 개발이 필요합니다.

## 3. Features

| 영역 | 구현 기능 | 비고 |
|---|---|---|
| DNS | A, AAAA, CNAME, MX, NS 조회 | DNSPython |
| TLS | 인증서 발급자, 유효기간, SAN, 협상 TLS 버전 및 암호 스위트 | Python `ssl` |
| HTTP | HTTP/HTTPS 응답, 리다이렉션, 상태 코드, 일부 보안·서버 헤더 | Requests |
| CDN / Edge | CNAME 및 HTTP 헤더 기반 제공자 추정 | 서명 기반의 휴리스틱 |
| HTML | `href`, `src`, `<script src>` 추출 | 정적 수집 |
| JavaScript | JS 파일 다운로드, 정규식 기반 URL·endpoint 후보 추출 | AST/Data Flow 분석은 미구현 |
| Browser | 브라우저가 실행한 `fetch`, `xhr`, `eventsource` 요청·응답 관측 | Playwright |
| WebSocket | 연결 URL, 송수신 프레임 크기·방향·JSON 최상위 키 수집 | 메시지 본문 저장 아님 |
| Report | 원본 JSON, 검토용 UTF-8-SIG CSV 생성 | CSV에 수동 검토 필드 포함 |
| URL Filtering | URL 정규화, 외부 서비스·정적 파일·API 유사 경로 분류 | 별도 스크립트 |

## 4. Repository Structure

```text
surface_research/
├── surface_attack_v3.py       # 웹 공격표면 수집 및 분석
├── filtering.py               # JSON URL 후보 후처리 및 분류
├── env_test.py                # 의존 패키지 확인
├── result/                    # 분석 결과 (로컬 생성)
└── README.md
```

실제 GitHub에 등록된 파일명에 맞게 구조 및 실행 명령어를 조정해 주세요. 업로드된 수집 스크립트의 파일명은 `surface_attack_v3(1).py`이며, 아래 예시는 저장소에서 `surface_attack_v3.py`로 정리한 경우입니다.

## 5. Installation

### Requirements

- Python 3.x
- Chromium 브라우저 실행이 가능한 환경
- 네트워크 접근 환경 (허가된 대상의 공개 정보 수집용)

```bash
# 저장소 복제 (실제 저장소 URL로 변경)
git clone https://github.com/<YOUR_USERNAME>/surface_research.git
cd surface_research

# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 필수 패키지 설치
python3 -m pip install requests beautifulsoup4 dnspython playwright

# Playwright Chromium 설치
python3 -m playwright install chromium

# 환경 확인
python3 env_test.py
```

> Linux 환경에서 Chromium 실행용 시스템 패키지가 부족하면 Playwright 공식 설치 안내에 따라 추가 의존성을 설치해야 할 수 있습니다.

## 6. Usage

### 6.1 공격표면 수집

현재 수집 대상 도메인은 `surface_attack_v3.py` 상단의 상수로 지정합니다.

```python
TARGET_DOMAIN = "example.com"  # 본인이 관리하거나 조사 허가를 받은 도메인
```

실행:

```bash
python3 surface_attack_v3.py
```

실행이 완료되면 다음 파일이 생성됩니다.

```text
result/
├── surface_example_com_YYYYMMDD_HHMMSS.json
└── surface_example_com_YYYYMMDD_HHMMSS_review.csv
```

현재 스크립트는 별도의 `--url` 옵션을 제공하지 않으므로, 대상 변경 시 `TARGET_DOMAIN` 값을 수정해야 합니다. 브라우저는 페이지 로드 후 약 30초 동안 추가 요청을 관측합니다. 이 수치는 실행시간 보장이 아니라 코드에 설정된 관측 대기시간입니다.

### 6.2 필터링 실행

`filtering.py`는 수집된 URL을 정규화하여 분석 후보와 비분석 대상을 구분합니다.

```bash
python3 filtering.py input.json --related example.com
```

여러 관련 도메인 지정:

```bash
python3 filtering.py input.json \
  --related example.com \
  --related example.net
```

명시적으로 허용된 테스트 도메인 지정:

```bash
python3 filtering.py input.json --scope example.com
```

결과 디렉터리 지정:

```bash
python3 filtering.py input.json --out filtered_result
```

**호환성 주의:** 현재 `filtering.py`는 주로 `http[].browser_analysis`, `http[].dynamic.network` 구조를 읽도록 작성되어 있습니다. 반면 현행 `surface_attack_v3.py`는 `http[].javascript`와 최상위 `browser_observations`, `ws_connections`, `ws_frames`를 출력합니다. 따라서 현재 수집기 JSON을 필터링기에 그대로 넣으면 후보 일부가 누락될 수 있습니다. 스키마 변환 또는 `collect_urls()` 확장이 필요합니다.

또한 현재 `filtering.py`는 입력 JSON의 `target`을 `--scope` 미지정 시 기본 범위에 추가하므로, 그 결과의 `approved_for_testing` 플래그를 실제 허가 증빙으로 사용하면 안 됩니다.

## 7. Output Examples

### JSON — 관측 정보 예시

```json
{
  "target": "example.com",
  "scan_time": "2026-10-21T10:00:00",
  "dns": {
    "domain": "example.com",
    "a": [],
    "aaaa": [],
    "cname": [],
    "mx": [],
    "ns": []
  },
  "http": [],
  "browser_observations": [
    {
      "url": "https://example.com/api/status",
      "method": "GET",
      "resource_type": "fetch",
      "status": 200,
      "request_body_bytes": 0,
      "response_body_bytes": 128,
      "duration_ms": 52.3,
      "content_type": "application/json"
    }
  ],
  "ws_connections": [],
  "ws_frames": []
}
```

> 위 값은 필드 구조 설명을 위한 **가상 예시**이며 실제 사이트를 조사한 결과가 아닙니다.

### CSV — 수동 검토

CSV에는 URL, 발견 유형, 출처, 응답 코드, HTTP 메서드, 리소스 유형, 본문 크기, 응답 관측 시간, WebSocket 프레임 통계와 수동 입력용 `manual_type`, `manual_function`, `memo` 필드가 포함됩니다.

### 필터링 분류 예시

| Category | 의미 |
|---|---|
| `API_CANDIDATE` | API 경로 패턴 또는 기존 수집기의 API 관측 분류와 일치 |
| `RELATED_UNVERIFIED` | 관련 도메인이나 검증 허용 여부 미확인 |
| `STATIC_RESOURCE` | JS, CSS, 이미지, 폰트 등 정적 파일 |
| `THIRD_PARTY` | 사전 정의된 외부 서비스 또는 코드에서 외부로 판단한 도메인 |
| `UNRESOLVED_DYNAMIC` | `${...}`, `{{...}}` 같은 동적 변수 포함 |
| `NOISE` | schema.org 등 표준 URL 또는 로컬 주소 |
| `OTHER_PAGE` | API로 판정되지 않은 일반 페이지 |

현재 카테고리는 규칙 기반 *추정 결과*이며, 취약점의 존재 또는 자산 소유권을 검증한 결과가 아닙니다.

## 8. Limitations & Known Issues

- **정적 분석의 한계:** 정규식 기반 URL 후보 추출이므로 API 호출 여부, 실제 동작, 인증·인가 관계를 확정할 수 없습니다. JavaScript 번들, 동적 URL, 요청 래퍼를 누락할 수 있습니다.
- **동적 분석의 한계:** 현재는 페이지를 로드하고 정해진 시간 동안 관측하며, 로그인·버튼 클릭·전체 페이지 탐색 등의 시나리오를 자동 수행하지 않습니다.
- **필터 스키마 차이:** 현행 수집기 JSON과 필터 입력 구조가 완전히 연결되지 않았습니다.
- **WebSocket:** 실시간 연결·프레임의 메타데이터를 수집하지만, 연결되지 않은 서비스의 존재를 증명하지는 못합니다. 현재 필터는 `ws://`, `wss://`에 대한 분류 지원을 별도로 보완해야 합니다.
- **HTTPS 검증 설정:** 현재 Requests 수집 코드에 `verify=False`가 있어 인증서 검증을 생략합니다. 실제 보안 검증 및 운영 사용 시 수정이 필요합니다.
- **정적 URL 패턴:** `extract_api_candidates_from_js()`의 정규식 목록 중 일부 항목에 쉼표 누락이 있어 패턴들이 결합될 수 있습니다. 탐지 품질 검증 전 수정이 필요합니다.
- **Scope 표기:** 도메인이 수집되거나 관련 도메인으로 식별되는 것과 보안 테스트 허가는 다릅니다.

## 9. Research Roadmap

- [x] DNS / TLS / HTTP 기본 정보 수집
- [x] HTML 및 JavaScript URL 후보 수집
- [x] Playwright를 통한 fetch / XHR / SSE 네트워크 관측
- [x] WebSocket 연결 및 프레임 메타데이터 관측
- [x] JSON 및 검토용 CSV 출력
- [x] 독립적인 규칙 기반 URL 분류 스크립트
- [ ] 수집기와 필터 간 JSON 스키마 통합
- [ ] WebSocket / SSE / 챗봇 API 후보 분류 개선
- [ ] AST 및 JavaScript 데이터 흐름 기반 API 의존관계 분석
- [ ] 실제 네트워크 관측과 정적 추론 결과의 교차 검증
- [ ] 인증·인가·CORS 검증 모듈 (승인된 환경에 한함)
- [ ] 공격표면 관계 그래프 및 변경 이력 분석
- [ ] 탐지 정확도와 오탐률 평가용 실험 환경 구축

## 10. Responsible Use

본 프로젝트는 보안 연구 및 방어적 자산 식별을 위해 제작되었습니다. **본인이 소유하거나 명시적으로 조사 및 테스트 허가를 받은 시스템에서만 사용하세요.** 발견된 URL, 관련 하위 도메인, 리다이렉션 대상은 자동으로 테스트 허용 범위에 포함되지 않습니다. 서비스에 과도한 부하를 주거나 계정·데이터에 영향을 주는 검증은 별도의 승인 없이 실행하지 마세요.

---

**Project status:** Research prototype / Work in Progress (WIP)
