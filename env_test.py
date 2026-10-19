import sys

packages = [
    ("requests", "requests"),
    ("BeautifulSoup", "bs4"),
    ("Playwright", "playwright.sync_api"),
    ("DNSPython", "dns.resolver"),
]

print("===패키지 작동 테스트===")

for name, module_str in packages:
    try:
        __import__(module_str)
        print(f"[성공] {name} 정상 작동")
    except ImportError:
        print(f"[실패] {name} 미설치 또는 오류")

print("\n-----------------")
print(f"파이썬 버전: {sys.version.split()[0]}")