from urllib.parse import urlparse

THIRD_PARTY = {
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "instagram.com",
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
}

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg",
    ".jpeg", ".svg", ".woff", ".woff2",
    ".gif", ".webp"
)