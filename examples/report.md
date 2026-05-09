# log-analyzer report

- **Source:** `examples\sample.log`
- **Generated at:** 2026-05-09T21:15:40.245686+00:00
- **Total entries:** 1,000

## Top IP addresses

_283 unique IPs across 1,000 requests; top 10 shown_

| # | IP | Requests |
| -:| -- | -------:|
| 1 | `137.151.10.58` | 21 |
| 2 | `211.210.116.95` | 13 |
| 3 | `222.120.10.236` | 13 |
| 4 | `197.94.180.21` | 12 |
| 5 | `165.26.36.142` | 11 |
| 6 | `12.183.47.226` | 11 |
| 7 | `217.216.21.42` | 11 |
| 8 | `195.234.98.230` | 11 |
| 9 | `198.231.67.82` | 11 |
| 10 | `112.139.111.118` | 10 |

## HTTP status codes

_1,000 requests across 11 distinct status codes_

| Code | Count |
| ---: | ----: |
| 200 | 782 |
| 301 | 24 |
| 302 | 21 |
| 304 | 65 |
| 400 | 1 |
| 401 | 17 |
| 403 | 17 |
| 404 | 58 |
| 500 | 12 |
| 502 | 1 |
| 503 | 2 |

## Top 404 / Not Found paths

_58 responses with status 404 across 34 unique paths_

| # | Path | Hits |
| -:| ---- | ---:|
| 1 | `/` | 6 |
| 2 | `/static/css/main.css` | 5 |
| 3 | `/api/v1/products` | 4 |
| 4 | `/static/img/logo.svg` | 3 |
| 5 | `/tmp` | 2 |
| 6 | `/feed.rss` | 2 |
| 7 | `/wp-login.php` | 2 |
| 8 | `/.aws/credentials` | 2 |
| 9 | `/metrics` | 2 |
| 10 | `/.env` | 2 |

## Server errors (5xx)

_15 5xx responses across 14 (path, code) pairs_

| # | Path | Code | Hits |
| -:| ---- | ---:| ---:|
| 1 | `/blog` | 500 | 2 |
| 2 | `/static/js/app.js` | 500 | 1 |
| 3 | `/favicon.ico` | 500 | 1 |
| 4 | `/metrics` | 500 | 1 |
| 5 | `/products` | 500 | 1 |
| 6 | `/static/img/hero.jpg` | 500 | 1 |
| 7 | `/` | 500 | 1 |
| 8 | `/static/css/main.css` | 500 | 1 |
| 9 | `/favicon.ico` | 503 | 1 |
| 10 | `/api/v1/products` | 502 | 1 |

## Suspicious requests

_29 suspicious requests across 7 categories_

| Severity | Category | Hits | Example |
| -------- | -------- | ---: | ------- |
| **CRITICAL** | config-leak | 10 | `163.135.97.183 GET /.git/HEAD` |
| **CRITICAL** | sql-injection | 2 | `160.119.88.220 - GET /search` |
| **CRITICAL** | shellshock | 2 | `187.167.147.156 GET /config.php.bak` |
| **HIGH** | admin-probe | 5 | `187.167.147.156 GET /wp-login.php` |
| **HIGH** | xss | 3 | `75.48.69.25 - GET /comment` |
| **MEDIUM** | bad-user-agent | 27 | `163.135.97.183 GET /server-status` |
| **MEDIUM** | dirbuster | 7 | `163.135.97.183 GET /server-status` |

## User agents

_1,000 requests across 15 browser families (20 distinct UA strings)_

| Browser family | Requests |
| -------------- | -------: |
| Chrome | 354 |
| Safari | 142 |
| Firefox | 113 |
| Mobile Safari | 100 |
| Edge | 96 |
| Chrome Mobile | 59 |
| Googlebot | 45 |
| bingbot | 24 |
| Other | 21 |
| YandexBot | 16 |

## Traffic by hour (UTC)

_1,000 requests; peak hour 14:00 UTC with 63 hits_

| Hour (UTC) | Requests |
| ---------: | -------: |
| 00:00 | 28 |
| 01:00 | 21 |
| 02:00 | 25 |
| 03:00 | 22 |
| 04:00 | 25 |
| 05:00 | 36 |
| 06:00 | 31 |
| 07:00 | 47 |
| 08:00 | 50 |
| 09:00 | 49 |
| 10:00 | 48 |
| 11:00 | 60 |
| 12:00 | 58 |
| 13:00 | 52 |
| 14:00 | 63 |
| 15:00 | 45 |
| 16:00 | 51 |
| 17:00 | 50 |
| 18:00 | 40 |
| 19:00 | 53 |
| 20:00 | 34 |
| 21:00 | 33 |
| 22:00 | 44 |
| 23:00 | 35 |
