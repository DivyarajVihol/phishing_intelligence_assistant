# 05. Security rules (apply to every phase)

The app handles hostile URLs and makes outbound requests. Treat every URL as untrusted data.

## Never do
- Open, fetch or render a submitted URL in the MVP. Local checks work on the string only.
- Download or execute anything from a submitted destination.
- Make a submitted URL clickable or openable in any way (see the hard rule below).
- Log, print, render or store API keys. Keys come from `.env` only.
- Show stack traces or secrets to users (`DEBUG=False` outside local dev).

## Never let anyone open the submitted URL (hard rule)
- **Display:** every place a submitted URL appears (result, history, dashboard, report, error messages) uses `defang_url()` and plain text inside `<code>`.
- **Forbidden with submitted data** in templates and JS: `<a href>`, `src`, `action`, `formaction`, `<iframe>`, `<img>`, `<link>`, `<script src>`, `target="_blank"`, `<meta http-equiv="refresh">`, `window.open`, `location.href/assign/replace`, Django `urlize`, `mark_safe` / `|safe`. No auto-fetched favicons, screenshots or link previews.
- **Views:** never `redirect()` / `HttpResponseRedirect` to anything user-supplied. The only redirect allowed is internal (after POST, to the result page via `reverse()`). No `?next=` or `?url=` parameters.
- **No "Open site" button**, not even for Low observed risk. If the user wants the URL, offer "Copy defanged URL" only.
- **Redirect checker (Phase 13)** is the *server* reading headers. It never sends the user anywhere, and its hops are shown defanged.
- **JSON report:** includes `submitted_url_defanged`; the raw string appears only in a field named `submitted_url_raw`, documented as data and never rendered.
- **Test (every UI phase):** for pages at each risk level, assert no `href`/`src`/`action`/`formaction` attribute contains the submitted host or `hxxp`, no meta refresh, and a POST response only redirects to an internal path.

## Input handling
- Validate in `parse_url`: non-empty, <= `MAX_URL_LENGTH` (2048), only `http`/`https`, no control characters or whitespace inside.
- Django templates auto-escape. Do not use `|safe` or `mark_safe` on user-controlled data.
- CSRF protection stays on for the submit form.

## External lookups (PhishTank, URLhaus)
- Always: connect/read timeout from `EXTERNAL_TIMEOUT_SECONDS` (default 5), no unbounded retries, descriptive `User-Agent` for PhishTank.
- A PhishTank result is a match only when `in_database`, `verified` and `valid` are all true.
- Handle: timeout, connection error, HTTP 4xx/5xx, HTTP 509 / rate limit, invalid key, malformed JSON. Each becomes `status="unavailable"` with a short non-secret `error`.
- Keep the source's original fields in `detail`. Store source name, query time, status, record ID.
- Cache results with `LOOKUP_CACHE_TTL_SECONDS`. Cache key is a hash of the normalized URL + source.
- Tell the user on the submit page that URLs are sent to third-party intelligence services.

## Redirect checker (Phase 13) must satisfy ALL of these
- Disabled unless `ENABLE_REDIRECT_CHECK=True`.
- Resolve the hostname, then reject loopback, private, link-local, multicast, reserved and unspecified addresses (IPv4 and IPv6). Re-check **at every redirect hop**, and connect to the validated IP (guard against DNS rebinding).
- Max 5 redirects, 5 s timeout, HEAD/GET without downloading the body (`stream=True`, read no content), response-size cap, only http/https, no custom ports other than 80/443.
- Record every hop: source, destination, status code. Record why a URL was **not** fetched.
- Block `file://`, `ftp://`, `gopher://` and any non-http(s) scheme.

## DNS / RDAP (Phase 12)
- RDAP requests go only to the fixed host `rdap.org`. Validate the domain with a strict regex before inserting it into the URL path.
- DNS lookups use the validated registered domain only.

## Repo hygiene
`.env`, `db.sqlite3`, `ml/data/`, `.venv/` are git-ignored. Only `.env.example` (no real values) is committed.
