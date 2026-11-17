"""URL defanging utility for safe presentation (plain Python, no Django)."""


def _split_authority(url_body: str) -> tuple[str, str]:
    """Split URL body into authority part and trailing path/query/fragment."""
    auth_end = len(url_body)
    for idx, char in enumerate(url_body):
        if char in ("/", "?", "#"):
            auth_end = idx
            break
    return url_body[:auth_end], url_body[auth_end:]


def _split_host_port(host_port: str) -> tuple[str, str]:
    """Split host and port suffix, supporting bracketed IPv6."""
    if host_port.startswith("[") and "]" in host_port:
        end_idx = host_port.index("]") + 1
        return host_port[:end_idx], host_port[end_idx:]
    if ":" in host_port:
        host, port = host_port.split(":", 1)
        return host, f":{port}"
    return host_port, ""


def defang_url(raw: str) -> str:
    """Defang URL by converting http->hxxp and replacing host dots with [.]."""
    if not raw:
        return ""

    if "://" in raw:
        scheme_part, url_body = raw.split("://", 1)
        is_http = scheme_part.lower().startswith("http")
        scheme_prefix = "hxxp" + scheme_part[4:] if is_http else scheme_part
        prefix = f"{scheme_prefix}://"
    else:
        prefix = ""
        url_body = raw

    authority, trailing = _split_authority(url_body)
    if "@" in authority:
        userinfo_part, host_port = authority.rsplit("@", 1)
        userinfo_prefix = f"{userinfo_part}@"
    else:
        userinfo_prefix = ""
        host_port = authority

    host, port_suffix = _split_host_port(host_port)
    defanged_host = host.replace(".", "[.]")

    result = f"{prefix}{userinfo_prefix}{defanged_host}{port_suffix}{trailing}"
    if result.lower().startswith("http"):
        result = "hxxp" + result[4:]
    return result
