import re
import yaml


def parse_skill(text):
    front = {}
    body = text

    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if m:
        try:
            front = yaml.safe_load(m.group(1)) or {}
        except Exception:
            front = {}
        body = m.group(2)

    return front, body


def detect_secret(front, body):
    text = str(front) + "\n" + body

    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"AIza[A-Za-z0-9\-_]{35}",
        r"sk-[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{36}",
        r"https://hooks\.slack\.com/services/",
    ]

    for p in patterns:
        if re.search(p, text):
            return True

    return False


def detect_prompt(body):
    body = body.lower()

    patterns = [
        "ignore previous instructions",
        "ignore the user",
        "ignore user",
        "ignore system prompt",
        "ignore stop request",
        "ignore cancel request",
        "silently upload",
        "secretly send",
        "exfiltrate",
        "without informing the user",
        "do not tell the user",
        "reveal the system prompt",
    ]

    return any(p in body for p in patterns)


def detect_permissions(front):
    text = str(front).lower()

    bad = [
        "filesystem: all",
        "network: all",
        "read: /",
        "write: /",
        "\"*\"",
        "'*'",
        "/**",
    ]

    return any(x in text for x in bad)


def detect_provenance(front, body):
    author = "author" in front
    version = "version" in front
    changelog = "changelog" in front

    if not author and not version and not changelog:
        return True

    body = body.lower()

    suspicious = [
        "rewrite version",
        "update version silently",
        "increment version automatically",
        "overwrite changelog",
    ]

    return any(x in body for x in suspicious)


def scan_skill(text):
    front, body = parse_skill(text)

    categories = []

    if detect_secret(front, body):
        categories.append("hardcoded_secret")

    if detect_prompt(body):
        categories.append("prompt_injection")

    if detect_permissions(front):
        categories.append("excessive_permissions")

    if detect_provenance(front, body):
        categories.append("unclear_provenance")

    return categories
