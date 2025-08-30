#!/usr/bin/env python3
import json
import os
import re
import sys
import textwrap
from typing import List, Tuple, Dict
import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.0"})
TIMEOUT = (5, 15)  # connect, read

UA_DOMAIN = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]]+"
UA_URL_RE = re.compile(UA_DOMAIN)

# Markdown forms that might wrap a URL
MD_IMAGE_RE_TMPL = r"!\[[^\]]*\]\(\s*{url}\s*\)"
MD_LINK_RE_TMPL  = r"\[[^\]]*\]\(\s*{url}\s*\)"

PNG_CT = {"image/png"}
ZIP_CT = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",  # sometimes used for zip
}

GH_API = "https://api.github.com"


def debug(msg: str):
    print(f"[sync] {msg}")


def event_payload() -> Dict:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.exists(path):
        print("No GITHUB_EVENT_PATH; exiting.")
        sys.exit(0)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def classify_url(url: str) -> str:
    """
    HEAD (fallback to GET stream) and classify by Content-Type / filename.
    Returns "png" / "zip" / "other".
    """
    try:
        # Prefer HEAD; some endpoints may not allow -> then fall back to GET(stream=True)
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        cd = r.headers.get("Content-Disposition", "")
        # crude filename sniff
        filename = ""
        m = re.search(r'filename\*=UTF-8\'\'([^;]+)', cd) or re.search(r'filename="?([^";]+)"?', cd)
        if m:
            filename = m.group(1)
        # decide
        if ct in PNG_CT or url.lower().endswith(".png") or filename.lower().endswith(".png"):
            return "png"
        if (ct in ZIP_CT and (url.lower().endswith(".zip") or filename.lower().endswith(".zip"))) or url.lower().endswith(".zip"):
            return "zip"
        # A few user-attachments for PNG/ZIP may come with octet-stream + opaque asset URL (no ext).
        if ct in PNG_CT:
            return "png"
        if ct in ZIP_CT and (filename.lower().endswith(".zip") or not filename):
            return "zip"
        return "other"
    except Exception as e:
        debug(f"HEAD/GET failed for {url}: {e}")
        return "other"


def extract_ua_urls(text: str) -> List[str]:
    if not text:
        return []
    # Find raw URLs. Markdown wrappers are handled when removing.
    urls = UA_URL_RE.findall(text)
    # Deduplicate preserving order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def remove_urls_from_body(body: str, urls_to_remove: List[str]) -> str:
    if not body or not urls_to_remove:
        return body or ""

    new_body = body
    for url in urls_to_remove:
        # Remove markdown image/link that contains the URL
        img_pat = re.compile(MD_IMAGE_RE_TMPL.format(url=re.escape(url)))
        lnk_pat = re.compile(MD_LINK_RE_TMPL.format(url=re.escape(url)))

        before = new_body
        new_body = img_pat.sub("", new_body)
        new_body = lnk_pat.sub("", new_body)
        # Remove bare URL occurrences
        new_body = re.sub(re.escape(url), "", new_body)

        # Clean leftover extra blank lines from removed blocks
        new_body = re.sub(r"\n{3,}", "\n\n", new_body).strip()

    return new_body.strip()


def build_insertion_block(pngs: List[str], zips: List[str]) -> str:
    lines = []
    # PNG first (each as an image)
    for p in pngs:
        lines.append(f"![thumbnail]({p})")
    # ZIPs next (raw URLs; minimal formatting)
    for z in zips:
        lines.append(z)
    return "\n".join(lines).strip()


def main():
    ev = event_payload()
    comment = ev.get("comment", {})
    issue = ev.get("issue", {})

    comment_body = comment.get("body") or ""
    issue_body = issue.get("body") or ""
    issue_number = issue.get("number")
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")

    if not (repo and token and issue_number):
        debug("Missing GITHUB_TOKEN / GITHUB_REPOSITORY / issue_number; exit.")
        sys.exit(0)

    # Only proceed if the comment actually contains user-attachments links
    comment_urls = extract_ua_urls(comment_body)
    if not comment_urls:
        debug("No user-attachments URLs in this comment; nothing to do.")
        sys.exit(0)

    # Classify URLs in the *comment* (source of truth to move)
    pngs, zips = [], []
    for url in comment_urls:
        kind = classify_url(url)
        if kind == "png":
            pngs.append(url)
        elif kind == "zip":
            zips.append(url)

    if not pngs and not zips:
        debug("No PNG/ZIP in the comment; nothing to move.")
        sys.exit(0)

    # From the current issue body, remove existing PNG/ZIP user-attachments links
    body_urls = extract_ua_urls(issue_body)
    body_png_zip = []
    for url in body_urls:
        kind = classify_url(url)
        if kind in ("png", "zip"):
            body_png_zip.append(url)

    cleaned_body = remove_urls_from_body(issue_body, body_png_zip)

    insertion = build_insertion_block(pngs, zips)
    if insertion:
        new_body = (insertion + "\n\n" + cleaned_body).strip()
    else:
        new_body = cleaned_body

    # Avoid useless PATCH if unchanged
    if new_body.strip() == issue_body.strip():
        debug("Body unchanged; skipping PATCH.")
        sys.exit(0)

    # PATCH issue body
    url = f"{GH_API}/repos/{repo}/issues/{issue_number}"
    resp = SESSION.patch(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"body": new_body},
        timeout=TIMEOUT,
    )
    if resp.status_code >= 300:
        debug(f"Failed to update issue body: {resp.status_code} {resp.text}")
        # Exit non-zero so the job shows as failed; your call
        sys.exit(1)

    debug("Issue body updated successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
