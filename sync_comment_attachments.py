#!/usr/bin/env python3
import json, os, re, sys
from typing import List, Tuple, Dict, Optional
import requests
from urllib.parse import urlparse

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.3"})
TIMEOUT = (5, 15)

UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]]+"
UA_URL_RE = re.compile(UA_URL)

# [テキスト](URL) と ![alt](URL) から URL→ラベル を取る
MD_LINK_MAP_RE  = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")

PNG_CT = {"image/png"}
ZIP_CT  = {"application/zip","application/x-zip-compressed","application/octet-stream"}

GH_API = "https://api.github.com"

def debug(msg: str): print(f"[sync] {msg}")

def event_payload() -> Dict:
    p = os.environ.get("GITHUB_EVENT_PATH")
    if not p or not os.path.exists(p): sys.exit(0)
    with open(p, "r", encoding="utf-8") as f: return json.load(f)

def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment"

def parse_cd(cd: str) -> Optional[str]:
    if not cd: return None
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m: return m.group(1)
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd)
    if m: return m.group(1)
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m: return m.group(1).strip()
    return None

def classify(url: str) -> str:
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        u  = url.lower()
        if ct in PNG_CT or u.endswith(".png"): return "png"
        if (ct in ZIP_CT and (u.endswith(".zip") or "assets" in u)) or u.endswith(".zip"): return "zip"
        if ct in PNG_CT: return "png"
        if ct in ZIP_CT: return "zip"
        return "other"
    except Exception as e:
        debug(f"classify failed for {url}: {e}")
        return "other"

def extract_comment_maps(text: str) -> Tuple[List[str], Dict[str,str]]:
    link_text_map: Dict[str,str] = {}
    for m in MD_LINK_MAP_RE.finditer(text or ""):
        label, url = m.group(1), m.group(2); link_text_map[url] = label
    for m in MD_IMAGE_MAP_RE.finditer(text or ""):
        alt,   url = m.group(1), m.group(2)
        if alt: link_text_map.setdefault(url, alt)  # alt も”表示名候補”として使う
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u); urls.append(u)
    return urls, link_text_map

def extract_ua_urls(text: str) -> List[str]:
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u); urls.append(u)
    return urls

def remove_urls_from_body(body: str, urls: List[str]) -> str:
    if not body or not urls: return body or ""
    nb = body
    for url in urls:
        nb = re.sub(rf"!\[[^\]]*\]\(\s*{re.escape(url)}\s*\)", "", nb)
        nb = re.sub(rf"\[[^\]]*\]\(\s*{re.escape(url)}\s*\)", "", nb)
        nb = re.sub(re.escape(url), "", nb)
    nb = re.sub(r"\n{3,}", "\n\n", nb).strip()
    return nb

def build_insertion_block(
    png: Optional[Tuple[str,str]],
    zips: List[Tuple[str,str]],
) -> str:
    lines: List[str] = []
    if png:
        url, name = png
        alt = (name or "thumbnail").strip().strip('"').strip("'")
        lines.append(f"![{alt}]({url})")
    for url, name in zips:
        label = (name or guess_name_from_url(url)).strip().strip('"').strip("'")
        lines.append(f"[{label}]({url})")
    return "\n".join(lines).strip()

def main():
    ev = event_payload()
    comment = ev.get("comment", {})
    issue   = ev.get("issue",   {})

    comment_body = comment.get("body") or ""
    issue_body   = issue.get("body") or ""
    issue_number = issue.get("number")
    repo  = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not (repo and token and issue_number): sys.exit(0)

    # コメントから URL と URL→表示名候補のマップ
    urls, label_map = extract_comment_maps(comment_body)
    if not urls: sys.exit(0)

    # 先頭PNGを1枚だけ拾う。ZIPはすべて拾う（順序保持）
    picked_png: Optional[Tuple[str,str]] = None
    zips: List[Tuple[str,str]] = []

    for url in urls:
        kind = classify(url)
        if kind == "png" and picked_png is None:
            # PNG の表示名は：コメントラベル > ヘッダ名 > URL末尾
            name = label_map.get(url)
            if not name:
                try:
                    r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
                    if r.status_code >= 400 or not r.headers:
                        r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
                    name = parse_cd(r.headers.get("Content-Disposition") or "") or guess_name_from_url(url)
                except Exception:
                    name = guess_name_from_url(url)
            picked_png = (url, name)
        elif kind == "zip":
            name = label_map.get(url)
            if not name:
                try:
                    r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
                    if r.status_code >= 400 or not r.headers:
                        r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
                    name = parse_cd(r.headers.get("Content-Disposition") or "")
                except Exception:
                    name = None
            zips.append((url, name or guess_name_from_url(url)))

    if not picked_png and not zips: sys.exit(0)

    # 本文から既存の PNG/ZIP user-attachments を全除去
    body_urls = extract_ua_urls(issue_body)
    targets = []
    for u in body_urls:
        if classify(u) in ("png","zip"):
            targets.append(u)
    cleaned_body = remove_urls_from_body(issue_body, targets)

    # 先頭に PNG（あれば）→ ZIP 群を挿入
    insertion = build_insertion_block(picked_png, zips)
    new_body = (insertion + "\n\n" + cleaned_body).strip() if insertion else cleaned_body
    if new_body.strip() == issue_body.strip(): sys.exit(0)

    # 本文更新
    api = f"{GH_API}/repos/{repo}/issues/{issue_number}"
    resp = SESSION.patch(
        api,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"body": new_body},
        timeout=TIMEOUT,
    )
    if resp.status_code >= 300:
        debug(f"Failed to update issue body: {resp.status_code} {resp.text}")
        sys.exit(1)
    debug("Issue body updated successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
