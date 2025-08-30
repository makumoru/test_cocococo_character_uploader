#!/usr/bin/env python3
import json
import os
import re
import sys
from typing import List, Tuple, Dict, Optional
import requests
from urllib.parse import urlparse

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.3"})
TIMEOUT = (5, 15)

# user-attachments の URL を拾う
UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]]+"
UA_URL_RE = re.compile(UA_URL)

# コメント本文から [テキスト](URL) / ![alt](URL) / <img src="URL"> を抽出
MD_LINK_MAP_RE  = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")
HTML_IMG_RE     = re.compile(rf'<img[^>]+src="({UA_URL})"[^>]*>')

PNG_CT = {"image/png"}
ZIP_CT = {"application/zip", "application/x-zip-compressed", "application/octet-stream"}

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


def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment"


def parse_content_disposition(cd: str) -> Optional[str]:
    if not cd:
        return None
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m: return m.group(1)
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd)
    if m: return m.group(1)
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m: return m.group(1).strip()
    return None


def classify(url: str) -> str:
    """png/zip/other を判定（HEAD→GET(stream)）"""
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        low = url.lower()
        if ct in PNG_CT or low.endswith(".png"): return "png"
        if (ct in ZIP_CT and (low.endswith(".zip") or "assets" in low)) or low.endswith(".zip"):
            return "zip"
        if ct in PNG_CT: return "png"
        if ct in ZIP_CT: return "zip"
        return "other"
    except Exception as e:
        debug(f"HEAD/GET failed for {url}: {e}")
        return "other"


def extract_comment_maps(text: str) -> Tuple[List[str], Dict[str, str]]:
    """
    返り値:
      - urls: コメント内の user-attachments URL（順序保持・重複除去）
      - link_text_map: URL -> [テキスト]（ZIPの表示名に使う。PNGには使わない）
    """
    link_text_map: Dict[str, str] = {}

    for m in MD_LINK_MAP_RE.finditer(text or ""):
        label, url = m.group(1), m.group(2)
        link_text_map[url] = label

    # <img src="..."> も URL として拾えるよう総当たりで抽出
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            urls.append(u)
    # HTML <img> にのみ埋まっている URL も重複管理しつつ追加
    for m in HTML_IMG_RE.finditer(text or ""):
        u = m.group(1)
        if u not in seen:
            seen.add(u); urls.append(u)

    return urls, link_text_map


def extract_ua_urls(text: str) -> List[str]:
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def remove_urls_from_body(body: str, urls_to_remove: List[str]) -> str:
    """本文から対象 URL（生/リンク/画像）を除去"""
    if not body or not urls_to_remove:
        return body or ""
    new_body = body
    for url in urls_to_remove:
        img_pat = re.compile(rf"!\[[^\]]*\]\(\s*{re.escape(url)}\s*\)")
        lnk_pat = re.compile(rf"\[[^\]]*\]\(\s*{re.escape(url)}\s*\)")
        new_body = img_pat.sub("", new_body)
        new_body = lnk_pat.sub("", new_body)
        new_body = re.sub(re.escape(url), "", new_body)
    new_body = re.sub(r"\n{3,}", "\n\n", new_body).strip()
    return new_body


def build_insertion_block(
    pngs: List[str],
    zips: List[Tuple[str, Optional[str], Optional[str]]],
) -> str:
    """
    pngs: PNG の URL だけ（常に画像として埋め込む）
    zips: (URL, comment_label, header_name)
      ZIP の表示名は comment_label > header_name > URL末尾
    """
    lines: List[str] = []

    # --- PNG: 常に本文の最上段。リンク名は付けない。
    for p in pngs:
        lines.append(f"![thumbnail]({p})")

    # PNG と ZIP が両方あるなら、ここで「1行空ける」ことで後続リンク崩れを防止
    if pngs and zips:
        lines.append("")

    # --- ZIP: [表示名](URL)
    for url, comment_label, header_name in zips:
        display = (comment_label or header_name or guess_name_from_url(url)).strip().strip('"').strip("'")
        lines.append(f"[{display}]({url})")

    return "\n".join(lines).strip()


def main():
    ev = event_payload()
    comment = ev.get("comment", {})
    issue = ev.get("issue", {})

    comment_body = comment.get("body") or ""
    issue_body = issue.get("body") or ""
    issue_number = issue.get("number")
    repo  = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")

    if not (repo and token and issue_number):
        debug("Missing GITHUB_TOKEN / GITHUB_REPOSITORY / issue_number; exit.")
        sys.exit(0)

    # コメント解析
    comment_urls, link_text_map = extract_comment_maps(comment_body)
    if not comment_urls:
        debug("No user-attachments URLs in this comment; nothing to do.")
        sys.exit(0)

    # 分類と表示名候補
    pngs: List[str] = []
    zips: List[Tuple[str, Optional[str], Optional[str]]] = []
    for url in comment_urls:
        kind = classify(url)
        if kind == "png":
            pngs.append(url)  # ← PNG は名前を使わず画像埋め込みにする
        elif kind == "zip":
            comment_label = link_text_map.get(url)  # ← ZIP はコメント側の表示名を最優先
            header_name = None
            try:
                r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
                if r.status_code >= 400 or not r.headers:
                    r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
                header_name = parse_content_disposition(r.headers.get("Content-Disposition") or "")
            except Exception as e:
                debug(f"name fetch failed for {url}: {e}")
            zips.append((url, comment_label, header_name))

    if not pngs and not zips:
        debug("No PNG/ZIP in the comment; nothing to move.")
        sys.exit(0)

    # 本文から既存の PNG/ZIP user-attachments を除去
    body_urls = extract_ua_urls(issue_body)
    body_png_zip = []
    for url in body_urls:
        if classify(url) in ("png", "zip"):
            body_png_zip.append(url)
    cleaned_body = remove_urls_from_body(issue_body, body_png_zip)

    # 先頭へ挿入（PNG → 空行 → ZIP）。ブロックの下にも 1 空行を確保して本文を続ける。
    insertion = build_insertion_block(pngs, zips)
    new_body = (insertion + "\n\n" + cleaned_body).strip() if insertion else cleaned_body

    if new_body.strip() == issue_body.strip():
        debug("Body unchanged; skipping PATCH.")
        sys.exit(0)

    # 本文更新
    url = f"{GH_API}/repos/{repo}/issues/{issue_number}"
    resp = SESSION.patch(
        url,
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
