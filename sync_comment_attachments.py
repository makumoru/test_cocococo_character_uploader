#!/usr/bin/env python3
import json
import os
import re
import sys
from typing import List, Tuple, Dict, Optional
import requests
from urllib.parse import urlparse

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.2"})
TIMEOUT = (5, 15)

# user-attachments の URL
UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]]+"
UA_URL_RE = re.compile(UA_URL)

# コメント本文から [テキスト](URL) と ![alt](URL) を URL→テキスト/alt にマッピング
MD_LINK_MAP_RE = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")

PNG_CT = {"image/png"}
ZIP_CT = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
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


def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment"


def parse_content_disposition(cd: str) -> Optional[str]:
    if not cd:
        return None
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m:
        return m.group(1)
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd)
    if m:
        return m.group(1)
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m:
        return m.group(1).strip()
    return None


def classify(url: str) -> str:
    """png/zip/other を判定（HEAD→GET(stream)）"""
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        low_url = url.lower()
        if ct in PNG_CT or low_url.endswith(".png"):
            return "png"
        if (ct in ZIP_CT and (low_url.endswith(".zip") or "assets" in low_url)) or low_url.endswith(".zip"):
            return "zip"
        if ct in PNG_CT:
            return "png"
        if ct in ZIP_CT:
            return "zip"
        return "other"
    except Exception as e:
        debug(f"HEAD/GET failed for {url}: {e}")
        return "other"


def extract_comment_maps(text: str) -> Tuple[List[str], Dict[str, str], Dict[str, str]]:
    """
    返り値:
      - urls: コメント内に現れた user-attachments URL（順序保持・重複除去）
      - link_text_map: URL -> [テキスト]（通常リンクの表示名）
      - img_alt_map:  URL -> ![alt] の alt
    """
    link_text_map: Dict[str, str] = {}
    img_alt_map: Dict[str, str] = {}

    for m in MD_LINK_MAP_RE.finditer(text or ""):
        label, url = m.group(1), m.group(2)
        link_text_map[url] = label

    for m in MD_IMAGE_MAP_RE.finditer(text or ""):
        alt, url = m.group(1), m.group(2)
        img_alt_map[url] = alt

    # 生URLや順序確定のために総当たり抽出
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            urls.append(u)

    return urls, link_text_map, img_alt_map


def extract_ua_urls(text: str) -> List[str]:
    seen, urls = set(), []
    for m in UA_URL_RE.finditer(text or ""):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def remove_urls_from_body(body: str, urls_to_remove: List[str]) -> str:
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
    pngs: PNG の URL
    zips: (URL, comment_label, header_name)
      表示名の優先度: comment_label > header_name > URL末尾
    """
    lines: List[str] = []

    for p in pngs:
        lines.append(f"![thumbnail]({p})")

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
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")

    if not (repo and token and issue_number):
        debug("Missing GITHUB_TOKEN / GITHUB_REPOSITORY / issue_number; exit.")
        sys.exit(0)

    # コメント解析：URL列と URL→[ラベル] / URL→alt のマップ
    comment_urls, link_text_map, _img_alt_map = extract_comment_maps(comment_body)
    if not comment_urls:
        debug("No user-attachments URLs in this comment; nothing to do.")
        sys.exit(0)

    # 分類と表示名候補の収集
    pngs: List[str] = []
    zips: List[Tuple[str, Optional[str], Optional[str]]] = []  # (url, comment_label, header_name)

    for url in comment_urls:
        kind = classify(url)
        if kind == "png":
            pngs.append(url)
        elif kind == "zip":
            # コメント側でのリンクテキスト（[ここ]の “ここ”）を最優先
            comment_label = link_text_map.get(url)
            # ヘッダ由来のファイル名は default.zip 問題があっても次点として保持しておく
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

    # 既存の本文から PNG/ZIP の user-attachments を除去
    body_urls = extract_ua_urls(issue_body)
    body_png_zip = []
    for url in body_urls:
        if classify(url) in ("png", "zip"):
            body_png_zip.append(url)

    cleaned_body = remove_urls_from_body(issue_body, body_png_zip)

    # 先頭に PNG→ZIP を挿入（ZIP は [表示名](URL)、表示名はコメントのテキストを最優先）
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
