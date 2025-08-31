#!/usr/bin/env python3
# coding: utf-8
import json
import os
import re
import sys
import hashlib
from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse

import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.5"})
TIMEOUT = (5, 15)

# user-attachments URL（assets / files の両系統）
UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]\"'>]+"
UA_URL_RE = re.compile(UA_URL)

# 本文・コメント内の構文
MD_LINK_MAP_RE  = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")
HTML_IMG_TAG_RE = re.compile(
    rf"(<img\b[^>]*\bsrc=[\"']\s*({UA_URL})\s*[\"'][^>]*>)",
    re.IGNORECASE
)

PNG_CT = {"image/png"}
ZIP_CT = {"application/zip", "application/x-zip-compressed", "application/octet-stream"}

GH_API = "https://api.github.com"

# 先頭ブロックの世代印（＝最新性を検証側と共有）
MARKER_PREFIX = "<!-- attachments-normalized:sha256="
MARKER_RE = re.compile(r"<!--\s*attachments-normalized:sha256=([0-9a-f]{64})\s*-->")

# 旧ブロックを**先頭から丸ごと**削除するための強いパターン
ATTACH_BLOCK_HEAD_RE = re.compile(
    r"""^(
        (?:[ \t]*(?:<img\b[^>]*\bsrc=['"]""" + UA_URL + r"""['"][^>]*>)[ \t]*\r?\n)+
        (?:\r?\n)?
        (?:[ \t]*\[[^\]]+\]\(\s*""" + UA_URL + r"""\s*\)[ \t]*\r?\n)+
        [ \t]*<!--\s*attachments-normalized:sha256=[0-9a-f]{64}\s*-->\s*\r?\n
    )""",
    re.IGNORECASE | re.MULTILINE | re.VERBOSE
)

def debug(msg: str):
    print(f"[sync] {msg}", file=sys.stderr)

def load_event(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment.zip"

def parse_cd(cd: Optional[str]) -> Optional[str]:
    if not cd:
        return None
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m:
        return m.group(1)
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m:
        return m.group(1).strip().strip('"')
    return None

def classify(url: str, hint_img: bool=False) -> str:
    if hint_img:
        return "png"
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        low = url.lower()
        if ct in PNG_CT or low.endswith(".png") or ct.startswith("image/"):
            return "png"
        if ct in ZIP_CT or low.endswith(".zip"):
            return "zip"
    except Exception as e:
        debug(f"classify error: {e!r}")
    return "other"

def dedup(seq: List[str]) -> List[str]:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def build_label_map_md(text: str) -> Dict[str, str]:
    m = {}
    for label, url in MD_LINK_MAP_RE.findall(text):
        if UA_URL_RE.fullmatch(url):
            m[url] = label.strip()
    return m

def extract_from_text(text: str):
    """任意テキストから UA URL と PNGヒント・<img>原文を抜く"""
    hits: List[Tuple[str, bool]] = []
    url_to_imgtag: Dict[str, str] = {}

    for full_tag, url in HTML_IMG_TAG_RE.findall(text):
        hits.append((url, True))
        url_to_imgtag[url] = full_tag

    for _, url in MD_IMAGE_MAP_RE.findall(text):
        hits.append((url, True))

    for url in UA_URL_RE.findall(text):
        hits.append((url, False))

    merged: Dict[str, bool] = {}
    for url, hint in hits:
        merged[url] = merged.get(url, False) or hint
    ordered = dedup(list(merged.keys()))
    return [(u, merged[u]) for u in ordered], url_to_imgtag

def render_png_line(url: str, imgtag_map: Dict[str, str]) -> str:
    # PNGは必ずHTMLの <img …> を用いる
    if url in imgtag_map:
        return imgtag_map[url]
    return f'<img alt="Image" src="{url}" />'

def render_zip_line(url: str, label: Optional[str]) -> str:
    # ZIPはMarkdownリンクのみ、表示名は [xxx.zip](URL) の xxx.zip を最優先
    name = (label or "").strip()
    if not name:
        try:
            r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
            name = parse_cd(r.headers.get("Content-Disposition")) or ""
        except Exception:
            name = ""
        if not name:
            name = guess_name_from_url(url)
        if not name.lower().endswith(".zip"):
            name += ".zip"
    return f"[{name}]({url})"

def compute_block_hash(png_urls: List[str], zip_urls: List[str]) -> str:
    blob = ("\n".join(png_urls) + "\n--\n" + "\n".join(zip_urls)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

def strip_ua_everywhere(text: str) -> str:
    """本文全体から UA 関連断片と旧マーカーを除去（安全網）"""
    cleaned = HTML_IMG_TAG_RE.sub("", text)
    cleaned = MD_IMAGE_MAP_RE.sub("", cleaned)
    cleaned = MD_LINK_MAP_RE.sub(lambda m: "" if UA_URL_RE.fullmatch(m.group(2)) else m.group(0), cleaned)
    cleaned = UA_URL_RE.sub("", cleaned)
    cleaned = MARKER_RE.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip() + "\n"

def normalize_issue_body(body: str, comment_text: str = "") -> Optional[Tuple[str, str]]:
    """
    本文＋（あれば）コメントを合成して**一発**で整形。
    - 先頭に既存のアタッチブロックがあれば丸ごと削除
    - PNG群（HTML）→空行→ZIP群（MDリンク）→マーカー→空行→残本文
    戻り値: (new_body, normalized_hash) / 変更無しなら None
    """
    # 1) 合成してから抽出（レース/二重実行に強い）
    combined = (body.rstrip() + "\n\n" + (comment_text or "").rstrip() + "\n").lstrip()

    # 2) 先頭に既存アタッチブロックがあればまず剥がす
    combined = ATTACH_BLOCK_HEAD_RE.sub("", combined, count=1)

    # 3) 抽出
    label_map = build_label_map_md(combined)
    hits, imgtag_map = extract_from_text(combined)
    if not hits:
        return None

    png_urls, zip_urls = [], []
    for url, hint_img in hits:
        kind = classify(url, hint_img)
        if kind == "png":
            png_urls.append(url)
        elif kind == "zip":
            zip_urls.append(url)
        else:
            pass

    png_urls, zip_urls = dedup(png_urls), dedup(zip_urls)
    if not png_urls and not zip_urls:
        return None

    # 4) 先頭ブロック生成
    lines: List[str] = []
    for u in png_urls:
        lines.append(render_png_line(u, imgtag_map))
    if png_urls and zip_urls:
        lines.append("")  # PNG直下の空行
    for u in zip_urls:
        lines.append(render_zip_line(u, label_map.get(u)))
    block_hash = compute_block_hash(png_urls, zip_urls)
    lines.append(f"{MARKER_PREFIX}{block_hash} -->")
    lines.append("")  # 区切り

    # 5) 本文から UA 断片を全削除して後段へ
    tail = strip_ua_everywhere(combined)
    new_body = "\n".join(lines) + tail

    # 6) 冪等比較（末尾改行統一）
    def _norm(x: str) -> str:
        return re.sub(r"\s+\Z", "", x.strip()) + "\n"
    if _norm(new_body) == _norm(body):
        return None
    return new_body, block_hash

def github_update_issue(token: str, repo: str, number: int, new_body: str) -> bool:
    resp = SESSION.patch(
        f"{GH_API}/repos/{repo}/issues/{number}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"body": new_body},
        timeout=TIMEOUT,
    )
    if resp.status_code >= 300:
        debug(f"Failed to update issue body: {resp.status_code} {resp.text}")
        sys.exit(1)
    debug("Issue body updated.")
    return True

def main():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not (event_path and repo and token):
        debug("missing env")
        sys.exit(0)

    ev = load_event(event_path)
    event_name = os.environ.get("GITHUB_EVENT_NAME") or ""

    issue = ev.get("issue") or {}
    number = issue.get("number")
    if not number:
        debug("no issue")
        sys.exit(0)
    body = (issue.get("body") or "")

    comment_text = ""
    if event_name == "issue_comment":
        comment_text = (ev.get("comment") or {}).get("body", "")

    updated, normalized_hash = False, ""

    res = normalize_issue_body(body, comment_text)
    if res:
        new_body, h = res
        if github_update_issue(token, repo, number, new_body):
            updated, normalized_hash = True, h
    else:
        debug("No normalization needed.")

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"normalized={'changed' if updated else 'noop'}\n")
            f.write(f"issue_number={number}\n")
            if normalized_hash:
                f.write(f"normalized_hash={normalized_hash}\n")

if __name__ == "__main__":
    main()
