#!/usr/bin/env python3
import json
import os
import re
import sys
from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.3"})
TIMEOUT = (5, 15)

# user-attachments URL（assets と files の両系統を拾う）
UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]\"'>]+"
UA_URL_RE = re.compile(UA_URL)

# 本文・コメント内の Markdown/HTML 構文を個別に拾う
MD_LINK_MAP_RE  = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")
HTML_IMG_RE     = re.compile(rf"<img\b[^>]*\bsrc=[\"']\s*({UA_URL})\s*[\"'][^>]*>", re.IGNORECASE)

PNG_CT = {"image/png"}
ZIP_CT = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",  # GitHub 側がこれを返すことがある
}

GH_API = "https://api.github.com"


def debug(msg: str):
    print(f"[sync] {msg}", file=sys.stderr)


def load_event(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment"


def parse_content_disposition(cd: Optional[str]) -> Optional[str]:
    if not cd:
        return None
    # RFC5987 形式優先
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m:
        return m.group(1)
    # 通常の filename=
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m:
        return m.group(1).strip().strip('"')
    return None


def classify_via_http(url: str, hint_is_img: bool = False) -> str:
    """
    png/zip/other を判定。基本は HEAD→GET(stream) だが、
    HTML <img> など「画像であることが文法から明らか」な場合は hint_is_img=True でショートカット。
    """
    if hint_is_img:
        return "png"
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        low = url.lower()
        if (
            ct in PNG_CT
            or low.endswith(".png")
            or "image/" in ct  # assets/uuid でも image/* を返す
        ):
            return "png"
        if ct in ZIP_CT or low.endswith(".zip"):
            return "zip"
    except Exception as e:
        debug(f"classify error: {e!r}")
    return "other"


def dedup_keep_order(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_label_map_md(body: str) -> Dict[str, str]:
    """
    [label](URL) / ![alt](URL) から URL→表示名 を採取。
    ZIPの「default.zip 問題」対策で、[xxx.zip](URL) の xxx.zip を使うための地図。
    """
    m = {}
    for label, url in MD_LINK_MAP_RE.findall(body):
        if UA_URL_RE.fullmatch(url):
            m[url] = label.strip()
    # 画像の alt は表示名には使わない（ZIPのラベル優先）
    return m


def extract_ua_urls_with_hints_from_body(body: str) -> List[Tuple[str, bool]]:
    """
    本文から UA URL を抽出。第二要素は「構文上、画像（<img> or ![]()）であると分かるか」のヒント。
    """
    hits: List[Tuple[str, bool]] = []
    # HTML <img src="UA_URL">
    for url in HTML_IMG_RE.findall(body):
        hits.append((url, True))
    # Markdown image
    for _, url in MD_IMAGE_MAP_RE.findall(body):
        hits.append((url, True))
    # プレーン/リンクで露出している UA URL も拾う
    for url in UA_URL_RE.findall(body):
        hits.append((url, False))
    # 順序保持＆重複除去（画像ヒントは OR でまとめる）
    merged: Dict[str, bool] = {}
    for url, hint in hits:
        merged[url] = merged.get(url, False) or hint
    return [(u, merged[u]) for u in dedup_keep_order(list(merged.keys()))]


def render_png_line(url: str) -> str:
    # Markdown画像として統一（HTMLより崩れにくい）
    return f"![thumbnail]({url})"


def render_zip_line(url: str, label: Optional[str]) -> str:
    name = (label or "").strip()
    if not name:
        # Content-Disposition → URL末尾 → 最低限の代替名
        try:
            r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
            name = parse_content_disposition(r.headers.get("Content-Disposition")) or ""
        except Exception:
            name = ""
        if not name:
            name = guess_name_from_url(url)
        # 「.zip」で終わらなければ付ける（見た目合わせ）
        if not name.lower().endswith(".zip"):
            name += ".zip"
    return f"[{name}]({url})"


def strip_ua_fragments(body: str) -> str:
    """
    本文から UA 関連の <img> / ![]() / []() だけを除去。
    文中に紛れ込んだ場合も壊れないよう、構文単位で空文字にして、空行を整える。
    """
    cleaned = HTML_IMG_RE.sub("", body)
    cleaned = MD_IMAGE_MAP_RE.sub("", cleaned)
    cleaned = MD_LINK_MAP_RE.sub(lambda m: "" if UA_URL_RE.fullmatch(m.group(2)) else m.group(0), cleaned)
    # UA URL の素の貼り付けを消す（行頭・行中どちらも）
    cleaned = UA_URL_RE.sub("", cleaned)
    # 連続空行を詰める（ただし最終段では 2 連続まで許容）
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned, flags=re.MULTILINE)
    # 先頭末尾の空白を整える
    return cleaned.strip() + "\n"


def normalize_issue_body(body: str) -> Optional[str]:
    """
    本文直貼りの添付にも対応して、
    「PNG群 → 空行1つ → ZIP群 → 空行1つ → 残り本文」
    という形に再構成。変更が無ければ None。
    """
    label_map = build_label_map_md(body)
    ua_hits = extract_ua_urls_with_hints_from_body(body)
    if not ua_hits:
        return None  # 添付らしきものが無い

    png_urls: List[str] = []
    zip_urls: List[str] = []

    for url, hint_img in ua_hits:
        kind = classify_via_http(url, hint_is_img=hint_img)
        if kind == "png":
            png_urls.append(url)
        elif kind == "zip":
            zip_urls.append(url)
        else:
            # other は本文側に残す（ここでは触らない）
            pass

    png_urls = dedup_keep_order(png_urls)
    zip_urls = dedup_keep_order(zip_urls)

    if not png_urls and not zip_urls:
        return None  # 並べ替える対象無し

    # 先頭セクションを構築
    lines: List[str] = []
    for u in png_urls:
        lines.append(render_png_line(u))
    if png_urls and zip_urls:
        lines.append("")  # PNG群の直下に空行（GitHub表示バグ回避）
    for u in zip_urls:
        lines.append(render_zip_line(u, label_map.get(u)))
    if png_urls or zip_urls:
        lines.append("")  # 添付ブロックと本文の区切り

    # 本文から UA 関連片を除去して、残りを後段に連結
    tail = strip_ua_fragments(body)
    new_body = "\n".join(lines) + tail

    # 冪等のため、余計な空白差分を抑制
    def _s(x: str) -> str:
        return re.sub(r"\s+\Z", "", x.strip()) + "\n"
    if _s(new_body) == _s(body):
        return None
    return new_body


def github_update_issue(token: str, repo: str, number: int, new_body: str):
    url = f"{GH_API}/repos/{repo}/issues/{number}"
    resp = SESSION.patch(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"body": new_body},
        timeout=TIMEOUT,
    )
    if resp.status_code >= 300:
        debug(f"Failed to update issue body: {resp.status_code} {resp.text}")
        sys.exit(1)
    debug("Issue body updated.")


def main():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not (event_path and repo and token):
        debug("GITHUB_EVENT_PATH / GITHUB_REPOSITORY / GITHUB_TOKEN are required.")
        sys.exit(0)

    ev = load_event(event_path)
    event_name = os.environ.get("GITHUB_EVENT_NAME") or ""

    # --- 共通: Issue 本体の情報 ---
    issue = ev.get("issue") or {}
    number = issue.get("number")
    if not number:
        debug("No issue number in event.")
        sys.exit(0)

    current_body = (issue.get("body") or "").rstrip() + "\n"

    # パスA) issue_comment（既存のコメント由来パイプ）
    if event_name == "issue_comment":
        comment = ev.get("comment") or {}
        comment_body = comment.get("body") or ""
        # コメント内の UA を本文先頭へ持っていく（既存仕様と同等の整形）
        # → まず本文側を normalize（直貼りも含めた最新SSOT化）
        new_body_via_body = normalize_issue_body(current_body)
        if new_body_via_body:
            current_body = new_body_via_body

        # その上でコメント由来の UA を追加入力として再度 normalize
        composite = (current_body + "\n\n" + comment_body).strip() + "\n"
        new_body = normalize_issue_body(composite)
        if new_body:
            github_update_issue(token, repo, number, new_body)
        sys.exit(0)

    # パスB) issues.edited（本文直貼りへの対応）
    if event_name == "issues":
        # body の変更時のみ動けばよい（changes.body が無い編集は何もしない）
        changes = ev.get("changes") or {}
        if not changes.get("body"):
            debug("Issue edited but body not changed; skipping.")
            sys.exit(0)

        new_body = normalize_issue_body(current_body)
        if new_body:
            github_update_issue(token, repo, number, new_body)
        else:
            debug("No normalization needed.")
        sys.exit(0)

    # それ以外のイベントでは何もしない
    debug(f"Unsupported event: {event_name}")
    sys.exit(0)


if __name__ == "__main__":
    main()
