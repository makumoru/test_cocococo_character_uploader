#!/usr/bin/env python3
import json, os, re, sys, hashlib
from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.4"})
TIMEOUT = (5, 15)

UA_URL = r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]\"'>]+"
UA_URL_RE = re.compile(UA_URL)

# 直貼りの各構文
MD_LINK_MAP_RE  = re.compile(rf"\[([^\]]+)\]\(\s*({UA_URL})\s*\)")
MD_IMAGE_MAP_RE = re.compile(rf"!\[([^\]]*)\]\(\s*({UA_URL})\s*\)")
HTML_IMG_TAG_RE = re.compile(
    rf"(<img\b[^>]*\bsrc=[\"']\s*({UA_URL})\s*[\"'][^>]*>)",
    re.IGNORECASE
)

PNG_CT = {"image/png"}
ZIP_CT = {"application/zip", "application/x-zip-compressed", "application/octet-stream"}

GH_API = "https://api.github.com"

def debug(msg: str): print(f"[sync] {msg}", file=sys.stderr)

def load_event(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f: return json.load(f)

def guess_name_from_url(url: str) -> str:
    tail = os.path.basename(urlparse(url).path)
    return tail or "attachment.zip"

def parse_cd(cd: Optional[str]) -> Optional[str]:
    if not cd: return None
    m = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", cd)
    if m: return m.group(1)
    m = re.search(r"filename\s*=\s*([^;]+)", cd)
    if m: return m.group(1).strip().strip('"')
    return None

def classify(url: str, hint_img: bool=False) -> str:
    if hint_img: return "png"
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        low = url.lower()
        if ct in PNG_CT or low.endswith(".png") or ct.startswith("image/"): return "png"
        if ct in ZIP_CT or low.endswith(".zip"): return "zip"
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
        if UA_URL_RE.fullmatch(url): m[url] = label.strip()
    return m

def extract_from_body(body: str):
    """
    本文から UA URL を抽出。PNGヒントと、元の<img>タグ（あれば）を回収。
    """
    hits: List[Tuple[str, bool]] = []
    url_to_imgtag: Dict[str, str] = {}

    # HTML <img ... src="UA_URL" ...>
    for full_tag, url in HTML_IMG_TAG_RE.findall(body):
        hits.append((url, True))
        # URLごとの最新タグを保存（最後のを使う）
        url_to_imgtag[url] = full_tag

    # Markdown image
    for _, url in MD_IMAGE_MAP_RE.findall(body):
        hits.append((url, True))

    # プレーン/リンクのUA URL
    for url in UA_URL_RE.findall(body):
        hits.append((url, False))

    # 画像ヒントは集約
    merged: Dict[str, bool] = {}
    for url, hint in hits:
        merged[url] = merged.get(url, False) or hint
    ordered = dedup(list(merged.keys()))
    return [(u, merged[u]) for u in ordered], url_to_imgtag

def render_png_line(url: str, imgtag_map: Dict[str, str]) -> str:
    # 元HTMLを維持。Markdown画像にはしない（PNGはHTMLのみ）。
    if url in imgtag_map:
        return imgtag_map[url]
    # 最低限のタグ（幅/高は持たない—GitHub側で調整される）
    return f'<img alt="Image" src="{url}" />'

def render_zip_line(url: str, label: Optional[str]) -> str:
    # ZIPはMarkdownリンクのみ。表示名は [xxx.zip](URL) の xxx.zip を最優先。
    name = (label or "").strip()
    if not name:
        try:
            r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
            name = parse_cd(r.headers.get("Content-Disposition")) or ""
        except Exception:
            name = ""
        if not name: name = guess_name_from_url(url)
        if not name.lower().endswith(".zip"): name += ".zip"
    return f"[{name}]({url})"

MARKER_PREFIX = "<!-- attachments-normalized:sha256="
MARKER_RE = re.compile(r"<!--\s*attachments-normalized:sha256=([0-9a-f]{64})\s*-->")

def strip_ua_fragments(body: str) -> str:
    # UA関連の<img> / ![]() / []() / 素URL / 旧マーカーを除去
    cleaned = HTML_IMG_TAG_RE.sub("", body)
    cleaned = MD_IMAGE_MAP_RE.sub("", cleaned)
    cleaned = MD_LINK_MAP_RE.sub(lambda m: "" if UA_URL_RE.fullmatch(m.group(2)) else m.group(0), cleaned)
    cleaned = UA_URL_RE.sub("", cleaned)
    cleaned = MARKER_RE.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned, flags=re.MULTILINE)
    return cleaned.strip() + "\n"

def compute_block_hash(png_urls: List[str], zip_urls: List[str]) -> str:
    blob = ("\n".join(png_urls) + "\n--\n" + "\n".join(zip_urls)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

def normalize_issue_body(body: str) -> Optional[Tuple[str, str]]:
    """
    戻り値: (new_body, normalized_hash) / 変更なしなら None
    """
    label_map = build_label_map_md(body)
    ua_hits, imgtag_map = extract_from_body(body)
    if not ua_hits: return None

    png_urls, zip_urls = [], []
    for url, hint_img in ua_hits:
        kind = classify(url, hint_img)
        if kind == "png": png_urls.append(url)
        elif kind == "zip": zip_urls.append(url)
        else: pass

    png_urls, zip_urls = dedup(png_urls), dedup(zip_urls)
    if not png_urls and not zip_urls: return None

    # 先頭ブロック
    lines: List[str] = []
    for u in png_urls:
        lines.append(render_png_line(u, imgtag_map))
    if png_urls and zip_urls:
        lines.append("")  # PNG直下の空行（GitHubの描画バグ回避）
    for u in zip_urls:
        lines.append(render_zip_line(u, label_map.get(u)))

    # ブロックハッシュを隠しマーカーで付与
    block_hash = compute_block_hash(png_urls, zip_urls)
    lines.append(f"{MARKER_PREFIX}{block_hash} -->")
    lines.append("")  # 添付ブロックと本文の区切り

    tail = strip_ua_fragments(body)
    new_body = "\n".join(lines) + tail

    # 冪等比較（末尾改行そろえ）
    def _norm(x: str) -> str: return re.sub(r"\s+\Z", "", x.strip()) + "\n"
    if _norm(new_body) == _norm(body): return None
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
        debug("missing env"); sys.exit(0)

    ev = load_event(event_path)
    event_name = os.environ.get("GITHUB_EVENT_NAME") or ""
    issue = ev.get("issue") or {}
    number = issue.get("number")
    if not number: debug("no issue"); sys.exit(0)
    current_body = (issue.get("body") or "").rstrip() + "\n"

    updated, normalized_hash = False, ""

    if event_name == "issue_comment":
        # 本文をまずnormalize（直貼りの分も拾う）
        res = normalize_issue_body(current_body)
        if res:
            new_body, h = res
            if github_update_issue(token, repo, number, new_body):
                updated, normalized_hash = True, h
        else:
            # コメントも混ぜて再normalize（コメント側のUAも取り込む）
            composite = (current_body + "\n\n" + (ev.get("comment") or {}).get("body", "")).strip() + "\n"
            res2 = normalize_issue_body(composite)
            if res2:
                new_body, h = res2
                if github_update_issue(token, repo, number, new_body):
                    updated, normalized_hash = True, h

    elif event_name == "issues":
        changes = ev.get("changes") or {}
        if not changes.get("body"):
            debug("edited w/o body change")
        else:
            res = normalize_issue_body(current_body)
            if res:
                new_body, h = res
                if github_update_issue(token, repo, number, new_body):
                    updated, normalized_hash = True, h
            else:
                debug("No normalization needed.")

    else:
        debug(f"Unsupported event: {event_name}")

    # 出力
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"normalized={'changed' if updated else 'noop'}\n")
            f.write(f"issue_number={number}\n")
            if normalized_hash:
                f.write(f"normalized_hash={normalized_hash}\n")

if __name__ == "__main__":
    main()
