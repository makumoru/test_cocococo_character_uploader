#!/usr/bin/env python3
import json
import os
import re
import sys
from typing import List, Tuple, Dict, Optional
import requests
from urllib.parse import urlparse

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "attachment-sync/1.1"})
TIMEOUT = (5, 15)  # connect, read

# user-attachments の URL を素直に拾う（Markdown 内でも生でもヒットする）
UA_URL_RE = re.compile(r"https?://github\.com/user-attachments/(?:files|assets)/[^\s\)\]]+")

PNG_CT = {"image/png"}
ZIP_CT = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",  # ZIP がこれで返ることがある
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


def _guess_name_from_url(url: str) -> str:
    # URL 末尾のパス名を雑に拾う（assets の場合は UUID で無意味なことが多い）
    p = urlparse(url)
    tail = os.path.basename(p.path)
    return tail or "attachment"


def _parse_content_disposition(cd: str) -> Optional[str]:
    # filename*=UTF-8''... を優先、次に filename="..."/filename=...
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


def classify_and_name(url: str) -> Tuple[str, Optional[str]]:
    """
    URL を HEAD（失敗時 GET(stream)）し、種別と表示名を返す。
    戻り値: ("png"|"zip"|"other", filename or None)
    """
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        if r.status_code >= 400 or not r.headers:
            r = SESSION.get(url, stream=True, allow_redirects=True, timeout=TIMEOUT)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        cd = r.headers.get("Content-Disposition") or ""
        name = _parse_content_disposition(cd) or _guess_name_from_url(url)

        # 分類
        low_url = url.lower()
        low_name = name.lower() if name else ""
        if ct in PNG_CT or low_url.endswith(".png") or low_name.endswith(".png"):
            return "png", name
        if (
            ct in ZIP_CT
            and (low_url.endswith(".zip") or low_name.endswith(".zip") or "assets" in low_url)
        ) or low_url.endswith(".zip"):
            return "zip", name
        # user-attachments では octet-stream + assets/UUID で拡張子不明なことがある
        if ct in PNG_CT:
            return "png", name
        if ct in ZIP_CT:
            return "zip", name
        return "other", name
    except Exception as e:
        debug(f"HEAD/GET failed for {url}: {e}")
        return "other", None


def extract_ua_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = UA_URL_RE.findall(text)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def remove_urls_from_body(body: str, urls_to_remove: List[str]) -> str:
    """本文から対象 URL（生/リンク/画像）を安全に除去"""
    if not body or not urls_to_remove:
        return body or ""

    new_body = body
    for url in urls_to_remove:
        # ![]() と []() の両方を除去
        img_pat = re.compile(rf"!\[[^\]]*\]\(\s*{re.escape(url)}\s*\)")
        lnk_pat = re.compile(rf"\[[^\]]*\]\(\s*{re.escape(url)}\s*\)")
        new_body = img_pat.sub("", new_body)
        new_body = lnk_pat.sub("", new_body)
        # 生 URL も除去
        new_body = re.sub(re.escape(url), "", new_body)

    # 余分な空行を整える
    new_body = re.sub(r"\n{3,}", "\n\n", new_body).strip()
    return new_body


def build_insertion_block(pngs: List[Tuple[str, Optional[str]]],
                          zips: List[Tuple[str, Optional[str]]]) -> str:
    """PNG を画像として、ZIP を [名前](URL) で出力。順序は PNG → ZIP。"""
    lines: List[str] = []

    # PNG（画像埋め込み）。alt は固定で "thumbnail"
    for url, _name in pngs:
        lines.append(f"![thumbnail]({url})")

    # ZIP（リンク）。表示名はヘッダ由来のファイル名があればそれを使う。
    for url, name in zips:
        display = name or _guess_name_from_url(url)
        # 余計なクォートや周辺空白を掃除
        display = display.strip().strip('"').strip("'")
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

    # コメントから user-attachments URL を抽出
    comment_urls = extract_ua_urls(comment_body)
    if not comment_urls:
        debug("No user-attachments URLs in this comment; nothing to do.")
        sys.exit(0)

    # 分類 + ファイル名解決
    pngs: List[Tuple[str, Optional[str]]] = []
    zips: List[Tuple[str, Optional[str]]] = []
    for url in comment_urls:
        kind, name = classify_and_name(url)
        if kind == "png":
            pngs.append((url, name))
        elif kind == "zip":
            zips.append((url, name))

    if not pngs and not zips:
        debug("No PNG/ZIP in the comment; nothing to move.")
        sys.exit(0)

    # 本文から既存の PNG/ZIP の user-attachments を除去
    body_urls = extract_ua_urls(issue_body)
    body_png_zip = []
    for url in body_urls:
        kind, _ = classify_and_name(url)
        if kind in ("png", "zip"):
            body_png_zip.append(url)

    cleaned_body = remove_urls_from_body(issue_body, body_png_zip)

    # 先頭に PNG→ZIP を挿入（ZIP は [名前](URL) 形式）
    insertion = build_insertion_block(pngs, zips)
    new_body = (insertion + "\n\n" + cleaned_body).strip() if insertion else cleaned_body

    if new_body.strip() == issue_body.strip():
        debug("Body unchanged; skipping PATCH.")
        sys.exit(0)

    # Issue 本文を更新
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
