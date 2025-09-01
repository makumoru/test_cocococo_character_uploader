#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
発火: issue作成・本文編集 / コメント追加 で一本化して動くスクリプト。
- 添付ファイル移動・並べ替え:
  分岐A: issue作成/本文編集時、本文に添付がない → 移動処理は何もしない
  分岐B: コメント追加時、そのコメントに添付がない → 移動処理は何もしない
  分岐C: issue作成/本文編集時、本文に添付がある → 本文内の添付を上に移動(画像→ZIP)、各ブロックと本文は1行空ける
  分岐D: コメント追加時、そのコメントに添付がある → コメントの添付を本文先頭へ移動(画像→ZIP)、各ブロックと本文は1行空ける
- 画像は <img ... src="https://github.com/user-attachments/assets/..."> の **元テキストをそのまま** 用いる
- ZIPは [表示名](https://github.com/user-attachments/files/.../default.zip) の **元テキストをそのまま** 用いる
- 形式を変えるとファイルチェックが壊れるため、一切変換しない
- 並べ替えは「画像ブロック→空行→ZIPブロック→空行→本文残り」。同種内は出現順、Dでは「コメント由来→本文由来」の順。
- 冪等: 既に先頭に整列済みでも同一文字列は重複追加しない/本文から一旦除去して再構成する

この後、verify.py（既存）をそのままサブプロセスで実行する。
"""

import json
import os
import re
import sys
import subprocess
import requests
from typing import List, Tuple

# === 設定/ユーティリティ ======================================================

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME", "")
EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")  # "owner/repo"

SESSION = requests.Session()
SESSION.headers.update({
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github+json",
    "User-Agent": "unified-attachments-pipeline"
})
TIMEOUT = (10, 30)  # (connect, read)

IMG_HTML_RE = re.compile(
    r'<img\s+[^>]*?src="https://github\.com/user-attachments/assets/[^"]+"[^>]*?>',
    re.IGNORECASE | re.DOTALL
)

# ZIPは [text](... .zip) 形式（textは*.zip推奨だが厳格に強制しない）
ZIP_MD_RE = re.compile(
    r'\[[^\]]+?\]\(\s*(https://github\.com/user-attachments/(?:files|assets)/[^\s)]+?\.zip)\s*\)',
    re.IGNORECASE
)

# 画像のMarkdown(![]())が来るケースを一応サポート（元の形式保持が最重要なので変換せずそのまま扱う）
IMG_MD_RE = re.compile(
    r'!\[[^\]]*?\]\(\s*(https://github\.com/user-attachments/(?:assets|files)/[^\s)]+)\s*\)',
    re.IGNORECASE
)


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for s in items:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out


def _extract_images_and_zips(text: str) -> Tuple[List[str], List[str]]:
    """本文 or コメントから、元テキストそのままで image / zip を抽出。"""
    images: List[str] = []
    zips: List[str] = []

    # HTML画像
    for m in IMG_HTML_RE.finditer(text):
        images.append(m.group(0).strip())

    # Markdown画像（念のため）
    for m in IMG_MD_RE.finditer(text):
        images.append(m.group(0).strip())

    # Markdown ZIPリンク
    for m in ZIP_MD_RE.finditer(text):
        zips.append(m.group(0).strip())

    return images, zips


def _remove_occurrences(text: str, occurrences: List[str]) -> str:
    """textから、与えられた完全一致文字列を順に除去。"""
    out = text
    for s in occurrences:
        # 余計な空白を残さないよう、前後の単独改行も整える
        out = out.replace(s, "")
    # 連続空行を抑制しすぎると原文が変わるので、先頭の余計な空行だけ軽くtrim
    return out.lstrip("\n")


def _build_top_block(images: List[str], zips: List[str]) -> str:
    lines: List[str] = []
    if images:
        lines.extend(images)
    if zips:
        if images:
            lines.append("")  # 画像ブロックとの間に1行
        lines.extend(zips)
    return "\n".join(lines)


def _patch_issue_body(issue_number: int, new_body: str) -> None:
    url = f"{GITHUB_API}/repos/{REPO}/issues/{issue_number}"
    resp = SESSION.patch(url, json={"body": new_body}, timeout=TIMEOUT)
    resp.raise_for_status()


def _run_verify_py() -> int:
    # 既存verify.pyをそのまま実行
    verify_path = os.path.join(os.getcwd(), "verify.py")
    if not os.path.exists(verify_path):
        # リポジトリ構成により相対位置が異なる可能性がある場合に備えて隣接も見る
        verify_path_alt = os.path.join(os.path.dirname(__file__), "verify.py")
        if os.path.exists(verify_path_alt):
            verify_path = verify_path_alt
    proc = subprocess.run([sys.executable, verify_path], check=False)
    return proc.returncode


# === メイン処理 ===============================================================

def main() -> int:
    if not EVENT_PATH or not os.path.exists(EVENT_PATH):
        print("EVENT payload not found; nothing to do.", file=sys.stderr)
        return 0

    with open(EVENT_PATH, "r", encoding="utf-8") as f:
        payload = json.load(f)

    issue = payload.get("issue") or {}
    issue_number = issue.get("number")
    if not REPO or not issue_number:
        print("Missing REPO or issue number.", file=sys.stderr)
        return 1

    original_body = issue.get("body") or ""
    action = payload.get("action", "")
    is_issues_event = EVENT_NAME == "issues" and action in ("opened", "edited")
    is_comment_event = EVENT_NAME == "issue_comment" and action == "created"

    # 事前抽出
    body_images, body_zips = _extract_images_and_zips(original_body)

    comment_body = ""
    comment_images: List[str] = []
    comment_zips: List[str] = []

    if is_comment_event:
        comment_body = (payload.get("comment") or {}).get("body") or ""
        comment_images, comment_zips = _extract_images_and_zips(comment_body)

    # --------------------
    # 分岐A/B/C/Dの判定
    # --------------------
    do_rewrite = False
    new_body = original_body

    if is_issues_event:
        if not body_images and not body_zips:
            # 分岐A: 本文に添付がない → 何もしない（移動処理）
            do_rewrite = False
        else:
            # 分岐C: 本文内の添付を集めて「画像→ZIP→本文」の順に再構成
            # 本文から一旦、添付の元テキストを完全一致で除去
            cleaned = _remove_occurrences(original_body, body_images + body_zips)

            # ブロック生成（同種内は本文出現順）
            images_block = _dedupe_preserve_order(body_images)
            zips_block = _dedupe_preserve_order(body_zips)
            top_block = _build_top_block(images_block, zips_block)

            if top_block:
                # 画像→空行→ZIP→空行→本文
                candidate = top_block + "\n\n" + cleaned
            else:
                candidate = cleaned  # 念のため

            # 実際に差分がある場合のみ更新
            if candidate.strip() != original_body.strip():
                new_body = candidate
                do_rewrite = True

    elif is_comment_event:
        if not comment_images and not comment_zips:
            # 分岐B: コメントに添付がない → 何もしない（移動処理）
            do_rewrite = False
        else:
            # 分岐D: コメントの添付を本文先頭に移動
            # 本文に既にある添付も先頭で再整列するため、本文から除去
            cleaned = _remove_occurrences(original_body, body_images + body_zips)

            # 画像: コメント由来→本文由来（重複は除去、順序維持）
            images_block = _dedupe_preserve_order(comment_images + body_images)
            # ZIP: コメント由来→本文由来（重複は除去、順序維持）
            zips_block = _dedupe_preserve_order(comment_zips + body_zips)

            top_block = _build_top_block(images_block, zips_block)
            if top_block:
                candidate = top_block + "\n\n" + cleaned
            else:
                candidate = cleaned

            if candidate.strip() != original_body.strip():
                new_body = candidate
                do_rewrite = True

    # 更新（必要時のみ）
    if do_rewrite:
        print("Updating issue body with reordered attachments...")
        _patch_issue_body(issue_number, new_body)
    else:
        print("No body rewrite needed for this event/branch.")

    # 既存ファイルチェック（verify.py）を必ず実行
    rc = _run_verify_py()
    print(f"verify.py exited with code {rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
