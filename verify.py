import os
import sys
import re
import json
import stat
import hashlib
import zipfile
import unicodedata
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlparse, unquote
from typing import List, Dict, Optional

import requests
import configparser
from PIL import Image

# ===== 定数 =====
MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024
MAX_PNG_SIZE_BYTES = 10 * 1024 * 1024
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
ALLOWED_ROOT_FILES = {"character.ini", "readme.txt", "signature.json"}  # 仕様メモ

# ===== GitHub API =====
def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def post_comment(repo: str, issue: str | int, token: str, body: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}/comments"
    r = requests.post(url, json={"body": body}, headers=_gh_headers(token), timeout=15)
    r.raise_for_status()

def add_labels(repo: str, issue: str | int, token: str, labels: List[str]) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}/labels"
    r = requests.post(url, json={"labels": labels}, headers=_gh_headers(token), timeout=15)
    r.raise_for_status()

def close_issue(repo: str, issue: str | int, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}"
    r = requests.patch(url, json={"state": "closed"}, headers=_gh_headers(token), timeout=15)
    r.raise_for_status()

def get_issue_body(repo: str, issue: str | int, token: str) -> str:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}"
    r = requests.get(url, headers=_gh_headers(token), timeout=15)
    r.raise_for_status()
    data = r.json()
    return data.get("body") or ""

def remove_label(repo: str, issue: str | int, token: str, label: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}/labels/{requests.utils.quote(label, safe='')}"
    r = requests.delete(url, headers=_gh_headers(token), timeout=15)
    # ラベルが付いてなければ 404 が返る。これは無視してOK
    if r.status_code not in (200, 204, 404):
        r.raise_for_status()

# ===== GHA outputs =====
def set_output(name: str, value: str) -> None:
    out_path = os.environ.get("GITHUB_OUTPUT")
    line = f"{name}={value}\n"
    if out_path:
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(line)
    else:
        print(f"[hint] set-output: {line.strip()}")

# ===== 署名・ハッシュ =====
def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256(); h.update(data); return h.hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def normalize_json_for_signing(obj: dict) -> str:
    # アップローダ側に合わせる
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

# ===== 添付URL抽出 =====

# ---- 失敗時の本文サニタイズ（添付無効化） ----
PLACEHOLDER_TEXT = "--検証に失敗したため本ファイルは削除しました--"

IMG_HTML_RE = re.compile(
    r'<img[^>]*\bsrc=[\"\'](https://github\.com/user-attachments/(?:assets|files)/[^"\']+)[\"\'][^>]*>',
    re.IGNORECASE
)
IMG_MD_RE = re.compile(
    r'!\[[^\]]*?\]\(\s*(https://github\.com/user-attachments/(?:assets|files)/[^\s)]+)\s*\)',
    re.IGNORECASE
)
ZIP_MD_RE = re.compile(
    r'\[[^\]]+?\]\(\s*(https://github\.com/user-attachments/(?:files|assets)/[^\s)]+?\.zip)\s*\)',
    re.IGNORECASE
)

def _patch_issue_body(repo: str, issue: str | int, token: str, new_body: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{issue}"
    r = requests.patch(url, json={"body": new_body}, headers=_gh_headers(token), timeout=15)
    r.raise_for_status()

def sanitize_issue_body_on_failure(body: str) -> str:
    if not body:
        return body
    # 1) <img ... src="..."> を置換
    body2 = IMG_HTML_RE.sub(PLACEHOLDER_TEXT, body)
    # 2) Markdown画像
    body2 = IMG_MD_RE.sub(PLACEHOLDER_TEXT, body2)
    # 3) Markdown ZIPリンク
    body2 = ZIP_MD_RE.sub(PLACEHOLDER_TEXT, body2)
    # 4) 裸URL
    body2 = ATTACH_RE.sub(PLACEHOLDER_TEXT, body2)
    return body2

ATTACH_RE = re.compile(
    r"https://github\.com/user-attachments/"
    r"(?:files/\d+/[^\s\)]+|assets/[0-9A-Za-z\-]+)"
)

def _guess_filename_from_headers(r: requests.Response) -> Optional[str]:
    cd = r.headers.get("content-disposition") or r.headers.get("Content-Disposition")
    if not cd:
        return None
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^\";]+)"?', cd, re.IGNORECASE)
    if not m:
        return None
    return unquote(m.group(1))

def _filename_from_url(url: str) -> str:
    path = urlparse(url).path
    return unquote(path.rsplit("/", 1)[-1]) if "/" in path else unquote(path)

def _head(url: str) -> requests.Response:
    # HEAD を拒否する場合があるので GET(stream=True)
    r = requests.get(url, stream=True, timeout=30)
    r.raise_for_status()
    return r

def parse_attachments(issue_body: str) -> List[Dict[str, str]]:
    ats: List[Dict[str, str]] = []
    for m in ATTACH_RE.finditer(issue_body or ""):
        url = m.group(0)
        path = urlparse(url).path
        kind = "files" if "/files/" in path else ("assets" if "/assets/" in path else "unknown")

        url_name = _filename_from_url(url)
        url_ext = (Path(url_name).suffix or "").lower()

        r = _head(url)
        mime = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").split(";")[0].strip().lower()
        hdr_name = _guess_filename_from_headers(r)
        filename = hdr_name or url_name
        ext = (Path(filename).suffix or "").lower() or url_ext

        ats.append({"url": url, "filename": filename, "ext": ext, "mime": mime, "kind": kind})
    return ats

# ===== 添付ポリシー =====
def enforce_attachment_policy(attachments: List[Dict[str, str]], env_zip_url: Optional[str]) -> str:
    """
    許可: ZIP と PNG のみ
      - ZIP: ext=.zip または MIME が application/zip 相当
      - PNG: MIME が image/png（assets は拡張子が無くてもOK）
      - 'thumbnail.png' 名前チェックは、files/... でファイル名が見える場合のみ強制
    """
    if not attachments:
        raise RuntimeError("unreachable")

    def is_zip(a: Dict[str, str]) -> bool:
        return (a["ext"] == ".zip") or (a["mime"] in {"application/zip", "application/x-zip-compressed", "application/octet-stream"})

    def is_png(a: Dict[str, str]) -> bool:
        return (a["ext"] == ".png") or (a["mime"] == "image/png")

    # 許可されない種別が混ざっていないか
    for a in attachments:
        if not (is_zip(a) or is_png(a)):
            raise ValueError(f"許可されていない添付ファイルが見つかりました: {a['filename']}")

    # PNG は 'thumbnail.png' を原則要求。ただし assets 形式は名前が消えるため MIME=PNG なら許容
    pngs = [a for a in attachments if is_png(a)]
    if pngs:
        # files/… で拡張子が .png と分かるケースは厳密にチェック
        visible_named_pngs = [a for a in pngs if a["kind"] == "files" and a["ext"] == ".png"]
        if visible_named_pngs:
            if not all(a["filename"].lower() == "thumbnail.png" for a in visible_named_pngs):
                bad = [a["filename"] for a in visible_named_pngs if a["filename"].lower() != "thumbnail.png"]
                raise ValueError(f"PNG は 'thumbnail.png' のみ許可されます（不一致: {', '.join(bad[:5])}）。")
        # PNG は1個だけ（assets と files が混在しても合計1）
        if len(pngs) > 1:
            raise ValueError("PNG の添付は 1 つだけ許可します。")

    # ZIP の選定（少なくとも1つ必要）
    zips = [a for a in attachments if is_zip(a)]
    if not zips:
        raise ValueError("ZIP 添付が見つかりません。")

    if env_zip_url:
        if not any(a["url"] == env_zip_url for a in zips):
            raise ValueError("指定された ZIP_URL が Issue の添付に含まれていません。")
        return env_zip_url

    return zips[0]["url"]

# ===== PNG 実体検査 =====
def validate_thumbnail_png(url: str) -> None:
    with requests.get(url, stream=True, timeout=30) as r:
        r.raise_for_status()
        content_length = int(r.headers.get("content-length", "0") or "0")
        if content_length and content_length > MAX_PNG_SIZE_BYTES:
            raise ValueError("thumbnail.png のサイズが上限(10MB)を超えています。")
        data = r.content

    if not data:
        raise ValueError("thumbnail.png を取得できませんでした。")
    if len(data) > MAX_PNG_SIZE_BYTES:
        raise ValueError("thumbnail.png のサイズが上限(10MB)を超えています。（実体サイズ）")

    # PNGシグネチャ + Pillow verify
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("thumbnail.png が PNG 署名ではありません。（型偽装の可能性）")
    with Image.open(BytesIO(data)) as im:
        im.verify()
        if (getattr(im, "format", "") or "").upper() != "PNG":
            raise ValueError("thumbnail.png が PNG として認識されませんでした。")

# ===== ZIP 安全性チェック =====
def validate_zip_members(zf: zipfile.ZipFile, extract_root: Path) -> None:
    extract_root = extract_root.resolve()
    for info in zf.infolist():
        name = info.filename
        if not name:
            raise ValueError("ZIP内に空のエントリ名があります。")
        norm = name.replace("\\", "/")
        if norm.startswith("/") or PurePosixPath(norm).is_absolute() or PureWindowsPath(norm).is_absolute():
            raise ValueError("ZIPファイルに不正な絶対パスが含まれています。")
        if ".." in PurePosixPath(norm).parts:
            raise ValueError("ZIPファイルに不正なパスが含まれています。")
        target = (extract_root / norm).resolve()
        root_prefix = str(extract_root) + os.sep
        if not (str(target) == str(extract_root) or str(target).startswith(root_prefix)):
            raise ValueError("ZIPファイルに不正なパスが含まれています。")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("ZIPファイルにシンボリックリンクが含まれています。")

# ===== 文字列正規化 =====
def _norm_rel(p: str) -> str:
    return unicodedata.normalize("NFC", p.replace("\\", "/"))

def _looks_jp(s: str) -> bool:
    for ch in s:
        code = ord(ch)
        if (0x3040 <= code <= 0x30FF) or (0x4E00 <= code <= 0x9FFF) or (0xFF65 <= code <= 0xFF9F):
            return True
    return False

def pretty_name(s: str) -> str:
    try:
        b = s.encode("cp437", errors="strict")
        fixed = b.decode("cp932", errors="strict")
        if fixed != s and _looks_jp(fixed):
            return fixed
    except Exception:
        pass
    return s

# ===== 展開後の完全一致チェック =====
def enforce_no_extra_files_fs(extract_root: Path, manifest_paths: List[str]) -> None:
    root = extract_root.resolve()
    actual_set: set[str] = set()
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            rel = _norm_rel(rel)
            if rel == "signature.json":
                continue
            actual_set.add(rel)
    manifest_set = {_norm_rel(s) for s in manifest_paths}
    extras = sorted(actual_set - manifest_set)
    missing = sorted(manifest_set - actual_set)
    if extras or missing:
        msgs = []
        if extras:
            pe = [pretty_name(x) for x in extras]
            sample = ", ".join(pe[:10])
            more = "" if len(pe) <= 10 else f"（他 {len(pe) - 10} 件）"
            msgs.append(f"マニフェストにないファイル: {sample}{more}")
        if missing:
            pm = [pretty_name(x) for x in missing]
            sample = ", ".join(pm[:10])
            more = "" if len(pm) <= 10 else f"（他 {len(pm) - 10} 件）"
            msgs.append(f"不足しているファイル: {sample}{more}")
        raise ValueError("ZIP内容がマニフェストと一致しません。 " + " / ".join(msgs))

# ===== 画像の軽量検査 =====
def verify_images_if_needed(root: Path, relpath: str) -> None:
    p = (root / relpath).resolve()
    if p.suffix.lower() in IMAGE_EXTS:
        with Image.open(p) as im:
            im.verify()

# ===== メイン =====
def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY")
    issue_number = os.environ.get("ISSUE_NUMBER")
    github_token = os.environ.get("GITHUB_TOKEN")
    signature_salt = os.environ.get("SIGNATURE_SALT") or ""
    zip_url_override = os.environ.get("ZIP_URL")

    if not (repo and issue_number and github_token):
        print("必要な環境変数が足りません。")
        return 1

    try:
        # 添付抽出
        body = get_issue_body(repo, issue_number, github_token)
        attachments = parse_attachments(body)

        # 添付なしはスキップ
        if not attachments:
            print("No attachments detected; skipping verification.")
            set_output("verification_result", "skipped")
            set_output("verification_exit_code", "0")
            return 0

        # 許可・選定
        zip_url = enforce_attachment_policy(attachments, zip_url_override)

        # PNG 実体検査（あれば）
        for a in attachments:
            # MIME が image/png なら assets/UUID でも PNG として扱う
            if (a["ext"] == ".png") or (a["mime"] == "image/png"):
                validate_thumbnail_png(a["url"])

        # ZIP 取得
        print(f"Downloading ZIP: {zip_url}")
        with requests.get(zip_url, stream=True, timeout=30) as r:
            r.raise_for_status()
            content_length = int(r.headers.get("content-length", "0") or "0")
            if content_length and content_length > MAX_ZIP_SIZE_BYTES:
                raise ValueError("ZIPサイズが上限(100MB)を超えています。")
            data = r.content
        if not data:
            raise ValueError("ZIPを取得できませんでした。")
        if len(data) > MAX_ZIP_SIZE_BYTES:
            raise ValueError("ZIPサイズが上限(100MB)を超えています。（実体サイズ）")

        extract_root = Path("extracted").resolve()
        extract_root.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(BytesIO(data)) as zf:
            validate_zip_members(zf, extract_root)

            # 署名検証（展開前）
            try:
                sig_data = json.loads(zf.read("signature.json").decode("utf-8"))
            except KeyError:
                raise ValueError("signature.json が見つかりません。")

            if "signature" not in sig_data:
                raise ValueError("signature.json に signature フィールドがありません。")

            signature = sig_data.pop("signature")
            normalized = normalize_json_for_signing(sig_data)
            calc_sig = sha256_bytes((normalized + signature_salt).encode("utf-8"))
            if calc_sig != signature:
                raise ValueError("署名が一致しません。")

            manifest = sig_data.get("file_manifest")
            if not manifest:
                raise ValueError("file_manifest が空、または存在しません。")

            manifest_paths: List[str] = []
            if isinstance(manifest, dict):
                manifest_paths = list(manifest.keys())
            elif isinstance(manifest, list):
                for item in manifest:
                    if isinstance(item, dict) and "path" in item and "sha256" in item:
                        manifest_paths.append(item["path"])
            if not manifest_paths:
                raise ValueError("file_manifest の形式が不正、または検証対象がありません。")

            # 展開
            zf.extractall(extract_root)

        # 余分ファイルなし（完全一致）
        enforce_no_extra_files_fs(extract_root, manifest_paths)

        # ハッシュ照合
        def _expected_sha(pth: str) -> Optional[str]:
            if isinstance(manifest, dict):
                return manifest.get(pth)
            for item in manifest:
                if isinstance(item, dict) and item.get("path") == pth:
                    return item.get("sha256")
            return None

        for relpath in manifest_paths:
            file_path = (extract_root / relpath).resolve()
            if not file_path.exists() or not file_path.is_file():
                raise ValueError(f"マニフェスト記載ファイルが見つかりません: {pretty_name(relpath)}")
            actual_sha = sha256_file(file_path)
            expected_sha = _expected_sha(relpath)
            if not expected_sha or actual_sha != expected_sha:
                raise ValueError(f"ハッシュ不一致: {pretty_name(relpath)}")
            verify_images_if_needed(extract_root, relpath)

        # character.ini を読んで派生/NSFWラベルを自動付与
        try:
            ini_rel = None
            for rp in manifest_paths:
                if rp.lower().endswith("character.ini"):
                    ini_rel = rp
                    break
            if ini_rel:
                ini_path = (extract_root / ini_rel).resolve()
                # 読み込み（INI内の奇妙なUnicodeも許容）
                cp = configparser.ConfigParser()
                with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
                    cp.read_file(f)
                nsfw = False
                derivative = False
                if cp.has_section("INFO"):
                    # 文字列の大小無視で true を判定
                    getv = lambda k: (cp.get("INFO", k, fallback="false") or "").strip().lower()
                    nsfw = getv("IS_NSFW") in ("1","true","yes","on")
                    derivative = getv("IS_DERIVATIVE") in ("1","true","yes","on")
                labels_to_add = []
                if nsfw:
                    labels_to_add.append("nsfw")
                if derivative:
                    labels_to_add.append("derivative-work")
                if labels_to_add:
                    try:
                        add_labels(repo, issue_number, github_token, labels_to_add)
                    except Exception as e2:
                        print(f"[warn] ラベル付与に失敗: {labels_to_add}: {e2}")
        except Exception as e:
            print(f"[warn] character.ini の解析に失敗: {e}")

        # 成功処理
        add_labels(repo, issue_number, github_token, ["Verified ✅"])
        try:
            remove_label(repo, issue_number, github_token, "Invalid ❌")
        except Exception as e2:
            print(f"[warn] Invalidラベル削除に失敗: {e2}")
        try:
            remove_label(repo, issue_number, github_token, "pending")
        except Exception as e2:
            print(f"[warn] pendingラベル削除に失敗: {e2}")

        post_comment(repo, issue_number, github_token,
                     "検証成功: 署名・マニフェスト完全一致・添付ポリシーの整合性を確認しました。")

        set_output("verification_result", "success")
        set_output("verification_exit_code", "0")
        print("Verification succeeded.")
        return 0

    except Exception as e:
        reason = str(e) or e.__class__.__name__
        print(f"Verification failed with reason: {reason}")
        try:
            post_comment(repo, issue_number, github_token, f"検証失敗: {reason}")
        except Exception as e2:
            print(f"[warn] コメント投稿に失敗: {e2}")
        try:
            add_labels(repo, issue_number, github_token, ["Invalid ❌"])
        except Exception as e2:
            print(f"[warn] ラベル付与に失敗: {e2}")
        try:
            remove_label(repo, issue_number, github_token, "Verified ✅")
        except Exception as e2:
            print(f"[warn] Verifiedラベル削除に失敗: {e2}")
        try:
            remove_label(repo, issue_number, github_token, "pending")
        except Exception as e2:
            print(f"[warn] pendingラベル削除に失敗: {e2}")

        # 本文から添付を無効化（置換）
        try:
            current = get_issue_body(repo, issue_number, github_token)
            sanitized = sanitize_issue_body_on_failure(current)
            if sanitized != current:
                _patch_issue_body(repo, issue_number, github_token, sanitized)
        except Exception as e2:
            print(f"[warn] 本文サニタイズに失敗: {e2}")

        try:
            close_issue(repo, issue_number, github_token)
        except Exception as e2:
            print(f"[warn] Issueクローズに失敗: {e2}")

        set_output("verification_result", "failure")
        set_output("verification_exit_code", "1")
        return 1

if __name__ == "__main__":
    sys.exit(main())
