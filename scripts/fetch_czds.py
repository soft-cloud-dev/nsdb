#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from urllib.parse import urlparse

import requests

AUTH_BASE = "https://account-api.icann.org"
CZDS_BASE = "https://czds-api.icann.org"


def atomic_json(path: Path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def authenticate(session: requests.Session, username: str, password: str) -> str:
    response = session.post(
        AUTH_BASE + "/api/authenticate",
        json={"username": username, "password": password},
        headers={"Accept": "application/json"},
        timeout=60,
    )
    response.raise_for_status()
    token = response.json().get("accessToken")
    if not token:
        raise RuntimeError("ICANN authentication response did not contain accessToken")
    return token


def safe_filename(response: requests.Response, url: str) -> str:
    disposition = response.headers.get("content-disposition", "")
    name = None
    if disposition:
        msg = Message()
        msg["content-type"] = disposition
        name = msg.get_param("filename")
    if not name:
        name = Path(urlparse(url).path).name or "zone.dat"
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not name:
        raise RuntimeError(f"cannot derive safe filename for {url}")
    return name


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True, type=Path)
    p.add_argument("--day", default=datetime.now(timezone.utc).date().isoformat())
    args = p.parse_args()

    username = os.environ.get("ICANN_USERNAME")
    password = os.environ.get("ICANN_PASSWORD")
    if not username or not password:
        raise SystemExit("ICANN_USERNAME and ICANN_PASSWORD are required")

    os.umask(0o077)
    zone_dir = args.state_dir / "zones" / args.day
    zone_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    complete = zone_dir / ".complete"
    manifest_path = zone_dir / "manifest.json"

    if complete.exists():
        print(f"Reusing completed CZDS download set for {args.day}: {zone_dir}")
        return

    if any(zone_dir.glob("*.part")):
        raise SystemExit(
            "ambiguous partial CZDS download exists; refusing an automatic retry that might violate the once-per-24-hours limit"
        )

    manifest = {"day": args.day, "files": []}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    completed_by_url = {item["url"]: item for item in manifest.get("files", [])}

    session = requests.Session()
    token = authenticate(session, username, password)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    links_response = session.get(CZDS_BASE + "/czds/downloads/links", headers=headers, timeout=60)
    links_response.raise_for_status()
    links = sorted(set(links_response.json()))
    if not links:
        raise SystemExit("CZDS returned no approved download links")

    for index, url in enumerate(links, start=1):
        prior = completed_by_url.get(url)
        if prior:
            final = zone_dir / prior["filename"]
            if not final.is_file():
                raise SystemExit(f"manifest records {url}, but file is missing: {final}")
            if sha256_file(final) != prior["sha256"]:
                raise SystemExit(f"stored zone file checksum changed: {final}")
            print(f"[{index}/{len(links)}] reuse {final.name}")
            continue

        print(f"[{index}/{len(links)}] download {url}")
        response = session.get(url, headers={"Authorization": f"Bearer {token}"}, stream=True, timeout=(30, 1800))
        if response.status_code == 401:
            token = authenticate(session, username, password)
            response = session.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                stream=True,
                timeout=(30, 1800),
            )
        response.raise_for_status()
        filename = safe_filename(response, url)
        final = zone_dir / filename
        if final.exists():
            raise SystemExit(f"refusing to overwrite an untracked zone file: {final}")
        partial = zone_dir / (filename + ".part")

        h = hashlib.sha256()
        size = 0
        with open(partial, "wb") as fh:
            for chunk in response.iter_content(1024 * 1024):
                if not chunk:
                    continue
                fh.write(chunk)
                h.update(chunk)
                size += len(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(partial, final)

        item = {
            "url": url,
            "filename": filename,
            "sha256": h.hexdigest(),
            "bytes": size,
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
        }
        manifest.setdefault("files", []).append(item)
        completed_by_url[url] = item
        atomic_json(manifest_path, manifest)

    current_urls = {item["url"] for item in manifest.get("files", [])}
    if current_urls != set(links):
        raise SystemExit("CZDS manifest does not match the approved link set")

    complete.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    print(f"Completed {len(links)} CZDS downloads")


if __name__ == "__main__":
    main()
